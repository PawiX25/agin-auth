use axum::{
    Extension,
    extract::Query,
    response::{IntoResponse, Redirect},
};
use chrono::{Duration, Utc};
use entity::{email_confirmation_token, user};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    axum_error::{AxumError, AxumResult},
    state::AppState,
    utils::{generate_reset_token, hash_token},
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(confirm_email))
}

pub async fn send_confirmation_email(
    state: &AppState,
    user_id: i32,
    email: &str,
) -> AxumResult<()> {
    let Some(mail) = &state.mail_service else {
        user::Entity::update_many()
            .col_expr(
                user::Column::EmailConfirmed,
                sea_orm::sea_query::Expr::value(true),
            )
            .filter(user::Column::Id.eq(user_id))
            .exec(&state.db)
            .await?;

        tracing::info!(
            user_id,
            "Mail service not configured, auto-confirming email for newly registered user"
        );
        return Ok(());
    };

    let token = generate_reset_token();
    let token_hash = hash_token(&token);
    let expires_at = Utc::now() + Duration::hours(24);

    let new_token = email_confirmation_token::ActiveModel {
        token_hash: Set(token_hash),
        user_id: Set(user_id),
        expires_at: Set(expires_at),
        ..Default::default()
    };
    new_token.insert(&state.db).await?;

    if let Err(error) = mail.send_email_confirmation(email, &token).await {
        tracing::warn!(error = ?error, user_id, "Failed to send confirmation email");
        return Err(AxumError::service_unavailable(color_eyre::eyre::eyre!(
            "Confirmation email service is unavailable"
        )));
    }

    Ok(())
}

#[derive(Deserialize, IntoParams)]
struct ConfirmEmailQuery {
    /// Confirmation token from the email link
    token: String,
}

/// Confirm email address
///
/// Validates the confirmation token, marks the email as confirmed, and redirects to the frontend result page.
#[utoipa::path(
    method(get),
    path = "/",
    params(ConfirmEmailQuery),
    responses(
        (status = 302, description = "Redirects to frontend with status"),
    ),
    tag = "Email Confirmation"
)]
async fn confirm_email(
    Extension(state): Extension<AppState>,
    Query(query): Query<ConfirmEmailQuery>,
) -> impl IntoResponse {
    let redirect_error =
        |reason: &str| Redirect::temporary(&format!("/confirm-email?status=error&reason={reason}"));

    let token_hash = hash_token(&query.token);

    let token_doc = match email_confirmation_token::Entity::find()
        .filter(email_confirmation_token::Column::TokenHash.eq(&token_hash))
        .one(&state.db)
        .await
    {
        Ok(Some(doc)) => doc,
        Ok(None) => return redirect_error("invalid"),
        Err(e) => {
            tracing::warn!(error = ?e, "Failed to look up email confirmation token");
            return redirect_error("invalid");
        }
    };

    // Delete the token (single use)
    let _ = email_confirmation_token::Entity::delete_by_id(token_doc.id)
        .exec(&state.db)
        .await;

    if Utc::now() > token_doc.expires_at {
        // Clean up other expired tokens in the background
        let db = state.db.clone();
        tokio::spawn(async move {
            let now = Utc::now();
            if let Err(e) = email_confirmation_token::Entity::delete_many()
                .filter(email_confirmation_token::Column::ExpiresAt.lt(now))
                .exec(&db)
                .await
            {
                tracing::warn!(error = ?e, "Failed to clean up expired email confirmation tokens");
            }
        });
        return redirect_error("expired");
    }

    let result = user::Entity::update_many()
        .col_expr(
            user::Column::EmailConfirmed,
            sea_orm::sea_query::Expr::value(true),
        )
        .filter(user::Column::Id.eq(token_doc.user_id))
        .exec(&state.db)
        .await;

    match result {
        Ok(r) if r.rows_affected > 0 => Redirect::temporary("/confirm-email?status=success"),
        Ok(_) => redirect_error("not_found"),
        Err(e) => {
            tracing::warn!(error = ?e, "Failed to update user email confirmation status");
            redirect_error("invalid")
        }
    }
}
