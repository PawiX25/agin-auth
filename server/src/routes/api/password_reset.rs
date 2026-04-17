use axum::{Extension, Json};
use axum_valid::Valid;
use chrono::{Duration, Utc};
use color_eyre::eyre;
use entity::{auth_method, password, password_reset_token, refresh_token, user};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, sea_query::Expr};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    auth_method_helpers::upsert_auth_method,
    axum_error::{AxumError, AxumResult},
    database::invalidate_user_sessions,
    state::AppState,
    utils::{generate_reset_token, hash_password, hash_token},
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(request_reset))
        .routes(routes!(confirm_reset))
}

#[derive(Deserialize, ToSchema, Validate)]
struct RequestResetBody {
    #[validate(email, length(max = 128))]
    email: String,
}

#[derive(Serialize, ToSchema)]
struct RequestResetResponse {
    success: bool,
}

#[utoipa::path(
    method(post),
    path = "/",
    request_body = RequestResetBody,
    responses(
        (status = OK, description = "Email sent (or address not found — always succeeds)", body = RequestResetResponse, content_type = "application/json"),
        (status = SERVICE_UNAVAILABLE, description = "Mail not configured", body = String, content_type = "application/json"),
    ),
    tag = "Password Reset"
)]
async fn request_reset(
    Extension(state): Extension<AppState>,
    Valid(Json(body)): Valid<Json<RequestResetBody>>,
) -> AxumResult<Json<RequestResetResponse>> {
    let Some(mail) = &state.mail_service else {
        return Err(AxumError::service_unavailable(eyre::eyre!(
            "Mail is not configured"
        )));
    };

    let user = user::Entity::find()
        .filter(user::Column::Email.eq(&body.email))
        .one(&state.db)
        .await?;

    let Some(user) = user else {
        return Ok(Json(RequestResetResponse { success: true }));
    };

    let token = generate_reset_token();
    let token_hash = hash_token(&token);
    let expires_at = Utc::now() + Duration::hours(1);

    let new_token = password_reset_token::ActiveModel {
        token_hash: Set(token_hash),
        user_id: Set(user.id),
        expires_at: Set(expires_at),
        ..Default::default()
    };
    new_token.insert(&state.db).await?;

    if let Err(e) = mail.send_password_reset(&user.email, &token).await {
        tracing::warn!(error = ?e, "Failed to send password reset email");
    }

    Ok(Json(RequestResetResponse { success: true }))
}

#[derive(Deserialize, ToSchema, Validate)]
struct ConfirmResetBody {
    token: String,

    #[validate(length(min = 8, max = 256))]
    new_password: String,
}

#[derive(Serialize, ToSchema)]
struct ConfirmResetResponse {
    success: bool,
}

/// Confirm password reset
///
/// Validates the token and sets the new password. Tokens expire after 1 hour
/// and are deleted on use.
#[utoipa::path(
    method(post),
    path = "/confirm",
    request_body = ConfirmResetBody,
    responses(
        (status = OK, description = "Password updated", body = ConfirmResetResponse, content_type = "application/json"),
        (status = BAD_REQUEST, description = "Invalid or expired token", body = String, content_type = "application/json"),
    ),
    tag = "Password Reset"
)]
async fn confirm_reset(
    Extension(state): Extension<AppState>,
    Valid(Json(body)): Valid<Json<ConfirmResetBody>>,
) -> AxumResult<Json<ConfirmResetResponse>> {
    let token_hash = hash_token(&body.token);

    let token_doc = password_reset_token::Entity::find()
        .filter(password_reset_token::Column::TokenHash.eq(&token_hash))
        .one(&state.db)
        .await?;

    let Some(token_doc) = token_doc else {
        return Err(AxumError::bad_request(eyre::eyre!(
            "Invalid or expired token"
        )));
    };

    if Utc::now() > token_doc.expires_at {
        password_reset_token::Entity::delete_by_id(token_doc.id)
            .exec(&state.db)
            .await?;
        return Err(AxumError::bad_request(eyre::eyre!(
            "Invalid or expired token"
        )));
    }

    let new_hash = hash_password(&body.new_password)?;

    // Update the password record
    let pw = password::Entity::find()
        .filter(password::Column::UserId.eq(token_doc.user_id))
        .one(&state.db)
        .await?;

    if let Some(pw) = pw {
        let mut active: password::ActiveModel = pw.into();
        active.password_hash = Set(new_hash);
        active.update(&state.db).await?;
    } else {
        // No password record exists yet — create one
        let new_pw = password::ActiveModel {
            user_id: Set(token_doc.user_id),
            password_hash: Set(new_hash),
        };
        new_pw.insert(&state.db).await?;

        upsert_auth_method(&state.db, token_doc.user_id, auth_method::Method::Password).await?;
    }

    if let Err(e) =
        invalidate_user_sessions(&state.db, &state.redis_pool, token_doc.user_id, None).await
    {
        tracing::error!(error = ?e, "Failed to invalidate user sessions after password reset");
    }

    refresh_token::Entity::update_many()
        .col_expr(refresh_token::Column::Revoked, Expr::value(true))
        .filter(refresh_token::Column::UserId.eq(token_doc.user_id))
        .filter(refresh_token::Column::Revoked.eq(false))
        .exec(&state.db)
        .await?;

    password_reset_token::Entity::delete_by_id(token_doc.id)
        .exec(&state.db)
        .await?;

    Ok(Json(ConfirmResetResponse { success: true }))
}
