use axum::{Extension, Json};
use axum_valid::Valid;
use chrono::{DateTime, Duration, Utc};
use color_eyre::eyre::{self, ContextCompat};
use mongodb::bson::{doc, oid::ObjectId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    axum_error::{AxumError, AxumResult},
    database::{User, invalidate_user_sessions},
    state::AppState,
    utils::{generate_reset_token, hash_password, hash_token},
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(request_reset))
        .routes(routes!(confirm_reset))
}

#[derive(Debug, Serialize, Deserialize)]
struct PasswordResetToken {
    token_hash: String,
    user_id: ObjectId,
    expires_at: DateTime<Utc>,
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

    let user = state
        .database
        .collection::<User>("users")
        .find_one(doc! { "email": &body.email })
        .await?;

    let Some(user) = user else {
        return Ok(Json(RequestResetResponse { success: true }));
    };

    let token = generate_reset_token();
    let token_hash = hash_token(&token);
    let expires_at = Utc::now() + Duration::hours(1);

    state
        .database
        .collection::<PasswordResetToken>("password_reset_tokens")
        .insert_one(PasswordResetToken {
            token_hash,
            user_id: user.id,
            expires_at,
        })
        .await?;

    if let Err(e) = mail.send_password_reset(&user.email, &token).await {
        tracing::warn!(error = ?e, "Failed to send password reset email");
    }

    Ok(Json(RequestResetResponse { success: true }))
}

#[derive(Deserialize, ToSchema, Validate)]
struct ConfirmResetBody {
    token: String,

    #[validate(length(min = 8))]
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

    let token_doc = state
        .database
        .collection::<PasswordResetToken>("password_reset_tokens")
        .find_one(doc! { "token_hash": &token_hash })
        .await?;

    let Some(token_doc) = token_doc else {
        return Err(AxumError::bad_request(eyre::eyre!(
            "Invalid or expired token"
        )));
    };

    if Utc::now() > token_doc.expires_at {
        state
            .database
            .collection::<PasswordResetToken>("password_reset_tokens")
            .delete_one(doc! { "token_hash": &token_hash })
            .await?;
        return Err(AxumError::bad_request(eyre::eyre!(
            "Invalid or expired token"
        )));
    }

    let new_hash = hash_password(&body.new_password)?;

    state
        .database
        .collection::<User>("users")
        .update_one(
            doc! { "_id": token_doc.user_id },
            doc! { "$set": { "auth_factors.password.password_hash": &new_hash } },
        )
        .await?
        .matched_count
        .eq(&1)
        .then_some(())
        .wrap_err("User not found")?;

    if let Err(e) =
        invalidate_user_sessions(&state.database, &state.redis_pool, &token_doc.user_id, None).await
    {
        tracing::error!(error = ?e, "Failed to invalidate user sessions after password reset");
    }

    state
        .database
        .collection::<PasswordResetToken>("password_reset_tokens")
        .delete_one(doc! { "token_hash": &token_hash })
        .await?;

    Ok(Json(ConfirmResetResponse { success: true }))
}
