use axum::{Extension, Json};
use axum_valid::Valid;
use color_eyre::eyre::{self, ContextCompat};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use tower_sessions::Session;

use crate::{
    axum_error::{AxumError, AxumResult},
    database::{User, get_user_by_id, invalidate_user_sessions},
    middlewares::require_auth::{UnauthorizedError, UserId},
    state::AppState,
    utils::{hash_password, verify_password},
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(change_password))
}

#[derive(Deserialize, ToSchema, Validate)]
struct ChangePasswordBody {
    current_password: String,

    #[validate(length(min = 8))]
    new_password: String,
}

#[derive(Serialize, ToSchema)]
struct ChangePasswordResponse {
    success: bool,
}

/// Change password
///
/// Changes the current user's password. Requires the current password for verification.
#[utoipa::path(
    method(post),
    path = "/change",
    request_body = ChangePasswordBody,
    responses(
        (status = OK, description = "Password changed", body = ChangePasswordResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
        (status = BAD_REQUEST, description = "Invalid current password or password not set", body = String, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn change_password(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
    session: Session,
    Valid(Json(body)): Valid<Json<ChangePasswordBody>>,
) -> AxumResult<Json<ChangePasswordResponse>> {
    let user = get_user_by_id(&state.database, &user_id)
        .await?
        .wrap_err("User not found")?;

    let password_hash = user
        .auth_factors
        .password
        .password_hash
        .as_deref()
        .ok_or_else(|| {
            AxumError::bad_request(eyre::eyre!("Password is not set for this account"))
        })?;

    verify_password(&body.current_password, password_hash)
        .map_err(|_| AxumError::bad_request(eyre::eyre!("Current password is incorrect")))?;

    let new_hash = hash_password(&body.new_password)?;

    state
        .database
        .collection::<User>("users")
        .update_one(
            doc! { "_id": *user_id },
            doc! { "$set": { "auth_factors.password.password_hash": &new_hash } },
        )
        .await?
        .matched_count
        .eq(&1)
        .then_some(())
        .wrap_err("User not found")?;

    let current_session_id = session.id().map(|id| id.to_string());
    if let Err(e) = invalidate_user_sessions(
        &state.database,
        &state.redis_pool,
        &user_id,
        current_session_id.as_deref(),
    )
    .await
    {
        tracing::error!(error = ?e, "Failed to invalidate user sessions after password change");
    }

    Ok(Json(ChangePasswordResponse { success: true }))
}
