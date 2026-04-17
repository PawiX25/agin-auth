use axum::{Extension, Json};
use axum_valid::Valid;
use color_eyre::eyre::{self, ContextCompat};
use entity::{password, session};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use tower_sessions_redis_store::fred::prelude::KeysInterface;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::{UnauthorizedError, UserId},
    state::AppState,
    utils::{hash_password, verify_password},
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(change_password))
}

#[derive(Deserialize, ToSchema, Validate)]
struct ChangePasswordBody {
    #[validate(length(max = 256))]
    current_password: String,

    #[validate(length(min = 8, max = 256))]
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
    let pw = password::Entity::find_by_id(*user_id)
        .one(&state.db)
        .await?
        .wrap_err("Password is not set for this account")?;

    verify_password(&body.current_password, &pw.password_hash)
        .map_err(|_| AxumError::bad_request(eyre::eyre!("Current password is incorrect")))?;

    let new_hash = hash_password(&body.new_password)?;

    let mut model = pw.into_active_model();
    model.password_hash = Set(new_hash);
    model.update(&state.db).await?;

    // Invalidate all other sessions for this user
    let current_session_key = session.id().map(|id| id.to_string());
    let sessions = session::Entity::find()
        .filter(session::Column::UserId.eq(*user_id))
        .all(&state.db)
        .await?;

    for s in &sessions {
        if current_session_key.as_deref() == Some(&s.session_key) {
            continue;
        }
        let _: i64 = state
            .redis_pool
            .del(&s.session_key)
            .await
            .unwrap_or_default();
    }

    // Remove invalidated session records from DB
    let ids_to_delete: Vec<i32> = sessions
        .iter()
        .filter(|s| current_session_key.as_deref() != Some(&s.session_key))
        .map(|s| s.id)
        .collect();
    if !ids_to_delete.is_empty() {
        session::Entity::delete_many()
            .filter(session::Column::Id.is_in(ids_to_delete))
            .exec(&state.db)
            .await?;
    }

    Ok(Json(ChangePasswordResponse { success: true }))
}
