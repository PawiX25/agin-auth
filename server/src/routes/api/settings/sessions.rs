use axum::{Extension, Json};
use color_eyre::eyre;
use entity::session;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use tower_sessions_redis_store::fred::prelude::KeysInterface;
use tracing::warn;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::UserId,
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_sessions))
        .routes(routes!(delete_session))
}

#[derive(Serialize, ToSchema)]
struct SessionItem {
    id: String,
    ip_address: String,
    user_agent: String,
    created_at: String,
    last_active: String,
    current: bool,
}

#[derive(Serialize, ToSchema)]
struct SessionsResponse {
    sessions: Vec<SessionItem>,
}

/// List active sessions
///
/// Returns all active sessions for the current user.
#[utoipa::path(
    method(get),
    path = "/",
    responses(
        (status = OK, description = "Sessions list", body = SessionsResponse, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn list_sessions(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
    session: Session,
) -> AxumResult<Json<SessionsResponse>> {
    let current_session_key = session.id().map(|id| id.to_string()).unwrap_or_default();

    let records = session::Entity::find()
        .filter(session::Column::UserId.eq(*user_id))
        .order_by_desc(session::Column::LastActive)
        .all(&state.db)
        .await?;

    let mut sessions = Vec::new();
    let mut stale_ids = Vec::new();

    for record in records {
        let exists: i64 = state
            .redis_pool
            .exists(&record.session_key)
            .await
            .map_err(|error| {
                AxumError::new(eyre::eyre!("Failed to validate session state: {}", error))
            })?;

        if exists == 0 {
            stale_ids.push(record.id);
            continue;
        }

        let is_current = record.session_key == current_session_key;
        sessions.push(SessionItem {
            id: record.public_id.to_string(),
            ip_address: record.ip_address.unwrap_or_default(),
            user_agent: record.user_agent.unwrap_or_default(),
            created_at: record.created_at.to_rfc3339(),
            last_active: record.last_active.to_rfc3339(),
            current: is_current,
        });
    }

    if !stale_ids.is_empty() {
        session::Entity::delete_many()
            .filter(session::Column::Id.is_in(stale_ids))
            .exec(&state.db)
            .await?;
    }

    sessions.sort_by(|a, b| {
        b.current
            .cmp(&a.current)
            .then(b.last_active.cmp(&a.last_active))
    });

    Ok(Json(SessionsResponse { sessions }))
}

#[derive(Deserialize, ToSchema, IntoParams)]
struct DeleteSessionPath {
    session_id: String,
}

#[derive(Serialize, ToSchema)]
struct DeleteSessionResponse {
    success: bool,
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({ "error": "Session not found" }))]
struct SessionErrorResponse {
    error: String,
}

/// Revoke a session
///
/// Deletes a specific session by ID. Cannot revoke the current session (use logout instead).
#[utoipa::path(
    method(delete),
    path = "/{session_id}",
    params(DeleteSessionPath),
    responses(
        (status = OK, description = "Session revoked", body = DeleteSessionResponse, content_type = "application/json"),
        (status = BAD_REQUEST, description = "Cannot revoke current session", body = SessionErrorResponse, content_type = "application/json"),
        (status = NOT_FOUND, description = "Session not found", body = SessionErrorResponse, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn delete_session(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
    session: Session,
    axum::extract::Path(path): axum::extract::Path<DeleteSessionPath>,
) -> AxumResult<Json<DeleteSessionResponse>> {
    let current_session_key = session.id().map(|id| id.to_string()).unwrap_or_default();

    let public_uuid = path
        .session_id
        .parse::<Uuid>()
        .map_err(|_| AxumError::not_found(eyre::eyre!("Session not found")))?;

    let record = session::Entity::find()
        .filter(session::Column::PublicId.eq(public_uuid))
        .filter(session::Column::UserId.eq(*user_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| AxumError::not_found(eyre::eyre!("Session not found")))?;

    if record.session_key == current_session_key {
        return Err(AxumError::bad_request(eyre::eyre!(
            "Cannot revoke the current session. Use logout instead."
        )));
    }

    let _: i64 = state
        .redis_pool
        .del(&record.session_key)
        .await
        .map_err(|e| AxumError::new(eyre::eyre!("Failed to invalidate session: {}", e)))?;

    if let Err(error) = session::Entity::delete_by_id(record.id)
        .exec(&state.db)
        .await
    {
        warn!(
            error = ?error,
            public_id = %path.session_id,
            "Failed to clean up session record after revoke"
        );
    }

    Ok(Json(DeleteSessionResponse { success: true }))
}
