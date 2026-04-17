use std::ops::Deref;

use axum::{Extension, extract::Request, http::header, middleware::Next, response::Response};
use axum_client_ip::ClientIp;
use color_eyre::eyre;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use utoipa::ToSchema;

use crate::{
    axum_error::{AxumError, AxumResult},
    database::record_session,
    routes::api::AuthState,
    state::AppState,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserId(pub i32);

impl Deref for UserId {
    type Target = i32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

async fn get_auth_state(session: &Session) -> color_eyre::Result<(i32, AuthState)> {
    let user_id = session.get::<i32>("user_id").await?;
    let auth_state = session.get::<AuthState>("auth_state").await?;
    if auth_state.is_none() || user_id.is_none() {
        return Err(eyre::eyre!("Unauthorized"));
    }

    let user_id = user_id.unwrap();
    let auth_state = auth_state.unwrap();

    Ok((user_id, auth_state))
}

/// Middleware that ensures the user is authenticated
pub async fn require_auth(
    Extension(state): Extension<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    mut request: Request,
    next: Next,
) -> AxumResult<Response> {
    let (user_id, auth_state) = get_auth_state(&session)
        .await
        .map_err(|_| AxumError::unauthorized(eyre::eyre!("Unauthorized")))?;

    if auth_state != AuthState::Authenticated {
        return Err(AxumError::unauthorized(eyre::eyre!("Unauthorized")));
    }

    if let Some(session_id) = session.id() {
        let user_agent = request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("unknown")
            .to_owned();

        if let Err(error) = record_session(
            &state.db,
            &session_id.to_string(),
            user_id,
            &ip.to_string(),
            &user_agent,
        )
        .await
        {
            tracing::warn!(error = ?error, "Failed to record session");
        }
    }

    request.extensions_mut().insert(UserId(user_id));

    Ok(next.run(request).await)
}

/// Middleware that ensures the user has completed the first factor of authentication
pub async fn require_first_factor(
    session: Session,
    mut request: Request,
    next: Next,
) -> AxumResult<Response> {
    let (user_id, auth_state) = get_auth_state(&session)
        .await
        .map_err(|_| AxumError::unauthorized(eyre::eyre!("Unauthorized")))?;

    if auth_state == AuthState::Anonymous {
        return Err(AxumError::unauthorized(eyre::eyre!("Unauthorized")));
    }

    if auth_state == AuthState::Authenticated {
        return Err(AxumError::forbidden(eyre::eyre!("Already logged in")));
    }

    request.extensions_mut().insert(UserId(user_id));

    Ok(next.run(request).await)
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({"error": "Unauthorized"}))]
pub struct UnauthorizedError {
    error: String,
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({"error": "Forbidden"}))]
pub struct ForbiddenError {
    error: String,
}

/// Middleware that ensures the user is an admin.
/// Must be applied after `require_auth` so that `UserId` is available in extensions.
pub async fn require_admin(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
    request: Request,
    next: Next,
) -> AxumResult<Response> {
    use entity::user;
    use sea_orm::{EntityTrait, prelude::*};

    let user = user::Entity::find_by_id(*user_id)
        .one(&state.db)
        .await
        .map_err(|_| AxumError::forbidden(eyre::eyre!("Forbidden")))?
        .ok_or_else(|| AxumError::forbidden(eyre::eyre!("Forbidden")))?;

    if !user.is_admin {
        return Err(AxumError::forbidden(eyre::eyre!("Forbidden")));
    }

    Ok(next.run(request).await)
}
