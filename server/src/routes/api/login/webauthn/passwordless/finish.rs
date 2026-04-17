use axum::{Extension, Json};
use color_eyre::{Result, eyre};
use entity::{user, webauthn as webauthn_entity};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use tower_sessions::Session;
use utoipa_axum::{router::OpenApiRouter, routes};
use webauthn_rs::prelude::*;

use crate::{
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::UnauthorizedError,
    routes::api::{AuthState, login::SuccessfulLoginResponse},
    state::AppState,
};

use super::super::helpers::update_webauthn_credentials;

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(passwordless_finish))
}

/// Finish discoverable (passwordless) WebAuthn authentication
///
/// Completes the discoverable credential authentication flow. Requires a previous call to
/// `/api/login/webauthn/passwordless/start`. The server identifies the user from the credential's
/// embedded user handle (UUID).
#[utoipa::path(
    method(post),
    path = "/",
    request_body = crate::webauthn::types::PublicKeyCredential,
    responses(
        (status = OK, description = "Success", body = SuccessfulLoginResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Invalid credential or user not found", body = UnauthorizedError, content_type = "application/json"),
    ),
    tag = "Login"
)]
async fn passwordless_finish(
    Extension(state): Extension<AppState>,
    session: Session,
    Json(auth): Json<PublicKeyCredential>,
) -> AxumResult<Json<SuccessfulLoginResponse>> {
    let auth_state: DiscoverableAuthentication = session
        .get("discoverable_auth_state")
        .await?
        .ok_or(AxumError::forbidden(eyre::eyre!(
            "Missing discoverable auth session. Use /api/login/webauthn/passwordless/start first."
        )))?;

    session.remove_value("discoverable_auth_state").await?;

    let (user_uuid, _cred_id) = state
        .webauthn
        .identify_discoverable_authentication(&auth)
        .map_err(|e| {
            AxumError::unauthorized(eyre::eyre!("Failed to identify credential: {}", e))
        })?;

    let found_user = user::Entity::find()
        .filter(user::Column::Uuid.eq(user_uuid))
        .one(&state.db)
        .await?
        .ok_or(AxumError::unauthorized(eyre::eyre!(
            "User not found for this credential"
        )))?;

    let keys = webauthn_entity::Entity::find()
        .filter(webauthn_entity::Column::UserId.eq(found_user.id))
        .all(&state.db)
        .await?;

    let discoverable_keys = keys
        .iter()
        .map(|f| -> Result<DiscoverableKey> {
            let passkey: Passkey = serde_json::from_str(&f.serialized_key)?;
            Ok(passkey.into())
        })
        .collect::<Result<Vec<DiscoverableKey>, _>>()?;

    if discoverable_keys.is_empty() {
        return Err(AxumError::unauthorized(eyre::eyre!(
            "No WebAuthn credentials found for user"
        )));
    }

    let auth_result = state
        .webauthn
        .finish_discoverable_authentication(&auth, auth_state, &discoverable_keys)
        .map_err(|e| {
            AxumError::unauthorized(eyre::eyre!("Discoverable authentication failed: {}", e))
        })?;

    update_webauthn_credentials(&state, found_user.id, &auth_result).await?;

    session.insert("user_id", found_user.id).await?;
    session
        .insert("auth_state", AuthState::Authenticated)
        .await?;

    Ok(Json(SuccessfulLoginResponse {
        two_factor_required: false,
        recent_factor: None,
        second_factors: None,
    }))
}
