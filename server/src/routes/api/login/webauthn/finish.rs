use axum::{Extension, Json};
use color_eyre::eyre;
use tower_sessions::Session;
use utoipa_axum::{router::OpenApiRouter, routes};
use webauthn_rs::prelude::*;

use crate::{
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::{UnauthorizedError, UserId},
    routes::api::{AuthState, login::SuccessfulLoginResponse},
    state::AppState,
};

use super::helpers::update_webauthn_credentials;

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(webauthn_finish_login))
}

/// Finish WebAuthn 2FA
///
/// **This endpoint can only be used as a second factor.** For passwordless authentication, see `/api/login/webauthn/passwordless/start`. Requires a previous call to `/api/login/webauthn/start` to initiate the login process.
#[utoipa::path(
    method(post),
    path = "/",
    request_body = crate::webauthn::types::PublicKeyCredential,
    responses(
        (status = OK, description = "Success", body = SuccessfulLoginResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
    ),
    tag = "Login"
)]
async fn webauthn_finish_login(
    Extension(user_id): Extension<UserId>,
    Extension(state): Extension<AppState>,
    session: Session,
    Json(auth): Json<PublicKeyCredential>,
) -> AxumResult<Json<SuccessfulLoginResponse>> {
    let auth_state: PasskeyAuthentication =
        session
            .get("webauthn_login_state")
            .await?
            .ok_or(AxumError::forbidden(eyre::eyre!(
                "Missing WebAuthn login session. Use the /api/login/webauthn/start endpoint first."
            )))?;

    session.remove_value("webauthn_login_state").await?;

    let auth_result = state
        .webauthn
        .finish_passkey_authentication(&auth, &auth_state)
        .map_err(|e| {
            AxumError::bad_request(eyre::eyre!("WebAuthn authentication failed: {}", e))
        })?;

    update_webauthn_credentials(&state, *user_id, &auth_result).await?;

    session
        .insert("auth_state", AuthState::Authenticated)
        .await?;

    Ok(Json(SuccessfulLoginResponse {
        two_factor_required: false,
        recent_factor: None,
        second_factors: None,
    }))
}
