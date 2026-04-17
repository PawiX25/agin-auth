use axum::{Extension, Json};
use color_eyre::eyre::{self, Context, Result};
use entity::webauthn as webauthn_entity;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use tower_sessions::Session;
use utoipa_axum::{router::OpenApiRouter, routes};
use webauthn_rs::prelude::{Passkey, RequestChallengeResponse};

use crate::{
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::{UnauthorizedError, UserId},
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(webauthn_start_login))
}

/// Start WebAuthn 2FA
///
/// **This endpoint can only be used as a second factor.** For passwordless authentication, see `/api/login/webauthn/passwordless/start`. Request a challenge to start the WebAuthn login process. After receiving a response from the browser, the client should call the `/api/login/webauthn/finish` endpoint to complete the login.
#[utoipa::path(
    method(post),
    path = "/",
    responses(
        (status = OK, description = "Success", body = crate::webauthn::types::RequestChallengeResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
    ),
    tag = "Login"
)]
async fn webauthn_start_login(
    Extension(user_id): Extension<UserId>,
    Extension(state): Extension<AppState>,
    session: Session,
) -> AxumResult<Json<RequestChallengeResponse>> {
    session.remove_value("webauthn_login_state").await?;

    let keys = webauthn_entity::Entity::find()
        .filter(webauthn_entity::Column::UserId.eq(*user_id))
        .all(&state.db)
        .await?;

    let allow_credentials = keys
        .iter()
        .map(|f| -> Result<Passkey> {
            let passkey: Passkey = serde_json::from_str(&f.serialized_key)?;
            Ok(passkey)
        })
        .collect::<Result<Vec<Passkey>, _>>()?;

    if allow_credentials.is_empty() {
        return Err(AxumError::unauthorized(eyre::eyre!(
            "No WebAuthn credentials found for user."
        )));
    }

    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&allow_credentials)
        .wrap_err("Challenge generation failed")?;

    session.insert("webauthn_login_state", auth_state).await?;

    Ok(Json(rcr))
}
