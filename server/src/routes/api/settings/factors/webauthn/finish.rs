use axum::{Extension, Json};
use base64::Engine;
use color_eyre::eyre::{self, Context, ContextCompat};
use entity::{auth_method, webauthn as webauthn_entity};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Serialize;
use tower_sessions::Session;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use webauthn_rs::prelude::*;

use crate::{
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::{UnauthorizedError, UserId},
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(webauthn_finish_setup))
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({ "success": true }))]
struct WebAuthnFinishSuccess {
    success: bool,
}

/// Finish WebAuthn setup
///
/// Requires a previous call to `/api/settings/factors/webauthn/start` to initiate the registration process.
#[utoipa::path(
    method(post),
    path = "/",
    request_body = crate::webauthn::types::RegisterPublicKeyCredential,
    responses(
        (status = OK, description = "Success", body = WebAuthnFinishSuccess, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn webauthn_finish_setup(
    Extension(user_id): Extension<UserId>,
    Extension(state): Extension<AppState>,
    session: Session,
    Json(reg): Json<RegisterPublicKeyCredential>,
) -> AxumResult<Json<WebAuthnFinishSuccess>> {
    let reg_state: PasskeyRegistration = session.get("reg_state").await?.ok_or(AxumError::forbidden(eyre::eyre!("Missing WebAuthn registration session. Use the /api/settings/factors/webauthn/start endpoint first.")))?;

    session.remove_value("reg_state").await?;

    let sk = state
        .webauthn
        .finish_passkey_registration(&reg, &reg_state)
        .map_err(|e| AxumError::bad_request(eyre::eyre!("WebAuthn registration failed: {}", e)))?;

    let display_name: String = session
        .get("webauthn_display_name")
        .await?
        .wrap_err("Missing display name")?;

    let serialized_key = serde_json::to_string(&sk).wrap_err("Failed to serialize passkey")?;
    let credential_id =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.cred_id().as_ref());

    let model = webauthn_entity::ActiveModel {
        id: Default::default(),
        user_id: Set(*user_id),
        credential_id: Set(credential_id),
        display_name: Set(display_name),
        serialized_key: Set(serialized_key),
    };
    model.insert(&state.db).await?;

    // Upsert auth_method record for WebAuthn
    let now = chrono::Utc::now();
    let existing_method = auth_method::Entity::find()
        .filter(auth_method::Column::UserId.eq(*user_id))
        .filter(auth_method::Column::MethodType.eq(auth_method::Method::WebAuthn))
        .one(&state.db)
        .await?;
    if existing_method.is_none() {
        let am = auth_method::ActiveModel {
            user_id: Set(*user_id),
            method_type: Set(auth_method::Method::WebAuthn),
            is_enabled: Set(true),
            enrolled_at: Set(now),
            modified_at: Set(now),
            last_used_at: Set(None),
        };
        am.insert(&state.db).await?;
    }

    Ok(Json(WebAuthnFinishSuccess { success: true }))
}
