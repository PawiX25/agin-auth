use axum::{Extension, Json, extract::Path};
use color_eyre::eyre;
use entity::{user, webauthn as webauthn_entity};
use sea_orm::{ColumnTrait, EntityTrait, ModelTrait, QueryFilter};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::{UnauthorizedError, UserId},
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(delete_webauthn))
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({ "success": true }))]
struct DeleteWebAuthnResponse {
    success: bool,
}

/// Delete WebAuthn key
///
/// Removes a WebAuthn passkey by its credential ID.
#[utoipa::path(
    method(delete),
    path = "/{credential_id}",
    params(
        ("credential_id" = String, Path, description = "Credential ID of the WebAuthn key to delete")
    ),
    responses(
        (status = OK, description = "Success", body = DeleteWebAuthnResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
        (status = NOT_FOUND, description = "Key not found", body = String, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn delete_webauthn(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
    Path(credential_id): Path<String>,
) -> AxumResult<Json<DeleteWebAuthnResponse>> {
    let key = webauthn_entity::Entity::find()
        .filter(webauthn_entity::Column::UserId.eq(*user_id))
        .filter(webauthn_entity::Column::CredentialId.eq(&credential_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| AxumError::not_found(eyre::eyre!("WebAuthn key not found")))?;

    key.delete(&state.db).await?;

    if let Some(mail) = &state.mail_service {
        let user = user::Entity::find_by_id(*user_id).one(&state.db).await?;
        if let Some(user) = user {
            let email = user.email;
            let mail = mail.clone();
            tokio::spawn(async move {
                if let Err(e) = mail.send_factor_removed(&email, "WebAuthn passkey").await {
                    tracing::warn!(error = ?e, "Failed to send factor removed notification");
                }
            });
        }
    }

    Ok(Json(DeleteWebAuthnResponse { success: true }))
}
