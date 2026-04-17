use axum::{Extension, Json, extract::Path};
use color_eyre::eyre;
use entity::{pgp, user};
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
    OpenApiRouter::new().routes(routes!(delete_pgp_key))
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({ "success": true }))]
struct DeletePgpResponse {
    success: bool,
}

/// Delete PGP key
///
/// Removes a PGP key by its fingerprint.
#[utoipa::path(
    method(delete),
    path = "/{fingerprint}",
    params(
        ("fingerprint" = String, Path, description = "Fingerprint of the PGP key to delete")
    ),
    responses(
        (status = OK, description = "Success", body = DeletePgpResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
        (status = NOT_FOUND, description = "Key not found", body = String, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn delete_pgp_key(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
    Path(fingerprint): Path<String>,
) -> AxumResult<Json<DeletePgpResponse>> {
    let key = pgp::Entity::find()
        .filter(pgp::Column::UserId.eq(*user_id))
        .filter(pgp::Column::Fingerprint.eq(&fingerprint))
        .one(&state.db)
        .await?
        .ok_or_else(|| AxumError::not_found(eyre::eyre!("PGP key not found")))?;

    key.delete(&state.db).await?;

    if let Some(mail) = &state.mail_service {
        let user = user::Entity::find_by_id(*user_id).one(&state.db).await?;
        if let Some(user) = user {
            let email = user.email;
            let mail = mail.clone();
            tokio::spawn(async move {
                if let Err(e) = mail.send_factor_removed(&email, "PGP key").await {
                    tracing::warn!(error = ?e, "Failed to send factor removed notification");
                }
            });
        }
    }

    Ok(Json(DeletePgpResponse { success: true }))
}
