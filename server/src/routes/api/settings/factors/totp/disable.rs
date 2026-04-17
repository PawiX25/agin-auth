use axum::{Extension, Json};
use color_eyre::eyre;
use entity::{auth_method, totp, user};
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
    OpenApiRouter::new().routes(routes!(disable_totp))
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({ "success": true }))]
struct DisableTotpResponse {
    success: bool,
}

/// Disable TOTP
///
/// Removes the TOTP authentication factor from the user's account.
#[utoipa::path(
    method(delete),
    path = "/",
    responses(
        (status = OK, description = "Success", body = DisableTotpResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
        (status = BAD_REQUEST, description = "TOTP not enabled", body = String, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn disable_totp(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
) -> AxumResult<Json<DisableTotpResponse>> {
    let totp_record = totp::Entity::find_by_id(*user_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AxumError::bad_request(eyre::eyre!("TOTP is not enabled")))?;

    if !totp_record.fully_enabled {
        return Err(AxumError::bad_request(eyre::eyre!("TOTP is not enabled")));
    }

    totp_record.delete(&state.db).await?;

    // Remove auth_method record for TOTP
    if let Some(method) = auth_method::Entity::find()
        .filter(auth_method::Column::UserId.eq(*user_id))
        .filter(auth_method::Column::MethodType.eq(auth_method::Method::Totp))
        .one(&state.db)
        .await?
    {
        method.delete(&state.db).await?;
    }

    if let Some(mail) = &state.mail_service {
        let user = user::Entity::find_by_id(*user_id).one(&state.db).await?;
        if let Some(user) = user {
            let email = user.email;
            let mail = mail.clone();
            tokio::spawn(async move {
                if let Err(e) = mail.send_factor_removed(&email, "TOTP authenticator").await {
                    tracing::warn!(error = ?e, "Failed to send factor removed notification");
                }
            });
        }
    }

    Ok(Json(DisableTotpResponse { success: true }))
}
