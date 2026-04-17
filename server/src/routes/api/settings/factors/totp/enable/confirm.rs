use axum::{Extension, Json};
use axum_valid::Valid;
use color_eyre::eyre;
use entity::totp;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::{UnauthorizedError, UserId},
    routes::api::settings::factors::totp::{TotpCodeBody, verify_totp},
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(confirm_enabling_totp))
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({ "success": true }))]
pub struct ConfirmTotpResponse {
    pub success: bool,
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({
    "error": "TOTP is already enabled. To rotate your TOTP secret, disable it first and then enable it again."
}))]
pub struct AlreadyEnabledError {
    pub error: String,
}

/// Confirm enabling TOTP
///
/// Confirm enabling TOTP by providing the TOTP code.
#[utoipa::path(
    method(post),
    path = "/",
    request_body = TotpCodeBody,
    responses(
        (status = OK, description = "Success", body = ConfirmTotpResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
        (status = FORBIDDEN, description = "Already Enabled", body = AlreadyEnabledError, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn confirm_enabling_totp(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
    Valid(Json(body)): Valid<Json<TotpCodeBody>>,
) -> AxumResult<Json<ConfirmTotpResponse>> {
    let totp_record = totp::Entity::find_by_id(*user_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AxumError::forbidden(eyre::eyre!("TOTP secret is not yet generated")))?;

    if totp_record.fully_enabled {
        return Err(AxumError::forbidden(eyre::eyre!(
            "TOTP is already enabled. To rotate your TOTP secret, disable it first and then enable it again."
        )));
    }

    verify_totp(&totp_record.secret, &body.code)?;

    let mut model: totp::ActiveModel = totp_record.into();
    model.fully_enabled = Set(true);
    model.update(&state.db).await?;

    Ok(Json(ConfirmTotpResponse { success: true }))
}
