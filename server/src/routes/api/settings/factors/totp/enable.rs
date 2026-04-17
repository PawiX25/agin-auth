mod confirm;

use axum::{Extension, Json};
use axum_valid::Valid;
use base32::{Alphabet, encode};
use color_eyre::eyre::{self, ContextCompat};
use entity::{totp, user};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use serde::{Deserialize, Serialize};
use totp_rs::Secret;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::{UnauthorizedError, UserId},
    routes::api::settings::factors::totp::create_totp_instance,
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(enable_totp))
        .nest("/confirm", confirm::routes())
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct EnableTotpBody {
    /// The display name for the TOTP factor (for example authenticator app name).
    #[validate(length(min = 1, max = 32))]
    pub display_name: String,
}

#[derive(Serialize, ToSchema)]
pub struct EnableTotpResponse {
    /// The secret won't be shown again, so save it securely.
    pub secret: String,
    /// QR code URL that'll add the TOTP factor to your authenticator app. Won't be shown again.
    pub qr: String,
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({
    "error": "TOTP is already enabled. To rotate your TOTP secret, disable it first and then enable it again."
}))]
pub struct AlreadyEnabledError {
    pub error: String,
}

/// Enable TOTP
///
/// Generates TOTP secret and saves it. To fully enable TOTP, a call to `/api/settings/factors/totp/enable/confirm` is required.
#[utoipa::path(
    method(post),
    path = "/",
    request_body = EnableTotpBody,
    responses(
        (status = OK, description = "Success", body = EnableTotpResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
        (status = FORBIDDEN, description = "Already Enabled", body = AlreadyEnabledError, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn enable_totp(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
    Valid(Json(body)): Valid<Json<EnableTotpBody>>,
) -> AxumResult<Json<EnableTotpResponse>> {
    let existing = totp::Entity::find_by_id(*user_id).one(&state.db).await?;

    if existing.as_ref().is_some_and(|t| t.fully_enabled) {
        return Err(AxumError::forbidden(eyre::eyre!(
            "TOTP is already enabled. To rotate your TOTP secret, disable it first and then enable it again."
        )));
    }

    let raw_secret = Secret::generate_secret().to_bytes()?;
    let encoded_secret = encode(Alphabet::Rfc4648 { padding: false }, &raw_secret);

    if let Some(old) = existing {
        // Update existing (not yet confirmed) TOTP record
        let mut model: totp::ActiveModel = old.into();
        model.secret = Set(encoded_secret.clone());
        model.display_name = Set(body.display_name);
        model.fully_enabled = Set(false);
        model.update(&state.db).await?;
    } else {
        let model = totp::ActiveModel {
            user_id: Set(*user_id),
            display_name: Set(body.display_name),
            secret: Set(encoded_secret.clone()),
            fully_enabled: Set(false),
        };
        model.insert(&state.db).await?;
    }

    let user = user::Entity::find_by_id(*user_id)
        .one(&state.db)
        .await?
        .wrap_err("User not found")?;

    let totp_instance = create_totp_instance(
        &encoded_secret,
        Some(user.email),
        Some("Agin Auth".to_string()),
    )?;

    let qr = totp_instance.get_url();

    Ok(Json(EnableTotpResponse {
        secret: encoded_secret,
        qr,
    }))
}
