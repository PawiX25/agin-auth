use axum::{Extension, Json};
use axum_valid::Valid;
use color_eyre::eyre;
use entity::pgp;
use pgp_lib::{
    composed::{ArmorOptions, Deserializable, SignedPublicKey},
    types::KeyDetails,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::{UnauthorizedError, UserId},
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(enable_pgp))
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct EnablePgpBody {
    /// The display name for the PGP factor.
    #[validate(length(min = 1, max = 32))]
    pub display_name: String,

    /// The public key
    #[validate(length(min = 1))]
    pub public_key: String,
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({ "success": true }))]
pub struct EnablePgpResponse {
    pub success: bool,
}

/// Enable PGP
///
/// Enables PGP authentication factor for the user. This factor can only be used as a first factor.
#[utoipa::path(
    method(post),
    path = "/",
    request_body = EnablePgpBody,
    responses(
        (status = OK, description = "Success", body = EnablePgpResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn enable_pgp(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
    Valid(Json(body)): Valid<Json<EnablePgpBody>>,
) -> AxumResult<Json<EnablePgpResponse>> {
    let (public_key, _) = SignedPublicKey::from_string(&body.public_key)
        .map_err(|_| AxumError::bad_request(eyre::eyre!("Invalid public key")))?;

    let fingerprint = public_key.fingerprint().to_string();

    // Check for duplicate fingerprint
    let existing = pgp::Entity::find()
        .filter(pgp::Column::UserId.eq(*user_id))
        .filter(pgp::Column::Fingerprint.eq(&fingerprint))
        .one(&state.db)
        .await?;

    if existing.is_some() {
        return Err(AxumError::bad_request(eyre::eyre!(
            "This PGP key is already added"
        )));
    }

    let model = pgp::ActiveModel {
        id: Default::default(),
        user_id: Set(*user_id),
        display_name: Set(body.display_name),
        public_key: Set(public_key.to_armored_string(ArmorOptions::default())?),
        fingerprint: Set(fingerprint),
    };
    model.insert(&state.db).await?;

    Ok(Json(EnablePgpResponse { success: true }))
}
