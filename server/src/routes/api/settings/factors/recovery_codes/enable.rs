use axum::{Extension, Json};
use entity::recovery_code;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    axum_error::AxumResult,
    middlewares::require_auth::{UnauthorizedError, UserId},
    routes::api::settings::factors::recovery_codes::{
        generate_recovery_codes, hash_recovery_codes,
    },
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(enable_recovery_codes))
}

#[derive(Serialize, ToSchema)]
pub struct EnableRecoveryCodesResponse {
    /// Generated security codes. Save them securely as they won't be shown again.
    pub codes: Vec<String>,
}

/// Enable recovery codes
///
/// **Calling this endpoint again will regenerate the recovery codes.** The old codes will be forever lost.
#[utoipa::path(
    method(post),
    path = "/",
    responses(
        (status = OK, description = "Success", body = EnableRecoveryCodesResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn enable_recovery_codes(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
) -> AxumResult<Json<EnableRecoveryCodesResponse>> {
    let codes = generate_recovery_codes(10, 12);
    let hashed_codes = hash_recovery_codes(codes.clone())?;

    // Delete old codes
    recovery_code::Entity::delete_many()
        .filter(recovery_code::Column::UserId.eq(*user_id))
        .exec(&state.db)
        .await?;

    // Insert new codes
    for hash in &hashed_codes {
        let model = recovery_code::ActiveModel {
            id: Default::default(),
            user_id: Set(*user_id),
            code_hash: Set(hash.clone()),
            used: Set(false),
        };
        model.insert(&state.db).await?;
    }

    Ok(Json(EnableRecoveryCodesResponse { codes }))
}
