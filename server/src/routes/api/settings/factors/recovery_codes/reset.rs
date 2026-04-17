use axum::{Extension, Json};
use color_eyre::eyre;
use entity::{recovery_code, user};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, Set};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::{UnauthorizedError, UserId},
    routes::api::settings::factors::recovery_codes::{
        generate_recovery_codes, hash_recovery_codes,
    },
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(reset_recovery_codes))
}

#[derive(Serialize, ToSchema)]
pub struct ResetRecoveryCodesResponse {
    /// New recovery codes. Save them securely as they won't be shown again.
    pub codes: Vec<String>,
}

/// Reset recovery codes
///
/// Invalidates all existing recovery codes and generates a fresh set of 10.
#[utoipa::path(
    method(post),
    path = "/",
    responses(
        (status = OK, description = "Success", body = ResetRecoveryCodesResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
        (status = BAD_REQUEST, description = "Recovery codes not enabled", body = String, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn reset_recovery_codes(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
) -> AxumResult<Json<ResetRecoveryCodesResponse>> {
    let existing_count = recovery_code::Entity::find()
        .filter(recovery_code::Column::UserId.eq(*user_id))
        .count(&state.db)
        .await?;

    if existing_count == 0 {
        return Err(AxumError::bad_request(eyre::eyre!(
            "Recovery codes are not enabled"
        )));
    }

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

    if let Some(mail) = &state.mail_service {
        let user = user::Entity::find_by_id(*user_id).one(&state.db).await?;
        if let Some(user) = user {
            let email = user.email;
            let mail = mail.clone();
            tokio::spawn(async move {
                if let Err(e) = mail
                    .send_factor_added(&email, "recovery codes (regenerated)")
                    .await
                {
                    tracing::warn!(error = ?e, "Failed to send factor notification");
                }
            });
        }
    }

    Ok(Json(ResetRecoveryCodesResponse { codes }))
}
