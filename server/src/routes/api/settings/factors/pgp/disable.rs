use axum::{Extension, Json};
use color_eyre::eyre;
use entity::{pgp, user};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::{UnauthorizedError, UserId},
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(disable_pgp))
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({ "success": true }))]
struct DisablePgpResponse {
    success: bool,
}

/// Disable PGP
///
/// Removes the PGP authentication factor from the user's account.
#[utoipa::path(
    method(delete),
    path = "/",
    responses(
        (status = OK, description = "Success", body = DisablePgpResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
        (status = BAD_REQUEST, description = "PGP not enabled", body = String, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn disable_pgp(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
) -> AxumResult<Json<DisablePgpResponse>> {
    let count = pgp::Entity::find()
        .filter(pgp::Column::UserId.eq(*user_id))
        .count(&state.db)
        .await?;

    if count == 0 {
        return Err(AxumError::bad_request(eyre::eyre!("PGP is not enabled")));
    }

    pgp::Entity::delete_many()
        .filter(pgp::Column::UserId.eq(*user_id))
        .exec(&state.db)
        .await?;

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

    Ok(Json(DisablePgpResponse { success: true }))
}
