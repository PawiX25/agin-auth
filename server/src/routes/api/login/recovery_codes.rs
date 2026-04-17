use axum::{Extension, Json};
use color_eyre::eyre;
use entity::{auth_method, recovery_code};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, sea_query::Expr};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    auth_method_helpers::touch_auth_method,
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::UserId,
    routes::api::{AuthState, settings::factors::recovery_codes::verify_recovery_code},
    state::AppState,
};

use super::SuccessfulLoginResponse;

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(login_with_recovery_code))
}

#[derive(Deserialize, ToSchema)]
struct RecoveryCodeLoginBody {
    code: String,
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({"error": "Invalid recovery code"}))]
pub struct InvalidRecoveryCode {
    error: String,
}

/// Log in with a recovery code
///
/// **This endpoint can only be used as a second factor.** Each recovery code can be used only one time.
#[utoipa::path(
    method(post),
    path = "/",
    responses(
        (status = OK, description = "Success", body = SuccessfulLoginResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = InvalidRecoveryCode, content_type = "application/json"),
    ),
    tag = "Login"
)]
async fn login_with_recovery_code(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
    session: Session,
    Json(body): Json<RecoveryCodeLoginBody>,
) -> AxumResult<Json<SuccessfulLoginResponse>> {
    let codes = recovery_code::Entity::find()
        .filter(recovery_code::Column::UserId.eq(*user_id))
        .all(&state.db)
        .await?;

    if codes.is_empty() {
        return Err(AxumError::unauthorized(eyre::eyre!("Invalid 2FA code")));
    }

    let code_hash = verify_recovery_code(body.code, codes)?;

    let update_result = recovery_code::Entity::update_many()
        .col_expr(recovery_code::Column::Used, Expr::value(true))
        .filter(recovery_code::Column::UserId.eq(*user_id))
        .filter(recovery_code::Column::CodeHash.eq(&code_hash))
        .filter(recovery_code::Column::Used.eq(false))
        .exec(&state.db)
        .await?
        .rows_affected;

    if update_result != 1 {
        return Err(AxumError::unauthorized(eyre::eyre!(
            "Recovery code already used"
        )));
    }

    touch_auth_method(&state.db, *user_id, auth_method::Method::RecoveryCodes).await?;

    session
        .insert("auth_state", AuthState::Authenticated)
        .await?;

    Ok(Json(SuccessfulLoginResponse {
        two_factor_required: false,
        second_factors: None,
        recent_factor: None,
    }))
}
