use axum::{Extension, Json};
use color_eyre::eyre;
use entity::{auth_method, totp};
use sea_orm::EntityTrait;
use tower_sessions::Session;

use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    auth_method_helpers::touch_auth_method,
    axum_error::{AxumError, AxumResult},
    middlewares::require_auth::UserId,
    routes::api::{
        AuthState,
        login::SuccessfulLoginResponse,
        settings::factors::totp::{Invalid2faCode, TotpCodeBody, verify_totp},
    },
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(login_with_totp))
}

/// Log in with TOTP
///
/// **This endpoint can only be used as a second factor.** TOTP is not considered secure enough to be used as a primary authentication method.
#[utoipa::path(
    method(post),
    path = "/",
    request_body = TotpCodeBody,
    responses(
        (status = OK, description = "Success", body = SuccessfulLoginResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = Invalid2faCode, content_type = "application/json"),
    ),
    tag = "Login"
)]
async fn login_with_totp(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
    session: Session,
    Json(body): Json<TotpCodeBody>,
) -> AxumResult<Json<SuccessfulLoginResponse>> {
    let totp_record = totp::Entity::find_by_id(*user_id).one(&state.db).await?;

    let Some(totp_record) = totp_record.filter(|t| t.fully_enabled) else {
        return Err(AxumError::unauthorized(eyre::eyre!("Invalid 2FA code")));
    };

    verify_totp(&totp_record.secret, &body.code)?;

    touch_auth_method(&state.db, *user_id, auth_method::Method::Totp).await?;

    session
        .insert("auth_state", AuthState::Authenticated)
        .await?;

    Ok(Json(SuccessfulLoginResponse {
        two_factor_required: false,
        second_factors: None,
        recent_factor: None,
    }))
}
