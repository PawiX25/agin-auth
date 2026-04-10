use axum::{Extension, Json};
use axum_client_ip::ClientIp;
use axum_valid::Valid;
use color_eyre::eyre;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    axum_error::{AxumError, AxumResult},
    database::{FirstFactor, get_second_factors, get_user, set_recent_factor},
    routes::api::AuthState,
    state::AppState,
    utils::{hash_password, verify_password},
};

use super::SuccessfulLoginResponse;

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(login_with_password))
}

#[derive(Deserialize, ToSchema, Validate)]
struct LoginBody {
    /// Username or email address
    username: String,
    #[validate(length(max = 256))]
    password: String,
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({"error": "Invalid username or password"}))]
pub struct InvalidUserOrPass {
    error: String,
}

/// Log in with password
///
/// If user is not found or the password isn't enabled for the user returns the same response as if the password was incorrect.
#[utoipa::path(
    method(post),
    path = "/",
    responses(
        (status = OK, description = "Success", body = SuccessfulLoginResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = InvalidUserOrPass, content_type = "application/json"),
    ),
    tag = "Login"
)]
async fn login_with_password(
    Extension(state): Extension<AppState>,
    session: Session,
    ClientIp(client_ip): ClientIp,
    Valid(Json(body)): Valid<Json<LoginBody>>,
) -> AxumResult<Json<SuccessfulLoginResponse>> {
    let user = get_user(&state.database, &body.username).await?;

    // Hashing the password in order to prevent timing attacks
    if user.is_none()
        || user
            .clone()
            .unwrap()
            .auth_factors
            .password
            .password_hash
            .is_none()
    {
        let _ = hash_password(&body.password);

        return Err(AxumError::unauthorized(eyre::eyre!(
            "Invalid username or password"
        )));
    }

    let user = user.unwrap();

    let password_hash = &user.clone().auth_factors.password.password_hash.unwrap();

    verify_password(&body.password, password_hash)
        .map_err(|_| AxumError::unauthorized(eyre::eyre!("Invalid username or password")))?;

    session.insert("user_id", user.id).await?;

    let second_factors = get_second_factors(&user);

    if second_factors.is_empty() {
        session
            .insert("auth_state", AuthState::Authenticated)
            .await?;

        if let Some(mail) = &state.mail_service {
            let ip = client_ip.to_string();
            let email = user.email.clone();
            let mail = mail.clone();
            tokio::spawn(async move {
                if let Err(e) = mail.send_login_notification(&email, &ip).await {
                    tracing::warn!(error = ?e, "Failed to send login notification");
                }
            });
        }

        return Ok(Json(SuccessfulLoginResponse {
            two_factor_required: false,
            second_factors: None,
            recent_factor: None,
        }));
    }

    set_recent_factor(&state.database, &user.id, FirstFactor::Password.into()).await?;

    session
        .insert("auth_state", AuthState::BeforeTwoFactor)
        .await?;

    Ok(Json(SuccessfulLoginResponse {
        two_factor_required: true,
        second_factors: Some(second_factors),
        recent_factor: user.auth_factors.recent.second_factor,
    }))
}
