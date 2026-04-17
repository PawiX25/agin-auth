use axum::{Extension, Json};
use axum_client_ip::ClientIp;
use axum_valid::Valid;
use color_eyre::eyre;
use entity::{auth_method, password, user};
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    auth_method_helpers::touch_auth_method,
    axum_error::{AxumError, AxumResult},
    routes::api::AuthState,
    state::AppState,
    utils::{hash_password, verify_password},
};

use super::SuccessfulLoginResponse;

pub(crate) fn second_factor_slug(method: auth_method::Method) -> Option<&'static str> {
    match method {
        auth_method::Method::Totp => Some("totp"),
        auth_method::Method::RecoveryCodes => Some("recoverycode"),
        auth_method::Method::WebAuthn => Some("webauthn"),
        auth_method::Method::Password | auth_method::Method::Pgp => None,
    }
}

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
    // Find user by username or email
    let user = user::Entity::find()
        .filter(
            Condition::any()
                .add(user::Column::PreferredUsername.eq(&body.username))
                .add(user::Column::Email.eq(&body.username)),
        )
        .one(&state.db)
        .await?;

    let Some(user) = user else {
        let _ = hash_password(&body.password);
        return Err(AxumError::unauthorized(eyre::eyre!(
            "Invalid username or password"
        )));
    };

    // Look up password credential
    let password_cred = password::Entity::find_by_id(user.id).one(&state.db).await?;

    let Some(password_cred) = password_cred else {
        let _ = hash_password(&body.password);
        return Err(AxumError::unauthorized(eyre::eyre!(
            "Invalid username or password"
        )));
    };

    verify_password(&body.password, &password_cred.password_hash)
        .map_err(|_| AxumError::unauthorized(eyre::eyre!("Invalid username or password")))?;

    session.insert("user_id", user.id).await?;

    // Check for second factors
    let second_factor_methods = auth_method::Entity::find()
        .filter(auth_method::Column::UserId.eq(user.id))
        .filter(auth_method::Column::IsEnabled.eq(true))
        .filter(auth_method::Column::MethodType.is_in([
            auth_method::Method::Totp,
            auth_method::Method::RecoveryCodes,
            auth_method::Method::WebAuthn,
        ]))
        .all(&state.db)
        .await?;

    if second_factor_methods.is_empty() {
        touch_auth_method(&state.db, user.id, auth_method::Method::Password).await?;

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

    session
        .insert("auth_state", AuthState::BeforeTwoFactor)
        .await?;

    let factor_names: Vec<String> = second_factor_methods
        .iter()
        .filter_map(|m| second_factor_slug(m.method_type))
        .map(str::to_owned)
        .collect();

    // Find most recently used second factor
    let recent_factor = second_factor_methods
        .iter()
        .filter_map(|m| m.last_used_at.map(|t| (m, t)))
        .max_by_key(|(_, t)| *t)
        .and_then(|(m, _)| second_factor_slug(m.method_type))
        .map(str::to_owned);

    Ok(Json(SuccessfulLoginResponse {
        two_factor_required: true,
        second_factors: Some(factor_names),
        recent_factor,
    }))
}
