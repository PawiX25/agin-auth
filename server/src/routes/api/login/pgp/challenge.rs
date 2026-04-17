use axum::{Extension, Json};
use axum_valid::Valid;
use chrono::{DateTime, Utc};
use color_eyre::eyre;
use entity::{auth_method, pgp as pgp_entity, user};
use pgp_lib::composed::{Any, Deserializable, SignedPublicKey};
use rand::{RngExt, distr::Alphanumeric};
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
};

use super::super::SuccessfulLoginResponse;
use super::super::password::second_factor_slug;

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_pgp_challenge, respond_to_pgp_challenge))
}

#[derive(Serialize, ToSchema)]
pub struct PgpChallengeResponse {
    challenge: String,
}

#[derive(Serialize, Deserialize)]
pub struct PgpChallengeConfig {
    expires_at: DateTime<Utc>,
    challenge: String,
}

/// Get PGP challenge
///
/// Returns a challenge that needs to be signed with the user's PGP key.
#[utoipa::path(
    method(get),
    path = "/",
    responses(
        (status = OK, description = "Success", body = PgpChallengeResponse, content_type = "application/json"),
    ),
    tag = "Login"
)]
async fn get_pgp_challenge(session: Session) -> AxumResult<Json<PgpChallengeResponse>> {
    let challenge = generate_pgp_challenge();
    let expires_at = Utc::now() + chrono::Duration::minutes(5);

    let challenge_config = PgpChallengeConfig {
        expires_at,
        challenge: challenge.clone(),
    };

    session
        .insert("login::pgp_challenge", challenge_config)
        .await?;

    Ok(Json(PgpChallengeResponse { challenge }))
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({ "error": "Invalid signature" }))]
struct InvalidSignature {
    error: String,
}

#[derive(Deserialize, ToSchema, Validate)]
struct PgpChallengeBody {
    /// Username or email address
    username: String,

    /// Signature of the challenge obtained from `GET /api/login/pgp/challenge`
    #[validate(length(min = 1))]
    signature: String,
}

fn invalid_signature() -> AxumError {
    AxumError::unauthorized(eyre::eyre!("Invalid signature"))
}

/// Respond to PGP challenge
///
/// Sign the challenge obtained from `GET /api/login/pgp/challenge` with the user's PGP key and send the signature here to complete the login process.
#[utoipa::path(
    method(post),
    path = "/",
    request_body = PgpChallengeBody,
    responses(
        (status = OK, description = "Success", body = SuccessfulLoginResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = InvalidSignature, content_type = "application/json"),
    ),
    tag = "Login"
)]
async fn respond_to_pgp_challenge(
    Extension(state): Extension<AppState>,
    session: Session,
    Valid(Json(body)): Valid<Json<PgpChallengeBody>>,
) -> AxumResult<Json<SuccessfulLoginResponse>> {
    let challenge_config = session
        .get::<PgpChallengeConfig>("login::pgp_challenge")
        .await?
        .ok_or_else(|| {
            AxumError::bad_request(eyre::eyre!(
                "No challenge found. Please request a new challenge."
            ))
        })?;

    if challenge_config.expires_at < Utc::now() {
        return Err(AxumError::bad_request(eyre::eyre!(
            "Challenge expired. Please request a new challenge."
        )));
    }

    let (parsed, _) = Any::from_string(&body.signature).map_err(|_| invalid_signature())?;

    let Any::Cleartext(msg) = parsed else {
        return Err(invalid_signature());
    };

    let signed_text = msg.signed_text();
    if signed_text.trim() != challenge_config.challenge {
        return Err(invalid_signature());
    }

    // Find user by username or email
    let found_user = user::Entity::find()
        .filter(
            Condition::any()
                .add(user::Column::PreferredUsername.eq(&body.username))
                .add(user::Column::Email.eq(&body.username)),
        )
        .one(&state.db)
        .await?;

    let Some(found_user) = found_user else {
        return Err(invalid_signature());
    };

    // Get user's PGP keys
    let pgp_keys = pgp_entity::Entity::find()
        .filter(pgp_entity::Column::UserId.eq(found_user.id))
        .all(&state.db)
        .await?;

    if pgp_keys.is_empty() {
        return Err(invalid_signature());
    }

    // Try verifying against all registered PGP keys
    let mut verified = false;
    for pgp_key in &pgp_keys {
        if let Ok((public_key, _)) = SignedPublicKey::from_string(&pgp_key.public_key)
            && msg.verify(&public_key).is_ok()
        {
            verified = true;
            break;
        }
    }

    if !verified {
        return Err(invalid_signature());
    }

    session
        .remove::<PgpChallengeConfig>("login::pgp_challenge")
        .await?;

    session.insert("user_id", found_user.id).await?;

    // Check for second factors
    let second_factor_methods = auth_method::Entity::find()
        .filter(auth_method::Column::UserId.eq(found_user.id))
        .filter(auth_method::Column::IsEnabled.eq(true))
        .filter(
            auth_method::Column::MethodType
                .is_not_in([auth_method::Method::Password, auth_method::Method::Pgp]),
        )
        .all(&state.db)
        .await?;

    if second_factor_methods.is_empty() {
        touch_auth_method(&state.db, found_user.id, auth_method::Method::Pgp).await?;

        session
            .insert("auth_state", AuthState::Authenticated)
            .await?;

        return Ok(Json(SuccessfulLoginResponse {
            two_factor_required: false,
            second_factors: None,
            recent_factor: None,
        }));
    }

    touch_auth_method(&state.db, found_user.id, auth_method::Method::Pgp).await?;

    session
        .insert("auth_state", AuthState::BeforeTwoFactor)
        .await?;

    let factor_names: Vec<String> = second_factor_methods
        .iter()
        .filter_map(|m| second_factor_slug(m.method_type))
        .map(String::from)
        .collect();

    let recent_factor = second_factor_methods
        .iter()
        .filter_map(|m| m.last_used_at.map(|t| (m, t)))
        .max_by_key(|(_, t)| *t)
        .and_then(|(m, _)| second_factor_slug(m.method_type))
        .map(String::from);

    Ok(Json(SuccessfulLoginResponse {
        two_factor_required: true,
        second_factors: Some(factor_names),
        recent_factor,
    }))
}

fn generate_pgp_challenge() -> String {
    let rng = rand::rngs::ThreadRng::default();

    rng.sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}
