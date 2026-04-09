use axum::{Extension, Json};
use axum_valid::Valid;
use chrono::{DateTime, Utc};
use color_eyre::eyre::{self};
use pgp::composed::{Any, Deserializable, SignedPublicKey};
use rand::{RngExt, distr::Alphanumeric};
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
};

use super::super::SuccessfulLoginResponse;

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

    let user = get_user(&state.database, &body.username).await?;

    let user = match user {
        Some(user) if !user.auth_factors.pgp.is_empty() => user,
        _ => return Err(invalid_signature()),
    };

    // Try verifying against all registered PGP keys
    let mut verified = false;
    for pgp_factor in &user.auth_factors.pgp {
        if let Ok((public_key, _)) = SignedPublicKey::from_string(&pgp_factor.public_key)
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

    session.insert("user_id", user.id).await?;

    let second_factors = get_second_factors(&user);

    if second_factors.is_empty() {
        session
            .insert("auth_state", AuthState::Authenticated)
            .await?;

        return Ok(Json(SuccessfulLoginResponse {
            two_factor_required: false,
            second_factors: None,
            recent_factor: None,
        }));
    }

    set_recent_factor(&state.database, &user.id, FirstFactor::Pgp.into()).await?;

    session
        .insert("auth_state", AuthState::BeforeTwoFactor)
        .await?;

    Ok(Json(SuccessfulLoginResponse {
        two_factor_required: true,
        second_factors: Some(second_factors),
        recent_factor: user.auth_factors.recent.second_factor,
    }))
}

fn generate_pgp_challenge() -> String {
    let rng = rand::rngs::ThreadRng::default();

    rng.sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}
