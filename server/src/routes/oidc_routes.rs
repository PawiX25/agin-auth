use axum::{
    Extension, Json,
    extract::{Form, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use color_eyre::eyre::{self, Context as _};
use mongodb::bson::doc;
use openidconnect::{
    AccessToken, Audience, EmptyAdditionalClaims, EndUserEmail, EndUserFamilyName,
    EndUserGivenName, EndUserName, EndUserUsername, IssuerUrl, LocalizedClaim, Nonce,
    SubjectIdentifier,
    core::{CoreIdToken, CoreIdTokenClaims, CoreJwsSigningAlgorithm},
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use subtle::ConstantTimeEq;
use tower_sessions::Session;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    axum_error::{AxumError, AxumResult},
    database::{Application, ClientType, User, get_user_by_uuid},
    oidc::{AccessTokenClaims, AuthorizationCode, RefreshToken, RevokedAccessToken},
    state::AppState,
    utils::{generate_reset_token, hash_token},
};

/// Known valid OIDC scopes.
const KNOWN_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(jwks))
        .routes(routes!(authorize_get, authorize_post))
        .routes(routes!(token))
        .routes(routes!(userinfo))
        .routes(routes!(revoke))
        .routes(routes!(introspect))
}

// ── Discovery ────────────────────────────────────────────────────

// ── JWKS ─────────────────────────────────────────────────────────

/// JSON Web Key Set
#[utoipa::path(
    method(get),
    path = "/jwks",
    responses(
        (status = OK, description = "JWKS Document"),
    ),
    tag = "OIDC"
)]
async fn jwks(Extension(state): Extension<AppState>) -> impl IntoResponse {
    Json(serde_json::to_value(&state.oidc_keys.jwks).unwrap_or_default())
}

// ── Authorize (GET) ──────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct AuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorizeInfo {
    pub app_name: String,
    pub app_icon: Option<String>,
    pub scopes: Vec<String>,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
}

/// Get authorization info (requires session)
#[utoipa::path(
    method(get),
    path = "/authorize",
    params(AuthorizeQuery),
    responses(
        (status = OK, description = "Authorization info", body = AuthorizeInfo),
        (status = BAD_REQUEST, description = "Invalid request"),
    ),
    tag = "OIDC"
)]
async fn authorize_get(
    Extension(state): Extension<AppState>,
    session: Session,
    Query(params): Query<AuthorizeQuery>,
) -> AxumResult<Json<AuthorizeInfo>> {
    // Check user is authenticated
    let user_id = session
        .get::<mongodb::bson::oid::ObjectId>("user_id")
        .await?;
    let auth_state = session
        .get::<crate::routes::api::AuthState>("auth_state")
        .await?;

    if user_id.is_none()
        || !matches!(
            auth_state,
            Some(crate::routes::api::AuthState::Authenticated)
        )
    {
        return Err(AxumError::unauthorized(eyre::eyre!(
            "Login required. Redirect to login page first."
        )));
    }

    // Validate response_type
    if params.response_type != "code" {
        return Err(AxumError::bad_request(eyre::eyre!(
            "Unsupported response_type. Only 'code' is supported."
        )));
    }

    // Look up application by client_id
    let app = state
        .database
        .collection::<Application>("applications")
        .find_one(doc! { "client_id": &params.client_id })
        .await
        .wrap_err("Database error")?
        .ok_or_else(|| AxumError::bad_request(eyre::eyre!("Unknown client_id")))?;

    // Validate redirect_uri
    if !app.redirect_uris.contains(&params.redirect_uri) {
        return Err(AxumError::bad_request(eyre::eyre!(
            "Invalid redirect_uri for this application"
        )));
    }

    // Validate PKCE
    if let Some(ref method) = params.code_challenge_method
        && method != "S256"
        && method != "plain"
    {
        return Err(AxumError::bad_request(eyre::eyre!(
            "Unsupported code_challenge_method. Only 'S256' and 'plain' are supported."
        )));
    }

    if params.code_challenge.is_some() && params.code_challenge_method.is_none() {
        return Err(AxumError::bad_request(eyre::eyre!(
            "code_challenge_method is required when code_challenge is provided"
        )));
    }

    if matches!(app.client_type, ClientType::Public)
        && params
            .code_challenge
            .as_ref()
            .is_none_or(|c| c.trim().is_empty())
    {
        return Err(AxumError::bad_request(eyre::eyre!(
            "PKCE (code_challenge) is required for public clients"
        )));
    }
    let scopes: Vec<String> = params
        .scope
        .unwrap_or_default()
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let filtered_scopes: Vec<String> = scopes
        .into_iter()
        .filter(|s| KNOWN_SCOPES.contains(&s.as_str()))
        .collect();

    if !filtered_scopes.iter().any(|s| s == "openid") {
        return Err(AxumError::bad_request(eyre::eyre!(
            "The 'openid' scope is required"
        )));
    }

    Ok(Json(AuthorizeInfo {
        app_name: app.name,
        app_icon: app.icon,
        scopes: filtered_scopes,
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        state: params.state,
        nonce: params.nonce,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
    }))
}

// ── Authorize (POST) ─────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthorizeConsent {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorizeResponse {
    pub redirect_url: String,
}

/// Approve authorization (user consent)
#[utoipa::path(
    method(post),
    path = "/authorize",
    request_body = AuthorizeConsent,
    responses(
        (status = OK, description = "Authorization code issued", body = AuthorizeResponse),
        (status = BAD_REQUEST, description = "Invalid request"),
        (status = UNAUTHORIZED, description = "Not authenticated"),
    ),
    tag = "OIDC"
)]
async fn authorize_post(
    Extension(state): Extension<AppState>,
    session: Session,
    Json(body): Json<AuthorizeConsent>,
) -> AxumResult<Json<AuthorizeResponse>> {
    // Check user is authenticated
    let user_id = session
        .get::<mongodb::bson::oid::ObjectId>("user_id")
        .await?
        .ok_or_else(|| AxumError::unauthorized(eyre::eyre!("Not authenticated")))?;

    let auth_state = session
        .get::<crate::routes::api::AuthState>("auth_state")
        .await?;
    if !matches!(
        auth_state,
        Some(crate::routes::api::AuthState::Authenticated)
    ) {
        return Err(AxumError::unauthorized(eyre::eyre!("Not authenticated")));
    }

    // Validate application
    let app = state
        .database
        .collection::<Application>("applications")
        .find_one(doc! { "client_id": &body.client_id })
        .await
        .wrap_err("Database error")?
        .ok_or_else(|| AxumError::bad_request(eyre::eyre!("Unknown client_id")))?;

    if !app.redirect_uris.contains(&body.redirect_uri) {
        return Err(AxumError::bad_request(eyre::eyre!("Invalid redirect_uri")));
    }

    let filtered_scope: String = body
        .scope
        .split_whitespace()
        .filter(|s| KNOWN_SCOPES.contains(s))
        .collect::<Vec<_>>()
        .join(" ");

    if !filtered_scope.split_whitespace().any(|s| s == "openid") {
        return Err(AxumError::bad_request(eyre::eyre!(
            "The 'openid' scope is required"
        )));
    }

    if let Some(ref method) = body.code_challenge_method
        && method != "S256"
        && method != "plain"
    {
        return Err(AxumError::bad_request(eyre::eyre!(
            "Unsupported code_challenge_method"
        )));
    }
    if body.code_challenge.is_some() && body.code_challenge_method.is_none() {
        return Err(AxumError::bad_request(eyre::eyre!(
            "code_challenge_method is required when code_challenge is provided"
        )));
    }

    if matches!(app.client_type, ClientType::Public)
        && body
            .code_challenge
            .as_ref()
            .is_none_or(|c| c.trim().is_empty())
    {
        return Err(AxumError::bad_request(eyre::eyre!(
            "PKCE (code_challenge) is required for public clients"
        )));
    }

    // Check user group access
    let user = state
        .database
        .collection::<User>("users")
        .find_one(doc! { "_id": &user_id })
        .await
        .wrap_err("Database error")?
        .ok_or_else(|| AxumError::bad_request(eyre::eyre!("User not found")))?;

    if !app.allowed_groups.is_empty() {
        let has_access = user.groups.iter().any(|g| app.allowed_groups.contains(g));
        if !has_access {
            return Err(AxumError::forbidden(eyre::eyre!(
                "You don't have access to this application"
            )));
        }
    }

    // Generate authorization code
    let code = generate_reset_token(); // 64 char random string
    let code_hash = hash_token(&code);

    let auth_code = AuthorizationCode {
        code_hash,
        client_id: body.client_id.clone(),
        user_id: user_id.to_hex(),
        redirect_uri: body.redirect_uri.clone(),
        scope: filtered_scope,
        nonce: body.nonce.clone(),
        code_challenge: body.code_challenge.clone(),
        code_challenge_method: body.code_challenge_method.clone(),
        created_at: Utc::now(),
        used: false,
    };

    state
        .database
        .collection::<AuthorizationCode>("authorization_codes")
        .insert_one(auth_code)
        .await
        .wrap_err("Failed to store authorization code")?;

    // Build redirect URL with code and state
    let mut redirect_url = body.redirect_uri.clone();
    redirect_url.push_str(if redirect_url.contains('?') { "&" } else { "?" });
    redirect_url.push_str(&format!("code={}", urlencoding::encode(&code)));
    if let Some(ref st) = body.state {
        redirect_url.push_str(&format!("&state={}", urlencoding::encode(st)));
    }

    Ok(Json(AuthorizeResponse { redirect_url }))
}

// ── Token ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    pub scope: String,
}

#[derive(Debug, Serialize)]
pub struct TokenError {
    pub error: String,
    pub error_description: String,
}

/// OAuth2 Token endpoint
#[utoipa::path(
    method(post),
    path = "/token",
    responses(
        (status = OK, description = "Token response", body = TokenResponse),
        (status = BAD_REQUEST, description = "Token error"),
    ),
    tag = "OIDC"
)]
async fn token(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Form(body): Form<TokenRequest>,
) -> Result<axum::response::Response, axum::response::Response> {
    // Extract client credentials from Basic auth header or body
    let (client_id, client_secret) =
        extract_client_credentials(&headers, &body.client_id, &body.client_secret);

    let result = match body.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(&state, &body, &client_id, &client_secret).await
        }
        "refresh_token" => {
            handle_refresh_token_grant(&state, &body, &client_id, &client_secret).await
        }
        _ => Err(token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Only authorization_code and refresh_token are supported",
        )),
    }?;

    // RFC 6749 §5.1: token responses MUST include Cache-Control: no-store
    Ok(axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Cache-Control", "no-store")
        .header("Pragma", "no-cache")
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&result.0).unwrap_or_default(),
        ))
        .expect("valid response"))
}

fn extract_client_credentials(
    headers: &HeaderMap,
    body_client_id: &Option<String>,
    body_client_secret: &Option<String>,
) -> (Option<String>, Option<String>) {
    // Try Basic auth first
    if let Some(auth) = headers.get("authorization")
        && let Ok(auth_str) = auth.to_str()
        && let Some(basic) = auth_str.strip_prefix("Basic ")
        && let Ok(decoded) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, basic.trim())
        && let Ok(creds) = String::from_utf8(decoded)
        && let Some((id, secret)) = creds.split_once(':')
    {
        return (Some(id.to_string()), Some(secret.to_string()));
    }

    // Fall back to body parameters
    (body_client_id.clone(), body_client_secret.clone())
}

/// Look up an OAuth2 client by `client_id` and verify `client_secret` for confidential clients.
async fn authenticate_client(
    state: &AppState,
    client_id: &str,
    client_secret: &Option<String>,
    unknown_client_status: StatusCode,
) -> Result<Application, axum::response::Response> {
    let app = state
        .database
        .collection::<Application>("applications")
        .find_one(doc! { "client_id": client_id })
        .await
        .map_err(|_| {
            token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Database error",
            )
        })?
        .ok_or_else(|| token_error(unknown_client_status, "invalid_client", "Unknown client"))?;

    if matches!(app.client_type, ClientType::Confidential) {
        let expected_hash = app.client_secret.as_ref().ok_or_else(|| {
            token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Confidential client has no secret",
            )
        })?;
        let provided = client_secret.as_ref().ok_or_else(|| {
            token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Client secret required",
            )
        })?;
        let provided_hash = hash_token(provided);
        if provided_hash
            .as_bytes()
            .ct_eq(expected_hash.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Invalid client secret",
            ));
        }
    }

    Ok(app)
}

async fn handle_authorization_code_grant(
    state: &AppState,
    body: &TokenRequest,
    client_id: &Option<String>,
    client_secret: &Option<String>,
) -> Result<Json<TokenResponse>, axum::response::Response> {
    let code = body
        .code
        .as_ref()
        .ok_or_else(|| token_error(StatusCode::BAD_REQUEST, "invalid_request", "Missing code"))?;

    let redirect_uri = body.redirect_uri.as_ref().ok_or_else(|| {
        token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing redirect_uri",
        )
    })?;

    let client_id = client_id.as_ref().ok_or_else(|| {
        token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing client_id",
        )
    })?;

    // Atomically find and mark code as used
    let code_hash = hash_token(code);
    let auth_code = state
        .database
        .collection::<AuthorizationCode>("authorization_codes")
        .find_one_and_update(
            doc! { "code_hash": &code_hash, "used": false },
            doc! { "$set": { "used": true } },
        )
        .await
        .map_err(|_| {
            token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Database error",
            )
        })?
        .ok_or_else(|| {
            token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Invalid or expired authorization code",
            )
        })?;

    // Validate code hasn't expired (10 minute lifetime)
    let age = Utc::now() - auth_code.created_at;
    if age.num_minutes() > 10 {
        return Err(token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code expired",
        ));
    }

    // Validate client_id and redirect_uri match
    if auth_code.client_id != *client_id {
        return Err(token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id mismatch",
        ));
    }
    if auth_code.redirect_uri != *redirect_uri {
        return Err(token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri mismatch",
        ));
    }

    // Verify PKCE code_verifier
    if let Some(ref challenge) = auth_code.code_challenge {
        let verifier = body.code_verifier.as_ref().ok_or_else(|| {
            token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code_verifier is required when code_challenge was used",
            )
        })?;

        let method = auth_code
            .code_challenge_method
            .as_deref()
            .unwrap_or("plain");

        let expected = match method {
            "S256" => {
                use base64::Engine as _;
                let digest = sha2::Sha256::digest(verifier.as_bytes());
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
            }
            "plain" => verifier.clone(),
            _ => {
                return Err(token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Unsupported code_challenge_method",
                ));
            }
        };

        if expected.as_bytes().ct_eq(challenge.as_bytes()).unwrap_u8() != 1 {
            return Err(token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "PKCE verification failed",
            ));
        }
    }

    // Validate client_secret for confidential clients
    authenticate_client(state, client_id, client_secret, StatusCode::BAD_REQUEST).await?;

    // Get user for claims
    let user_oid = mongodb::bson::oid::ObjectId::parse_str(&auth_code.user_id).map_err(|_| {
        token_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Invalid user_id",
        )
    })?;

    let user = state
        .database
        .collection::<User>("users")
        .find_one(doc! { "_id": &user_oid })
        .await
        .map_err(|_| {
            token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Database error",
            )
        })?
        .ok_or_else(|| token_error(StatusCode::BAD_REQUEST, "invalid_grant", "User not found"))?;

    let issuer = state
        .settings
        .general
        .public_url
        .to_string()
        .trim_end_matches('/')
        .to_string();

    let now = Utc::now().timestamp() as usize;
    let scopes: Vec<&str> = auth_code.scope.split_whitespace().collect();

    // Build access token (1 hour)
    let access_claims = AccessTokenClaims {
        iss: issuer.clone(),
        sub: user.uuid.to_string(),
        aud: client_id.clone(),
        exp: now + 3600,
        iat: now,
        scope: auth_code.scope.clone(),
        client_id: client_id.clone(),
    };
    let access_token = state
        .oidc_keys
        .sign_access_token(&access_claims)
        .map_err(|_| {
            token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to sign access token",
            )
        })?;

    // Build ID token if openid scope requested
    let id_token = if scopes.contains(&"openid") {
        let issuer_url = IssuerUrl::new(issuer.clone()).map_err(|_| {
            token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Invalid issuer URL",
            )
        })?;

        let mut standard_claims =
            openidconnect::StandardClaims::new(SubjectIdentifier::new(user.uuid.to_string()));

        if scopes.contains(&"profile") {
            standard_claims = standard_claims
                .set_name(Some(LocalizedClaim::from(EndUserName::new(
                    user.display_name.clone(),
                ))))
                .set_preferred_username(Some(EndUserUsername::new(user.preferred_username.clone())))
                .set_given_name(Some(LocalizedClaim::from(EndUserGivenName::new(
                    user.first_name.clone(),
                ))))
                .set_family_name(Some(LocalizedClaim::from(EndUserFamilyName::new(
                    user.last_name.clone(),
                ))));
        }
        if scopes.contains(&"email") {
            standard_claims = standard_claims
                .set_email(Some(EndUserEmail::new(user.email.clone())))
                .set_email_verified(Some(user.email_confirmed));
        }

        let id_claims = CoreIdTokenClaims::new(
            issuer_url,
            vec![Audience::new(client_id.clone())],
            Utc::now() + chrono::Duration::hours(1),
            Utc::now(),
            standard_claims,
            EmptyAdditionalClaims {},
        )
        .set_nonce(auth_code.nonce.as_ref().map(|n| Nonce::new(n.clone())));

        let access_token_obj = AccessToken::new(access_token.clone());

        let signed_id_token = CoreIdToken::new(
            id_claims,
            &state.oidc_keys.signing_key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            Some(&access_token_obj),
            None,
        )
        .map_err(|_| {
            token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to sign ID token",
            )
        })?;

        Some(signed_id_token.to_string())
    } else {
        None
    };

    // Generate refresh token if offline_access scope requested
    let refresh_token = if scopes.contains(&"offline_access") {
        let raw_token = generate_reset_token();
        let token_hash = hash_token(&raw_token);

        let rt = RefreshToken {
            token_hash,
            client_id: client_id.clone(),
            user_id: auth_code.user_id.clone(),
            scope: auth_code.scope.clone(),
            created_at: Utc::now(),
            revoked: false,
        };

        state
            .database
            .collection::<RefreshToken>("refresh_tokens")
            .insert_one(rt)
            .await
            .map_err(|_| {
                token_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Failed to store refresh token",
                )
            })?;

        Some(raw_token)
    } else {
        None
    };

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token,
        id_token,
        scope: auth_code.scope,
    }))
}

async fn handle_refresh_token_grant(
    state: &AppState,
    body: &TokenRequest,
    client_id: &Option<String>,
    client_secret: &Option<String>,
) -> Result<Json<TokenResponse>, axum::response::Response> {
    let raw_token = body.refresh_token.as_ref().ok_or_else(|| {
        token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing refresh_token",
        )
    })?;

    let token_hash = hash_token(raw_token);
    let stored = state
        .database
        .collection::<RefreshToken>("refresh_tokens")
        .find_one_and_update(
            doc! { "token_hash": &token_hash, "revoked": false },
            doc! { "$set": { "revoked": true } },
        )
        .await
        .map_err(|_| {
            token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Database error",
            )
        })?
        .ok_or_else(|| {
            token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Invalid or revoked refresh token",
            )
        })?;

    // Validate refresh token age (30 days max)
    let age = Utc::now() - stored.created_at;
    if age.num_days() > 30 {
        return Err(token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Refresh token expired",
        ));
    }

    // Validate client
    let req_client_id = client_id.as_ref().ok_or_else(|| {
        token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing client_id",
        )
    })?;

    if stored.client_id != *req_client_id {
        return Err(token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id mismatch",
        ));
    }

    // Validate client_secret for confidential clients
    authenticate_client(state, req_client_id, client_secret, StatusCode::BAD_REQUEST).await?;

    // Get user
    let user_oid = mongodb::bson::oid::ObjectId::parse_str(&stored.user_id).map_err(|_| {
        token_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Invalid user_id",
        )
    })?;

    let user = state
        .database
        .collection::<User>("users")
        .find_one(doc! { "_id": &user_oid })
        .await
        .map_err(|_| {
            token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Database error",
            )
        })?
        .ok_or_else(|| token_error(StatusCode::BAD_REQUEST, "invalid_grant", "User not found"))?;

    let issuer = state
        .settings
        .general
        .public_url
        .to_string()
        .trim_end_matches('/')
        .to_string();
    let now = Utc::now().timestamp() as usize;

    let access_claims = AccessTokenClaims {
        iss: issuer,
        sub: user.uuid.to_string(),
        aud: req_client_id.clone(),
        exp: now + 3600,
        iat: now,
        scope: stored.scope.clone(),
        client_id: req_client_id.clone(),
    };

    let access_token = state
        .oidc_keys
        .sign_access_token(&access_claims)
        .map_err(|_| {
            token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to sign access token",
            )
        })?;

    // Issue new refresh token (rotation)
    let raw_new_token = generate_reset_token();
    let new_token_hash = hash_token(&raw_new_token);
    let new_refresh_token = RefreshToken {
        token_hash: new_token_hash,
        user_id: stored.user_id,
        client_id: req_client_id.clone(),
        scope: stored.scope.clone(),
        created_at: Utc::now(),
        revoked: false,
    };
    let _ = state
        .database
        .collection::<RefreshToken>("refresh_tokens")
        .insert_one(new_refresh_token)
        .await;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some(raw_new_token),
        id_token: None,
        scope: stored.scope,
    }))
}

// ── UserInfo ─────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// OpenID Connect UserInfo endpoint
#[utoipa::path(
    method(get),
    path = "/userinfo",
    responses(
        (status = OK, description = "User info", body = UserInfoResponse),
        (status = UNAUTHORIZED, description = "Invalid or missing access token"),
    ),
    tag = "OIDC"
)]
async fn userinfo(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
) -> Result<Json<UserInfoResponse>, axum::response::Response> {
    // Extract Bearer token
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Missing or invalid Bearer token",
            )
        })?;

    // Verify access token
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[""]); // We'll skip audience validation for userinfo
    validation.validate_aud = false;

    let token_data = jsonwebtoken::decode::<AccessTokenClaims>(
        auth_header,
        &state.oidc_keys.decoding_key,
        &validation,
    )
    .map_err(|e| {
        token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            &format!("Token verification failed: {e}"),
        )
    })?;

    let claims = token_data.claims;

    // Get user by UUID
    let user_uuid = uuid::Uuid::parse_str(&claims.sub).map_err(|_| {
        token_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Invalid sub claim",
        )
    })?;

    let user = get_user_by_uuid(&state.database, &user_uuid)
        .await
        .map_err(|_| {
            token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Database error",
            )
        })?
        .ok_or_else(|| token_error(StatusCode::UNAUTHORIZED, "invalid_token", "User not found"))?;

    let scopes: Vec<&str> = claims.scope.split_whitespace().collect();

    let mut response = UserInfoResponse {
        sub: user.uuid.to_string(),
        name: None,
        preferred_username: None,
        given_name: None,
        family_name: None,
        email: None,
        email_verified: None,
    };

    if scopes.contains(&"profile") {
        response.name = Some(user.display_name);
        response.preferred_username = Some(user.preferred_username);
        response.given_name = Some(user.first_name);
        response.family_name = Some(user.last_name);
    }

    if scopes.contains(&"email") {
        response.email = Some(user.email);
        response.email_verified = Some(user.email_confirmed);
    }

    Ok(Json(response))
}

// ── Revoke (RFC 7009) ────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeRequest {
    pub token: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// Revoke a token (RFC 7009)
#[utoipa::path(
    method(post),
    path = "/revoke",
    request_body(content = RevokeRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = OK, description = "Token revoked (or was already invalid)"),
        (status = UNAUTHORIZED, description = "Invalid client credentials"),
    ),
    tag = "OIDC"
)]
async fn revoke(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Form(body): Form<RevokeRequest>,
) -> Result<StatusCode, axum::response::Response> {
    let (client_id, client_secret) =
        extract_client_credentials(&headers, &body.client_id, &body.client_secret);

    // Require client authentication for revocation
    let cid = client_id.as_ref().ok_or_else(|| {
        token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Client authentication required",
        )
    })?;

    authenticate_client(&state, cid, &client_secret, StatusCode::UNAUTHORIZED).await?;

    let token_hash = hash_token(&body.token);

    // Try revoking as refresh token (only if it belongs to the authenticated client)
    let revoked = state
        .database
        .collection::<RefreshToken>("refresh_tokens")
        .update_one(
            doc! { "token_hash": &token_hash, "client_id": cid, "revoked": false },
            doc! { "$set": { "revoked": true } },
        )
        .await
        .map_err(|_| {
            token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Database error",
            )
        })?;

    if revoked.modified_count > 0 {
        return Ok(StatusCode::OK);
    }

    // Try revoking as JWT access token — add to blocklist so introspect returns inactive
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_aud = false;
    if let Ok(token_data) = jsonwebtoken::decode::<AccessTokenClaims>(
        &body.token,
        &state.oidc_keys.decoding_key,
        &validation,
    ) && token_data.claims.client_id == *cid
    {
        let entry = RevokedAccessToken {
            token_hash: token_hash.clone(),
            client_id: cid.clone(),
            created_at: Utc::now(),
        };
        let _ = state
            .database
            .collection::<RevokedAccessToken>("revoked_access_tokens")
            .insert_one(entry)
            .await;
    }

    // Per RFC 7009: always return 200 even if token is unknown (no information leak)
    Ok(StatusCode::OK)
}

// ── Introspect (RFC 7662) ────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct IntrospectRequest {
    pub token: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
}

/// Introspect a token (RFC 7662)
#[utoipa::path(
    method(post),
    path = "/introspect",
    request_body(content = IntrospectRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = OK, description = "Token introspection result", body = IntrospectResponse),
        (status = UNAUTHORIZED, description = "Invalid client credentials"),
    ),
    tag = "OIDC"
)]
async fn introspect(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Form(body): Form<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, axum::response::Response> {
    let (client_id, client_secret) =
        extract_client_credentials(&headers, &body.client_id, &body.client_secret);

    // Authenticate the client (required for introspection)
    let cid = client_id.as_ref().ok_or_else(|| {
        token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Client authentication required",
        )
    })?;

    authenticate_client(&state, cid, &client_secret, StatusCode::UNAUTHORIZED).await?;

    let inactive = IntrospectResponse {
        active: false,
        scope: None,
        client_id: None,
        username: None,
        token_type: None,
        exp: None,
        iat: None,
        sub: None,
        iss: None,
    };

    // Try as JWT access token first
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_aud = false;

    if let Ok(token_data) = jsonwebtoken::decode::<AccessTokenClaims>(
        &body.token,
        &state.oidc_keys.decoding_key,
        &validation,
    ) {
        let claims = token_data.claims;

        // Check if this access token has been revoked
        let at_hash = hash_token(&body.token);
        let is_revoked = state
            .database
            .collection::<RevokedAccessToken>("revoked_access_tokens")
            .find_one(doc! { "token_hash": &at_hash })
            .await
            .ok()
            .flatten()
            .is_some();

        if is_revoked {
            return Ok(Json(inactive));
        }

        // Look up the user for username
        let username = if let Ok(user_uuid) = uuid::Uuid::parse_str(&claims.sub) {
            get_user_by_uuid(&state.database, &user_uuid)
                .await
                .ok()
                .flatten()
                .map(|u| u.preferred_username)
        } else {
            None
        };

        return Ok(Json(IntrospectResponse {
            active: true,
            scope: Some(claims.scope),
            client_id: Some(claims.client_id),
            username,
            token_type: Some("Bearer".to_string()),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            sub: Some(claims.sub),
            iss: Some(claims.iss),
        }));
    }

    // Try as refresh token
    let token_hash = hash_token(&body.token);
    if let Ok(Some(stored)) = state
        .database
        .collection::<RefreshToken>("refresh_tokens")
        .find_one(doc! { "token_hash": &token_hash, "revoked": false })
        .await
    {
        let age = Utc::now() - stored.created_at;
        if age.num_days() <= 30 {
            return Ok(Json(IntrospectResponse {
                active: true,
                scope: Some(stored.scope),
                client_id: Some(stored.client_id),
                username: None,
                token_type: Some("refresh_token".to_string()),
                exp: None,
                iat: Some(stored.created_at.timestamp() as usize),
                sub: None,
                iss: None,
            }));
        }
    }

    Ok(Json(inactive))
}

// ── Helpers ──────────────────────────────────────────────────────

fn token_error(status: StatusCode, error: &str, description: &str) -> axum::response::Response {
    let body = TokenError {
        error: error.to_string(),
        error_description: description.to_string(),
    };
    (status, Json(body)).into_response()
}
