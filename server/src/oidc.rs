use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use color_eyre::eyre::{Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use openidconnect::{
    AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl,
    PrivateSigningKey, ResponseTypes, Scope, TokenUrl, UserInfoUrl,
    core::{
        CoreClaimName, CoreJsonWebKey, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
        CoreProviderMetadata, CoreResponseType, CoreRsaPrivateSigningKey,
        CoreSubjectIdentifierType,
    },
};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::LineEnding;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

/// RSA key size for OIDC signing
const RSA_KEY_BITS: usize = 2048;

/// OIDC signing key data stored in AppState
pub struct OidcKeys {
    /// RSA private signing key (from `openidconnect` crate) — used for ID token signing.
    pub signing_key: CoreRsaPrivateSigningKey,
    /// JWKS for the `/jwks` endpoint.
    pub jwks: CoreJsonWebKeySet,
    /// jsonwebtoken encoding key — used for access token JWTs.
    pub encoding_key: EncodingKey,
    /// jsonwebtoken decoding key — used for access token verification (e.g. userinfo).
    pub decoding_key: DecodingKey,
    /// Key ID used for JWT headers.
    pub kid: String,
}

/// Access token claims (not covered by the openidconnect crate — access tokens are opaque there).
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub scope: String,
    pub client_id: String,
}

/// Authorization code stored in MongoDB.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthorizationCode {
    pub code_hash: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub used: bool,
}

/// Refresh token stored in MongoDB.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshToken {
    pub token_hash: String,
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub revoked: bool,
}

/// Revoked access token entry (short-lived blocklist for JWT access tokens).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RevokedAccessToken {
    pub token_hash: String,
    pub client_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Generate an OIDC signing key file at the default path.
/// Called during first-run config generation.
pub fn generate_oidc_key_file(key_file: &str) -> Result<()> {
    if std::path::Path::new(key_file).exists() {
        return Ok(());
    }

    info!("Generating new OIDC signing key ({RSA_KEY_BITS} bits)...");
    let mut rng = rsa::rand_core::OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, RSA_KEY_BITS).wrap_err("Failed to generate RSA key")?;

    let pem = private_key
        .to_pkcs1_pem(LineEnding::LF)
        .wrap_err("Failed to encode RSA key to PEM")?;
    std::fs::write(key_file, pem.as_str()).wrap_err("Failed to write OIDC signing key")?;
    info!("OIDC signing key saved to {key_file}");

    Ok(())
}

/// Initialize OIDC keys — load from file specified in config, or generate new if missing.
pub fn init_oidc_keys(key_file: &str) -> Result<Arc<OidcKeys>> {
    let (private_key, public_key) = if std::path::Path::new(key_file).exists() {
        info!("Loading OIDC signing key from {key_file}");
        let pem = std::fs::read_to_string(key_file).wrap_err("Failed to read OIDC signing key")?;
        let private_key =
            RsaPrivateKey::from_pkcs1_pem(&pem).wrap_err("Failed to parse OIDC signing key")?;
        let public_key = RsaPublicKey::from(&private_key);
        (private_key, public_key)
    } else {
        info!("Generating new OIDC signing key ({RSA_KEY_BITS} bits)...");
        let mut rng = rsa::rand_core::OsRng;
        let private_key =
            RsaPrivateKey::new(&mut rng, RSA_KEY_BITS).wrap_err("Failed to generate RSA key")?;
        let public_key = RsaPublicKey::from(&private_key);

        // Save for persistence across restarts
        let pem = private_key
            .to_pkcs1_pem(LineEnding::LF)
            .wrap_err("Failed to encode RSA key to PEM")?;
        std::fs::write(key_file, pem.as_str()).wrap_err("Failed to write OIDC signing key")?;
        info!("OIDC signing key saved to {key_file}");

        (private_key, public_key)
    };

    // Derive a stable kid from the public key hash
    let kid = {
        let der = public_key
            .to_pkcs1_der()
            .wrap_err("Failed to encode public key DER")?;
        let hash = Sha256::digest(der.as_bytes());
        URL_SAFE_NO_PAD.encode(&hash[..8])
    };

    // Build the openidconnect signing key + JWKS
    let private_pem = private_key
        .to_pkcs1_pem(LineEnding::LF)
        .wrap_err("Failed to encode private key")?;

    let signing_key = CoreRsaPrivateSigningKey::from_pem(
        private_pem.as_str(),
        Some(JsonWebKeyId::new(kid.clone())),
    )
    .map_err(|e| color_eyre::eyre::eyre!("Failed to create CoreRsaPrivateSigningKey: {e}"))?;

    let verification_key: CoreJsonWebKey = signing_key.as_verification_key();
    let jwks = CoreJsonWebKeySet::new(vec![verification_key]);

    // Build jsonwebtoken keys for access token signing/verification
    let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
        .wrap_err("Failed to create encoding key")?;

    let public_pem = public_key
        .to_pkcs1_pem(LineEnding::LF)
        .wrap_err("Failed to encode public key")?;
    let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
        .wrap_err("Failed to create decoding key")?;

    info!("OIDC provider initialized with kid={kid}");

    Ok(Arc::new(OidcKeys {
        signing_key,
        jwks,
        encoding_key,
        decoding_key,
        kid,
    }))
}

impl OidcKeys {
    /// Sign an access token JWT (not covered by the openidconnect crate).
    pub fn sign_access_token(&self, claims: &AccessTokenClaims) -> Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());

        jsonwebtoken::encode(&header, claims, &self.encoding_key)
            .wrap_err("Failed to sign access token")
    }
}

/// Build the OIDC discovery document using `CoreProviderMetadata`.
pub fn build_provider_metadata(issuer: &str) -> Result<CoreProviderMetadata> {
    let issuer_url = IssuerUrl::new(issuer.to_string()).wrap_err("Invalid issuer URL")?;
    let auth_url = AuthUrl::new(format!("{issuer}/api/oidc/authorize"))
        .wrap_err("Invalid authorization URL")?;
    let jwks_url =
        JsonWebKeySetUrl::new(format!("{issuer}/api/oidc/jwks")).wrap_err("Invalid JWKS URL")?;

    let provider_metadata = CoreProviderMetadata::new(
        issuer_url,
        auth_url,
        jwks_url,
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Public],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(
        TokenUrl::new(format!("{issuer}/api/oidc/token")).wrap_err("Invalid token URL")?,
    ))
    .set_userinfo_endpoint(Some(
        UserInfoUrl::new(format!("{issuer}/api/oidc/userinfo")).wrap_err("Invalid userinfo URL")?,
    ))
    .set_scopes_supported(Some(vec![
        Scope::new("openid".to_string()),
        Scope::new("profile".to_string()),
        Scope::new("email".to_string()),
        Scope::new("offline_access".to_string()),
    ]))
    .set_claims_supported(Some(vec![
        CoreClaimName::new("sub".to_string()),
        CoreClaimName::new("iss".to_string()),
        CoreClaimName::new("aud".to_string()),
        CoreClaimName::new("exp".to_string()),
        CoreClaimName::new("iat".to_string()),
        CoreClaimName::new("name".to_string()),
        CoreClaimName::new("given_name".to_string()),
        CoreClaimName::new("family_name".to_string()),
        CoreClaimName::new("preferred_username".to_string()),
        CoreClaimName::new("email".to_string()),
        CoreClaimName::new("email_verified".to_string()),
    ]));

    Ok(provider_metadata)
}
