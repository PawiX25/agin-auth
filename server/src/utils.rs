use rand::{RngExt, distr::Alphanumeric, rngs::ThreadRng};
use sea_orm::DbErr;
use sha2::{Digest, Sha256};

pub fn generate_client_id() -> String {
    let rng = ThreadRng::default();

    rng.sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect()
}

pub fn generate_client_secret() -> String {
    let rng = ThreadRng::default();

    rng.sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

pub fn generate_reset_token() -> String {
    let rng = ThreadRng::default();

    rng.sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn hash_password(password: &str) -> color_eyre::eyre::Result<String> {
    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
    };

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| color_eyre::eyre::eyre!("Failed to hash password"))?
        .to_string();

    Ok(hash)
}

pub fn verify_password(password: &str, hash: &str) -> color_eyre::eyre::Result<()> {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};

    let parsed_hash =
        PasswordHash::new(hash).map_err(|_| color_eyre::eyre::eyre!("Failed to parse hash"))?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| color_eyre::eyre::eyre!("Invalid password"))?;

    Ok(())
}

/// Check if a `DbErr` is a PostgreSQL unique constraint violation (SQLSTATE 23505).
pub fn is_unique_violation(err: &DbErr) -> bool {
    let msg = err.to_string();
    msg.contains("duplicate key value violates unique constraint") || msg.contains("23505")
}
