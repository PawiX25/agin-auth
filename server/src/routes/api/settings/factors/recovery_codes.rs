mod enable;
mod reset;

use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use color_eyre::eyre::{self, Context, Result};
use entity::recovery_code;
use rand::{RngExt, distr::Alphanumeric};
use utoipa_axum::router::OpenApiRouter;

use crate::{
    axum_error::{AxumError, AxumResult},
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .nest("/enable", enable::routes())
        .nest("/reset", reset::routes())
}

pub fn generate_recovery_code(len: usize) -> String {
    let rng = rand::rngs::ThreadRng::default();

    rng.sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

pub fn generate_recovery_codes(count: usize, code_length: usize) -> Vec<String> {
    (0..count)
        .map(|_| generate_recovery_code(code_length))
        .collect()
}

pub fn hash_recovery_codes(codes: Vec<String>) -> AxumResult<Vec<String>> {
    let argon2 = Argon2::default();

    let hashes = codes
        .into_iter()
        .map(|code| -> Result<String> {
            let salt = SaltString::generate(&mut OsRng);

            let hash = argon2
                .hash_password(code.as_bytes(), &salt)
                .map_err(|_| eyre::eyre!("Failed to compute hash"))?
                .to_string();

            Ok(hash)
        })
        .collect::<Result<Vec<_>>>()
        .wrap_err("Failed to hash codes")?;

    Ok(hashes)
}

pub fn verify_recovery_code(code: String, codes: Vec<recovery_code::Model>) -> AxumResult<String> {
    let argon2 = Argon2::default();

    for rc in codes {
        let parsed_hash =
            PasswordHash::new(&rc.code_hash).map_err(|_| eyre::eyre!("Failed to compute hash"))?;

        if argon2
            .verify_password(code.as_bytes(), &parsed_hash)
            .is_ok()
        {
            if rc.used {
                return Err(AxumError::unauthorized(eyre::eyre!(
                    "Recovery code already used"
                )));
            }
            return Ok(rc.code_hash);
        }
    }

    Err(AxumError::unauthorized(eyre::eyre!(
        "Invalid recovery code"
    )))
}
