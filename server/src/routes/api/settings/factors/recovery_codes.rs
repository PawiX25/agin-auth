mod enable;
mod reset;

use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use color_eyre::eyre::{self, Context, Result};
use entity::{auth_method, recovery_code};
use rand::{RngExt, distr::Alphanumeric};
use sea_orm::{
    ColumnTrait, Condition, DatabaseConnection, EntityTrait, ModelTrait, PaginatorTrait,
    QueryFilter, TransactionTrait,
};
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

/// Check if all recovery codes are exhausted and disable the auth_method if so.
pub async fn disable_if_exhausted(db: &DatabaseConnection, user_id: i32) -> Result<()> {
    let txn = db.begin().await.wrap_err("Failed to start transaction")?;

    let remaining = recovery_code::Entity::find()
        .filter(recovery_code::Column::UserId.eq(user_id))
        .filter(recovery_code::Column::Used.eq(false))
        .count(&txn)
        .await
        .wrap_err("Failed to count remaining recovery codes")?;

    if remaining == 0 {
        if let Some(method) = auth_method::Entity::find()
            .filter(auth_method::Column::UserId.eq(user_id))
            .filter(auth_method::Column::MethodType.eq(auth_method::Method::RecoveryCodes))
            .one(&txn)
            .await
            .wrap_err("Failed to query recovery codes auth_method")?
        {
            method
                .delete(&txn)
                .await
                .wrap_err("Failed to delete recovery codes auth_method")?;
        }
    }

    txn.commit()
        .await
        .wrap_err("Failed to commit transaction")?;
    Ok(())
}

/// If the only remaining 2FA method is recovery codes, clean them up.
/// Call this after removing a non-recovery-code 2FA method.
pub async fn cleanup_if_only_recovery_codes_remain(
    db: &DatabaseConnection,
    user_id: i32,
) -> Result<()> {
    let txn = db.begin().await.wrap_err("Failed to start transaction")?;

    let remaining_methods = auth_method::Entity::find()
        .filter(auth_method::Column::UserId.eq(user_id))
        .filter(auth_method::Column::IsEnabled.eq(true))
        .filter(
            Condition::all()
                .add(auth_method::Column::MethodType.ne(auth_method::Method::Password))
                .add(auth_method::Column::MethodType.ne(auth_method::Method::Pgp)),
        )
        .all(&txn)
        .await
        .wrap_err("Failed to query remaining 2FA methods")?;

    // If only RecoveryCodes remain as 2FA methods, remove them
    if remaining_methods
        .iter()
        .all(|m| m.method_type == auth_method::Method::RecoveryCodes)
        && !remaining_methods.is_empty()
    {
        // Delete recovery code records
        recovery_code::Entity::delete_many()
            .filter(recovery_code::Column::UserId.eq(user_id))
            .exec(&txn)
            .await
            .wrap_err("Failed to delete recovery codes")?;

        // Delete auth_method record
        for method in remaining_methods {
            method
                .delete(&txn)
                .await
                .wrap_err("Failed to delete recovery codes auth_method")?;
        }
    }

    txn.commit()
        .await
        .wrap_err("Failed to commit transaction")?;
    Ok(())
}
