use base64::Engine;
use color_eyre::eyre::Context;
use entity::{auth_method, webauthn as webauthn_entity};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set};
use webauthn_rs::prelude::{AuthenticationResult, Passkey};

use crate::{auth_method_helpers::touch_auth_method, axum_error::AxumResult, state::AppState};

pub async fn update_webauthn_credentials(
    state: &AppState,
    user_id: i32,
    auth_result: &AuthenticationResult,
) -> AxumResult<()> {
    let cred_id =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(auth_result.cred_id().as_ref());

    let record = webauthn_entity::Entity::find()
        .filter(webauthn_entity::Column::UserId.eq(user_id))
        .filter(webauthn_entity::Column::CredentialId.eq(&cred_id))
        .one(&state.db)
        .await?;

    let Some(record) = record else {
        return Ok(());
    };

    let mut passkey: Passkey =
        serde_json::from_str(&record.serialized_key).wrap_err("Failed to deserialize passkey")?;
    passkey.update_credential(auth_result);

    let updated_key = serde_json::to_string(&passkey).wrap_err("Failed to serialize passkey")?;

    let mut am = record.into_active_model();
    am.serialized_key = Set(updated_key);
    am.update(&state.db).await?;

    touch_auth_method(&state.db, user_id, auth_method::Method::WebAuthn).await?;

    Ok(())
}
