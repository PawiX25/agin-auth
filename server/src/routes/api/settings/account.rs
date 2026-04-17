use axum::{Extension, Json, http::StatusCode};
use color_eyre::eyre::{self, OptionExt};
use entity::{
    auth_method, authorization_code, email_confirmation_token, password, password_reset_token, pgp,
    recovery_code, refresh_token, session, totp, user, webauthn,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};
use tower_sessions::Session;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    axum_error::{AxumError, AxumResult},
    database::invalidate_user_sessions,
    middlewares::require_auth::UserId,
    state::AppState,
    utils::verify_password,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(delete_account))
}

#[derive(serde::Deserialize, ToSchema)]
struct DeleteAccountBody {
    /// Current password for confirmation
    password: String,
}

/// Delete account
///
/// Permanently deletes the user's account after verifying their password. This action is irreversible.
#[utoipa::path(
    method(delete),
    path = "/",
    request_body = DeleteAccountBody,
    responses(
        (status = NO_CONTENT, description = "Account deleted"),
        (status = UNAUTHORIZED, description = "Invalid password"),
    ),
    tag = "Settings"
)]
async fn delete_account(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
    session: Session,
    Json(body): Json<DeleteAccountBody>,
) -> AxumResult<StatusCode> {
    let pw = password::Entity::find_by_id(*user_id)
        .one(&state.db)
        .await?
        .ok_or_eyre("Password not set")?;

    verify_password(&body.password, &pw.password_hash)
        .map_err(|_| AxumError::unauthorized(eyre::eyre!("Invalid password")))?;

    invalidate_user_sessions(&state.db, &state.redis_pool, *user_id, None).await?;

    let txn = state.db.begin().await?;

    authorization_code::Entity::delete_many()
        .filter(authorization_code::Column::UserId.eq(*user_id))
        .exec(&txn)
        .await?;
    email_confirmation_token::Entity::delete_many()
        .filter(email_confirmation_token::Column::UserId.eq(*user_id))
        .exec(&txn)
        .await?;
    password_reset_token::Entity::delete_many()
        .filter(password_reset_token::Column::UserId.eq(*user_id))
        .exec(&txn)
        .await?;
    refresh_token::Entity::delete_many()
        .filter(refresh_token::Column::UserId.eq(*user_id))
        .exec(&txn)
        .await?;
    session::Entity::delete_many()
        .filter(session::Column::UserId.eq(*user_id))
        .exec(&txn)
        .await?;
    webauthn::Entity::delete_many()
        .filter(webauthn::Column::UserId.eq(*user_id))
        .exec(&txn)
        .await?;
    recovery_code::Entity::delete_many()
        .filter(recovery_code::Column::UserId.eq(*user_id))
        .exec(&txn)
        .await?;
    pgp::Entity::delete_many()
        .filter(pgp::Column::UserId.eq(*user_id))
        .exec(&txn)
        .await?;
    totp::Entity::delete_many()
        .filter(totp::Column::UserId.eq(*user_id))
        .exec(&txn)
        .await?;
    auth_method::Entity::delete_many()
        .filter(auth_method::Column::UserId.eq(*user_id))
        .exec(&txn)
        .await?;
    password::Entity::delete_many()
        .filter(password::Column::UserId.eq(*user_id))
        .exec(&txn)
        .await?;
    user::Entity::delete_by_id(*user_id).exec(&txn).await?;

    txn.commit().await?;

    session.flush().await?;

    Ok(StatusCode::NO_CONTENT)
}
