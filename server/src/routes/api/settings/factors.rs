pub mod pgp;
pub mod recovery_codes;
pub mod totp;
pub mod webauthn;

use axum::{Extension, Json};
use entity::{
    auth_method, pgp as pgp_entity, recovery_code, totp as totp_entity, webauthn as webauthn_entity,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    axum_error::AxumResult,
    middlewares::require_auth::{UnauthorizedError, UserId},
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_factors))
        .nest("/totp", totp::routes())
        .nest("/recovery-codes", recovery_codes::routes())
        .nest("/pgp", pgp::routes())
        .nest("/webauthn", webauthn::routes())
}

#[derive(Serialize, ToSchema)]
struct PublicAuthFactors {
    password: bool,
    totp: Option<TotpStatus>,
    recovery_codes: usize,
    pgp: Vec<PgpKeyInfo>,
    webauthn: Vec<WebAuthnKeyInfo>,
}

#[derive(Serialize, ToSchema)]
struct TotpStatus {
    fully_enabled: bool,
}

#[derive(Serialize, ToSchema)]
struct PgpKeyInfo {
    fingerprint: String,
    display_name: String,
}

#[derive(Serialize, ToSchema)]
struct WebAuthnKeyInfo {
    credential_id: String,
    display_name: String,
}

/// Get factors
///
/// Gets all authentication factors for the current user.
#[utoipa::path(
    method(get),
    path = "/",
    responses(
        (status = OK, description = "Success", body = PublicAuthFactors, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
    ),
    tag = "Settings"
)]
async fn get_factors(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<UserId>,
) -> AxumResult<Json<PublicAuthFactors>> {
    let has_password = auth_method::Entity::find()
        .filter(auth_method::Column::UserId.eq(*user_id))
        .filter(auth_method::Column::MethodType.eq(auth_method::Method::Password))
        .one(&state.db)
        .await?
        .is_some();

    let totp = totp_entity::Entity::find_by_id(*user_id)
        .one(&state.db)
        .await?
        .map(|t| TotpStatus {
            fully_enabled: t.fully_enabled,
        });

    let recovery_count = recovery_code::Entity::find()
        .filter(recovery_code::Column::UserId.eq(*user_id))
        .filter(recovery_code::Column::Used.eq(false))
        .all(&state.db)
        .await?
        .len();

    let pgp_keys = pgp_entity::Entity::find()
        .filter(pgp_entity::Column::UserId.eq(*user_id))
        .all(&state.db)
        .await?
        .into_iter()
        .map(|k| PgpKeyInfo {
            fingerprint: k.fingerprint,
            display_name: k.display_name,
        })
        .collect();

    let webauthn_keys = webauthn_entity::Entity::find()
        .filter(webauthn_entity::Column::UserId.eq(*user_id))
        .all(&state.db)
        .await?
        .into_iter()
        .map(|k| WebAuthnKeyInfo {
            credential_id: k.credential_id,
            display_name: k.display_name,
        })
        .collect();

    Ok(Json(PublicAuthFactors {
        password: has_password,
        totp,
        recovery_codes: recovery_count,
        pgp: pgp_keys,
        webauthn: webauthn_keys,
    }))
}
