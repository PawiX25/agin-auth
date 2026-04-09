mod password;
mod pgp;
mod recovery_codes;
mod totp;
mod webauthn;

use axum::middleware;
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;

use crate::{
    database::SecondFactor, middlewares::require_auth::require_first_factor, state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    let two_factor = OpenApiRouter::new()
        .nest("/totp", totp::routes())
        .nest("/recovery-codes", recovery_codes::routes())
        .nest("/webauthn", webauthn::two_factor_routes())
        .layer(middleware::from_fn(require_first_factor));

    let public = OpenApiRouter::new()
        .nest("/password", password::routes())
        .nest("/pgp", pgp::routes())
        .nest("/webauthn/passwordless", webauthn::passwordless_routes());

    two_factor.merge(public)
}

#[derive(Serialize, ToSchema)]
struct SuccessfulLoginResponse {
    two_factor_required: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    second_factors: Option<Vec<SecondFactor>>,

    /// Recently used factor
    #[serde(skip_serializing_if = "Option::is_none")]
    recent_factor: Option<SecondFactor>,
}
