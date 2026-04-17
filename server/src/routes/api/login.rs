mod password;
// TODO: re-enable after PostgreSQL migration
// mod pgp;
// mod recovery_codes;
// mod totp;
// mod webauthn;

use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().nest("/password", password::routes())
}

#[derive(Serialize, ToSchema)]
struct SuccessfulLoginResponse {
    two_factor_required: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    second_factors: Option<Vec<String>>,

    /// Recently used factor
    #[serde(skip_serializing_if = "Option::is_none")]
    recent_factor: Option<String>,
}
