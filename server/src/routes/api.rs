// TODO: re-enable after PostgreSQL migration
// mod admin;
// mod applications;
// mod confirm_email;
mod health;
// mod login;
// mod logout;
// mod password_reset;
// mod register;
// mod settings;

use serde::{Deserialize, Serialize};
use strum::Display;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().nest("/health", health::routes())
}

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq, Debug, Display)]
pub enum AuthState {
    Anonymous,
    BeforeTwoFactor,
    Authenticated,
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({"success": true,"id": "1"}))]
pub struct CreateSuccess {
    success: bool,
    id: i32,
}
