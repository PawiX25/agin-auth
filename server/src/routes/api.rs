mod admin;
mod applications;
mod confirm_email;
mod health;
mod login;
mod logout;
mod password_reset;
mod register;
mod settings;

use axum::middleware;
use serde::{Deserialize, Serialize};
use strum::Display;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;

use crate::{
    middlewares::require_auth::{require_admin, require_auth},
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    let admin = OpenApiRouter::new()
        .nest("/admin", admin::routes())
        .layer(middleware::from_fn(require_admin));

    let auth = OpenApiRouter::new()
        .merge(admin)
        .nest("/logout", logout::routes())
        .nest("/settings", settings::routes())
        .nest("/applications", applications::routes())
        .layer(middleware::from_fn(require_auth));

    // Rate limit public endpoints: 5 burst, 1 replenish per 2s per IP
    let rate_limit_conf = GovernorConfigBuilder::default()
        .per_second(2)
        .burst_size(5)
        .finish()
        .unwrap();

    let public = OpenApiRouter::new()
        .nest("/health", health::routes())
        .nest("/login", login::routes())
        .nest("/register", register::routes())
        .nest("/confirm-email", confirm_email::routes())
        .nest("/password-reset", password_reset::routes())
        .layer(GovernorLayer::new(rate_limit_conf));

    auth.merge(public)
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
