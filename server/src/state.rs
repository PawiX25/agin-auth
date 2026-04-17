use std::sync::Arc;

use fred::prelude::Pool;
use mail::MailService;
use sea_orm::DatabaseConnection;
use webauthn_rs::Webauthn;

use crate::{oidc::OidcKeys, settings::Settings};

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub settings: Arc<Settings>,
    pub webauthn: Arc<Webauthn>,
    pub mail_service: Option<Arc<MailService>>,
    pub oidc_keys: Arc<OidcKeys>,
    pub redis_pool: Pool,
}
