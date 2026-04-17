mod auth_method_helpers;
mod axum_error;
mod database;
mod extractors;
mod factors;
mod init;
mod middlewares;
mod oidc;
mod routes;
mod settings;
mod state;
mod utils;
mod validators;
mod webauthn;

use std::sync::Arc;

use color_eyre::Result;
use color_eyre::eyre::WrapErr;
use tracing::info;
use utoipa::OpenApi;

use crate::{
    database::{init_database, init_session_store},
    init::{init_axum, init_listener, init_tracing},
    oidc::init_oidc_keys,
    settings::Settings,
    state::AppState,
    webauthn::init_webauthn,
};

#[derive(OpenApi)]
#[openapi()]
struct ApiDoc;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    dotenvy::dotenv().ok();
    init_tracing().wrap_err("failed to set global tracing subscriber")?;

    info!(
        "Starting {} {}...",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
    );

    let settings = Arc::new(Settings::try_load()?);

    let database = init_database(&settings).await?;

    let webauthn = init_webauthn(&settings)?;

    let mail_service = settings.mail.clone().map(|cfg| {
        Arc::new(mail::MailService::new(
            cfg,
            settings.general.app_name.clone(),
            &settings.general.public_url.to_string(),
        ))
    });

    let oidc_keys = init_oidc_keys(&settings.oidc.signing_key_file)?;

    let (session_layer, redis_pool) = init_session_store(&settings).await?;

    let app_state = AppState {
        db: database,
        settings: settings.clone(),
        webauthn,
        mail_service,
        oidc_keys,
        redis_pool,
    };

    let app = init_axum(app_state, session_layer).await?;
    let listener = init_listener(&settings).await?;

    info!(
        "listening on {} ({})",
        listener
            .local_addr()
            .wrap_err("failed to get local address")?,
        settings.general.public_url
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .wrap_err("failed to run server")?;

    Ok(())
}
