mod templates;

use mail_builder::MessageBuilder;
use mail_send::SmtpClientBuilder;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("SMTP error: {0}")]
    Smtp(#[from] mail_send::Error),
}

pub type Result<T> = std::result::Result<T, MailError>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MailConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    pub from_name: String,
    /// Use implicit TLS (port 465). Set to false for STARTTLS (port 587).
    #[serde(default)]
    pub implicit_tls: bool,
}

pub struct MailService {
    config: MailConfig,
    app_name: String,
    public_url: String,
}

impl MailService {
    pub fn new(config: MailConfig, app_name: String, public_url: &str) -> Self {
        Self {
            config,
            app_name,
            public_url: public_url.trim_end_matches('/').to_string(),
        }
    }

    async fn send(&self, to: &str, subject: &str, html: String) -> Result<()> {
        let message = MessageBuilder::new()
            .from((
                self.config.from_name.as_str(),
                self.config.from_address.as_str(),
            ))
            .to(vec![to])
            .subject(subject)
            .html_body(html);

        SmtpClientBuilder::new(self.config.host.as_str(), self.config.port)
            .implicit_tls(self.config.implicit_tls)
            .credentials((self.config.username.as_str(), self.config.password.as_str()))
            .connect()
            .await?
            .send(message)
            .await?;

        Ok(())
    }

    pub async fn send_password_reset(&self, to: &str, token: &str) -> Result<()> {
        let reset_url = format!("{}/reset-password?token={token}", self.public_url);
        let html = templates::password_reset(&reset_url);
        self.send(to, &format!("Reset your {} password", self.app_name), html)
            .await
    }

    pub async fn send_email_confirmation(&self, to: &str, token: &str) -> Result<()> {
        let confirm_url = format!("{}/api/confirm-email?token={token}", self.public_url);
        let html = templates::email_confirmation(&confirm_url);
        self.send(
            to,
            &format!("Confirm your {} email address", self.app_name),
            html,
        )
        .await
    }

    pub async fn send_login_notification(&self, to: &str, ip: &str) -> Result<()> {
        let html = templates::login_notification(ip);
        self.send(
            to,
            &format!("New login to your {} account", self.app_name),
            html,
        )
        .await
    }

    pub async fn send_password_changed(&self, to: &str) -> Result<()> {
        let html = templates::password_changed();
        self.send(
            to,
            &format!("Your {} password was changed", self.app_name),
            html,
        )
        .await
    }

    pub async fn send_factor_added(&self, to: &str, factor_name: &str) -> Result<()> {
        let html = templates::factor_added(factor_name);
        self.send(
            to,
            &format!("Security method added to your {} account", self.app_name),
            html,
        )
        .await
    }

    pub async fn send_factor_removed(&self, to: &str, factor_name: &str) -> Result<()> {
        let html = templates::factor_removed(factor_name);
        self.send(
            to,
            &format!(
                "Security method removed from your {} account",
                self.app_name
            ),
            html,
        )
        .await
    }
}

// ── Standalone render helpers (no SMTP needed, useful for previews/tests) ──

pub fn render_password_reset(reset_url: &str) -> String {
    templates::password_reset(reset_url)
}

pub fn render_email_confirmation(confirm_url: &str) -> String {
    templates::email_confirmation(confirm_url)
}

pub fn render_login_notification(ip: &str) -> String {
    templates::login_notification(ip)
}

pub fn render_password_changed() -> String {
    templates::password_changed()
}

pub fn render_factor_added(factor_name: &str) -> String {
    templates::factor_added(factor_name)
}

pub fn render_factor_removed(factor_name: &str) -> String {
    templates::factor_removed(factor_name)
}
