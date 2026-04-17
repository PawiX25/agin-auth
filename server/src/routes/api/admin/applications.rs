use axum::{Extension, Json};
use axum_valid::Valid;
use color_eyre::eyre::Context;
use entity::application::{self, ClientType};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    axum_error::AxumResult,
    middlewares::require_auth::{ForbiddenError, UnauthorizedError},
    state::AppState,
    utils::{generate_client_id, generate_client_secret, hash_token},
    validators::slug_validator,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_applications, create_application))
}

#[derive(Debug, Serialize, ToSchema, Clone)]
pub struct PublicApplication {
    pub id: i32,
    pub name: String,
    pub slug: String,
    pub icon: Option<String>,
    pub client_type: ClientType,
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub allowed_groups: Vec<String>,
}

impl From<application::Model> for PublicApplication {
    fn from(app: application::Model) -> Self {
        Self {
            id: app.id,
            name: app.name,
            slug: app.slug,
            icon: app.icon,
            client_type: app.client_type,
            client_id: app.client_id,
            redirect_uris: app.redirect_uris,
            allowed_groups: app.allowed_groups,
        }
    }
}

#[derive(Debug, serde::Deserialize, ToSchema, Clone, Validate)]
pub struct EditApplicationBody {
    #[validate(length(min = 1, max = 32))]
    pub name: String,
    #[validate(custom(function = "slug_validator"), length(min = 1, max = 32))]
    pub slug: String,
    #[validate(length(min = 1, max = 256))]
    pub icon: Option<String>,
    pub client_type: ClientType,
    pub redirect_uris: Vec<String>,
    pub allowed_groups: Vec<String>,
}

#[derive(Serialize, ToSchema)]
struct CreateApplicationResponse {
    success: bool,
    id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
}

/// Get applications
#[utoipa::path(
    method(get),
    path = "/",
    responses(
        (status = OK, description = "Success", body = Vec<PublicApplication>, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
        (status = FORBIDDEN, description = "Forbidden", body = ForbiddenError, content_type = "application/json"),
    ),
    tag = "Admin"
)]
async fn get_applications(
    Extension(state): Extension<AppState>,
) -> AxumResult<Json<Vec<PublicApplication>>> {
    let applications: Vec<application::Model> = application::Entity::find().all(&state.db).await?;

    let public_applications: Vec<PublicApplication> = applications
        .into_iter()
        .map(PublicApplication::from)
        .collect();

    Ok(Json(public_applications))
}

/// Create application
#[utoipa::path(
    method(post),
    path = "/",
    responses(
        (status = OK, description = "Success", body = CreateApplicationResponse, content_type = "application/json"),
        (status = UNAUTHORIZED, description = "Unauthorized", body = UnauthorizedError, content_type = "application/json"),
        (status = FORBIDDEN, description = "Forbidden", body = ForbiddenError, content_type = "application/json"),
    ),
    tag = "Admin"
)]
async fn create_application(
    Extension(state): Extension<AppState>,
    Valid(Json(body)): Valid<Json<EditApplicationBody>>,
) -> AxumResult<Json<CreateApplicationResponse>> {
    let client_secret = match body.client_type {
        ClientType::Confidential => Some(generate_client_secret()),
        ClientType::Public => None,
    };

    let app = application::ActiveModel {
        name: Set(body.name),
        slug: Set(body.slug),
        icon: Set(body.icon),
        client_type: Set(body.client_type),
        client_id: Set(generate_client_id()),
        client_secret: Set(client_secret.as_ref().map(|s| hash_token(s))),
        redirect_uris: Set(body.redirect_uris),
        allowed_groups: Set(body.allowed_groups),
        ..Default::default()
    };

    let inserted = app
        .insert(&state.db)
        .await
        .wrap_err("Failed to create application")?;

    Ok(Json(CreateApplicationResponse {
        success: true,
        id: inserted.id,
        client_secret,
    }))
}
