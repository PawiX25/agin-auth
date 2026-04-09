use axum::{Extension, Json};
use axum_valid::Valid;
use color_eyre::eyre::{Context, ContextCompat};
use futures::TryStreamExt;
use mongodb::bson::doc;
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    axum_error::AxumResult,
    database::{
        Application, ClientType, EditApplicationBody, PartialApplication, PublicApplication,
    },
    middlewares::require_auth::{ForbiddenError, UnauthorizedError},
    state::AppState,
    utils::{generate_client_id, generate_client_secret},
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_applications, create_application))
}

#[derive(Serialize, ToSchema)]
struct CreateApplicationResponse {
    success: bool,
    id: String,
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
    let cursor = state
        .database
        .collection::<Application>("applications")
        .find(doc! {})
        .await?;

    let applications: Vec<Application> = cursor.try_collect().await?;

    let public_applications = applications
        .iter()
        .map(|a| a.to_public())
        .collect::<Vec<_>>();

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

    let app = PartialApplication {
        name: body.name,
        slug: body.slug,
        icon: body.icon,
        client_type: body.client_type,
        client_id: generate_client_id(),
        client_secret: client_secret.clone(),
        redirect_uris: body.redirect_uris,
        allowed_groups: body.allowed_groups,
    };

    let inserted = state
        .database
        .collection::<PartialApplication>("applications")
        .insert_one(app)
        .await
        .wrap_err("Failed to create application")?;

    let id = inserted
        .inserted_id
        .as_object_id()
        .wrap_err("Failed to fetch application ID")?
        .to_string();

    Ok(Json(CreateApplicationResponse {
        success: true,
        id,
        client_secret,
    }))
}
