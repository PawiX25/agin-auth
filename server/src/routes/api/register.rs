use axum::{Extension, Json};
use axum_valid::Valid;
use color_eyre::eyre;
use mongodb::bson::{doc, oid::ObjectId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;
use validator::Validate;

use crate::{
    axum_error::{AxumError, AxumResult},
    database::{AuthFactors, PasswordFactor, User},
    routes::api::{
        CreateSuccess,
        confirm_email::{EmailConfirmationToken, send_confirmation_email},
    },
    state::AppState,
    utils::hash_password,
    validators::username_validator,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(register))
}

#[derive(Deserialize, ToSchema, Validate)]
struct RegisterBody {
    #[validate(length(min = 1, max = 32))]
    first_name: String,

    #[validate(length(min = 1, max = 32))]
    last_name: String,

    #[validate(length(min = 1, max = 32))]
    display_name: String,

    #[validate(custom(function = "username_validator"), length(min = 1, max = 32))]
    preferred_username: String,

    #[validate(email, length(max = 128))]
    email: String,

    #[validate(length(min = 8))]
    password: String,
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({"error": "User with this username or email already exists"}))]
pub struct BadRequestError {
    error: String,
}

/// Register
#[utoipa::path(
    method(post),
    path = "/",
    responses(
        (status = OK, description = "Success", body = CreateSuccess, content_type = "application/json"),
        (status = BAD_REQUEST, description = "BadRequest", body = BadRequestError, content_type = "application/json"),
    ),
    tag = "Register"
)]
async fn register(
    Extension(state): Extension<AppState>,
    Valid(Json(body)): Valid<Json<RegisterBody>>,
) -> AxumResult<Json<CreateSuccess>> {
    let already_exists = state
        .database
        .collection::<User>("users")
        .find_one(doc! {
            "$or": [
                { "preferred_username": &body.preferred_username },
                { "email": &body.email }
            ]
        })
        .await?;

    if already_exists.is_some() {
        return Err(AxumError::bad_request(eyre::eyre!(
            "User with this username or email already exists"
        )));
    }

    let hashed_password = hash_password(&body.password)?;
    let user_id = ObjectId::new();
    let uuid = Uuid::new_v4();

    let is_first_user = state
        .database
        .collection::<User>("users")
        .count_documents(doc! {})
        .await?
        == 0;

    let user = User {
        id: user_id,
        uuid,
        first_name: body.first_name,
        last_name: body.last_name,
        display_name: body.display_name,
        preferred_username: body.preferred_username,
        email: body.email.clone(),
        email_confirmed: false,
        is_admin: is_first_user,
        auth_factors: AuthFactors {
            password: PasswordFactor {
                password_hash: Some(hashed_password),
            },
            ..Default::default()
        },
        groups: vec![],
    };

    state
        .database
        .collection::<User>("users")
        .insert_one(user)
        .await?;

    if let Err(error) = send_confirmation_email(&state, user_id, &body.email).await {
        if let Err(cleanup_error) = state
            .database
            .collection::<EmailConfirmationToken>("email_confirmation_tokens")
            .delete_many(doc! { "user_id": user_id })
            .await
        {
            tracing::warn!(
                error = ?cleanup_error,
                %user_id,
                "Failed to clean up confirmation tokens after registration error"
            );
        }

        if let Err(cleanup_error) = state
            .database
            .collection::<User>("users")
            .delete_one(doc! { "_id": user_id })
            .await
        {
            tracing::error!(
                error = ?cleanup_error,
                %user_id,
                "Failed to roll back user after registration error"
            );
        }

        return Err(error);
    }

    Ok(Json(CreateSuccess {
        success: true,
        id: user_id.to_string(),
    }))
}
