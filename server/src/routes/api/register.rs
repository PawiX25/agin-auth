use axum::{Extension, Json};
use axum_valid::Valid;
use color_eyre::eyre;
use entity::{auth_method, password, user};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, PaginatorTrait,
    QueryFilter, Set, TransactionTrait, prelude::*,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;
use validator::Validate;

use crate::{
    axum_error::{AxumError, AxumResult},
    routes::api::CreateSuccess,
    state::AppState,
    utils::{hash_password, is_unique_violation},
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

    #[validate(length(min = 8, max = 256))]
    password: String,
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({"error": "User with this username or email already exists"}))]
pub struct BadRequestError {
    error: String,
}

async fn user_exists(db: &DatabaseConnection, username: &str, email: &str) -> Result<bool, DbErr> {
    let count = user::Entity::find()
        .filter(
            Condition::any()
                .add(user::Column::PreferredUsername.eq(username))
                .add(user::Column::Email.eq(email)),
        )
        .count(db)
        .await?;
    Ok(count > 0)
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
    if user_exists(&state.db, &body.preferred_username, &body.email).await? {
        return Err(AxumError::bad_request(eyre::eyre!(
            "User with this username or email already exists"
        )));
    }

    let hashed_password = hash_password(&body.password)?;

    let is_first_user = user::Entity::find().count(&state.db).await? == 0;

    let txn = state.db.begin().await?;

    let new_user = user::ActiveModel {
        uuid: Set(Uuid::new_v4()),
        first_name: Set(body.first_name),
        last_name: Set(body.last_name),
        display_name: Set(body.display_name),
        preferred_username: Set(body.preferred_username),
        email: Set(body.email),
        email_confirmed: Set(false),
        is_admin: Set(is_first_user),
        ..Default::default()
    };

    let user = new_user.insert(&txn).await.map_err(|e| {
        if is_unique_violation(&e) {
            AxumError::bad_request(eyre::eyre!(
                "User with this username or email already exists"
            ))
        } else {
            AxumError::from(e)
        }
    })?;

    // Record that the user has a password auth method
    let now = chrono::Utc::now();
    let auth_method = auth_method::ActiveModel {
        user_id: Set(user.id),
        method_type: Set(auth_method::Method::Password),
        is_enabled: Set(true),
        enrolled_at: Set(now),
        modified_at: Set(now),
        last_used_at: Set(None),
    };
    auth_method.insert(&txn).await?;

    // Store the hashed password
    let password_record = password::ActiveModel {
        user_id: Set(user.id),
        password_hash: Set(hashed_password),
    };
    password_record.insert(&txn).await?;

    txn.commit().await?;

    // TODO: send confirmation email

    Ok(Json(CreateSuccess {
        success: true,
        id: user.id,
    }))
}
