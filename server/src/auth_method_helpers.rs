use chrono::Utc;
use entity::auth_method;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter,
    Set, sea_query::OnConflict,
};

/// Upsert an auth_method record using `INSERT ... ON CONFLICT DO UPDATE`.
/// Atomically inserts a new record or updates `is_enabled` + `modified_at` if one exists.
pub async fn upsert_auth_method(
    db: &DatabaseConnection,
    user_id: i32,
    method: auth_method::Method,
) -> Result<(), sea_orm::DbErr> {
    let now = Utc::now();
    let model = auth_method::ActiveModel {
        user_id: Set(user_id),
        method_type: Set(method),
        is_enabled: Set(true),
        enrolled_at: Set(now),
        modified_at: Set(now),
        last_used_at: Set(None),
    };

    auth_method::Entity::insert(model)
        .on_conflict(
            OnConflict::columns([auth_method::Column::UserId, auth_method::Column::MethodType])
                .update_columns([
                    auth_method::Column::IsEnabled,
                    auth_method::Column::ModifiedAt,
                ])
                .to_owned(),
        )
        .exec(db)
        .await?;

    Ok(())
}

/// Update `last_used_at` for an auth method after a successful login.
pub async fn touch_auth_method(
    db: &DatabaseConnection,
    user_id: i32,
    method: auth_method::Method,
) -> Result<(), sea_orm::DbErr> {
    if let Some(record) = auth_method::Entity::find()
        .filter(auth_method::Column::UserId.eq(user_id))
        .filter(auth_method::Column::MethodType.eq(method))
        .one(db)
        .await?
    {
        let mut am = record.into_active_model();
        am.last_used_at = Set(Some(Utc::now()));
        am.update(db).await?;
    }

    Ok(())
}
