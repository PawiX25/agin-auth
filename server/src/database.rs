use chrono::Utc;
use color_eyre::eyre::{Context, Result};
use entity::session;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectOptions, Database, DatabaseConnection,
    EntityTrait, IntoActiveModel, QueryFilter, Set,
};
use sha2::{Digest, Sha256};
use tower_sessions::{
    Expiry, SessionManagerLayer,
    cookie::{SameSite, time::Duration},
};
use tower_sessions_redis_store::{
    RedisStore,
    fred::prelude::{ClientLike, Config, KeysInterface, Pool},
};

use crate::settings::Settings;

pub async fn init_database(settings: &Settings) -> Result<DatabaseConnection> {
    let mut opt = ConnectOptions::new(&settings.db.connection_string);
    opt.max_connections(100)
        .min_connections(5)
        .sqlx_logging(false);

    let db = Database::connect(opt)
        .await
        .wrap_err("failed to connect to PostgreSQL")?;

    Ok(db)
}

pub async fn init_session_store(
    settings: &Settings,
) -> Result<(SessionManagerLayer<RedisStore<Pool>>, Pool)> {
    let config = Config::from_url(&settings.redis.connection_string)?;
    let pool = Pool::new(config, None, None, None, 6)?;

    let _redis_conn = pool.connect();
    pool.wait_for_connect().await?;

    let session_store = RedisStore::<Pool>::new(pool.clone());

    let secure = settings.general.public_url.scheme_str() == Some("https");

    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(secure)
        .with_same_site(SameSite::Lax)
        .with_always_save(true)
        .with_expiry(Expiry::OnInactivity(Duration::days(7)));

    Ok((session_layer, pool))
}

fn session_public_id(session_id: &str) -> uuid::Uuid {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&Sha256::digest(session_id.as_bytes())[..16]);
    uuid::Uuid::from_bytes(bytes)
}

pub async fn record_session(
    db: &DatabaseConnection,
    session_id: &str,
    user_id: i32,
    ip_address: &str,
    user_agent: &str,
) -> Result<()> {
    let public_id = session_public_id(session_id);

    if let Some(existing) = session::Entity::find()
        .filter(
            Condition::any()
                .add(session::Column::SessionKey.eq(session_id.to_owned()))
                .add(session::Column::PublicId.eq(public_id)),
        )
        .one(db)
        .await
        .wrap_err("Failed to query session record")?
    {
        let mut model = existing.into_active_model();
        model.user_id = Set(user_id);
        model.session_key = Set(session_id.to_owned());
        model.ip_address = Set(Some(ip_address.to_owned()));
        model.user_agent = Set(Some(user_agent.to_owned()));
        model.last_active = Set(Utc::now());
        model
            .update(db)
            .await
            .wrap_err("Failed to update session record")?;
    } else {
        let now = Utc::now();
        let model = session::ActiveModel {
            user_id: Set(user_id),
            session_key: Set(session_id.to_owned()),
            public_id: Set(public_id),
            ip_address: Set(Some(ip_address.to_owned())),
            user_agent: Set(Some(user_agent.to_owned())),
            last_active: Set(now),
            created_at: Set(now),
            ..Default::default()
        };
        model
            .insert(db)
            .await
            .wrap_err("Failed to insert session record")?;
    }

    Ok(())
}

pub async fn invalidate_user_sessions(
    db: &DatabaseConnection,
    redis_pool: &Pool,
    user_id: i32,
    except_session_key: Option<&str>,
) -> Result<()> {
    let mut query = session::Entity::find().filter(session::Column::UserId.eq(user_id));

    if let Some(except) = except_session_key {
        query = query.filter(session::Column::SessionKey.ne(except));
    }

    let records = query.all(db).await.wrap_err("Failed to query sessions")?;

    for record in &records {
        let _: i64 = redis_pool.del(&record.session_key).await.unwrap_or(0);
    }

    let ids: Vec<i32> = records.iter().map(|r| r.id).collect();
    if !ids.is_empty() {
        session::Entity::delete_many()
            .filter(session::Column::Id.is_in(ids))
            .exec(db)
            .await
            .wrap_err("Failed to delete session records")?;
    }

    Ok(())
}
