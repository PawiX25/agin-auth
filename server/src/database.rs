use std::time::Duration as StdDuration;

use color_eyre::eyre::{Context, Result};
use mongodb::{
    Client, Database, IndexModel,
    bson::{self, Bson, doc, oid::ObjectId},
    options::IndexOptions,
};
use partial_struct::Partial;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use tower_sessions::{
    Expiry, SessionManagerLayer,
    cookie::{SameSite, time::Duration},
};
use tower_sessions_redis_store::{
    RedisStore,
    fred::prelude::{ClientLike, Config, KeysInterface, Pool},
};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;
use visible::StructFields;

use crate::{
    axum_error::AxumResult,
    mongo_id::{object_id_as_string_required, vec_oid_to_vec_string},
    settings::Settings,
    validators::slug_validator,
};

macro_rules! database_object {
    ($name:ident { $($field:tt)* }$(, $($omitfield:ident),*)?) => {
        #[derive(Partial, Debug, Serialize, Deserialize, ToSchema, Clone)]
        #[partial(omit(id $(, $($omitfield),* )?), derive(Debug, Serialize, Deserialize, ToSchema, Clone))]
        #[StructFields(pub)]
        pub struct $name {
            $($field)*
        }
    };
}

pub async fn init_database(settings: &Settings) -> Result<Database> {
    let client = Client::with_uri_str(&settings.db.connection_string).await?;
    let database = client.database(&settings.db.database_name);
    ensure_database_indexes(&database).await?;

    Ok(database)
}

async fn ensure_database_indexes(database: &Database) -> Result<()> {
    let sessions = database.collection::<bson::Document>("sessions");

    sessions
        .create_index(
            IndexModel::builder()
                .keys(doc! { "user_id": 1_i32, "last_active": -1_i32 })
                .options(
                    IndexOptions::builder()
                        .name(Some("sessions_user_last_active_idx".to_string()))
                        .build(),
                )
                .build(),
        )
        .await
        .wrap_err("Failed to create sessions_user_last_active_idx")?;

    sessions
        .create_index(
            IndexModel::builder()
                .keys(doc! { "public_id": 1_i32 })
                .options(
                    IndexOptions::builder()
                        .name(Some("sessions_public_id_unique_idx".to_string()))
                        .unique(true)
                        .sparse(true)
                        .build(),
                )
                .build(),
        )
        .await
        .wrap_err("Failed to create sessions_public_id_unique_idx")?;

    sessions
        .create_index(
            IndexModel::builder()
                .keys(doc! { "last_active": 1_i32 })
                .options(
                    IndexOptions::builder()
                        .name(Some("sessions_last_active_ttl_idx".to_string()))
                        .expire_after(StdDuration::from_secs(60 * 60 * 24 * 7))
                        .build(),
                )
                .build(),
        )
        .await
        .wrap_err("Failed to create sessions_last_active_ttl_idx")?;

    let users = database.collection::<bson::Document>("users");

    users
        .create_index(
            IndexModel::builder()
                .keys(doc! { "email": 1_i32 })
                .options(
                    IndexOptions::builder()
                        .name(Some("users_email_unique_idx".to_string()))
                        .unique(true)
                        .build(),
                )
                .build(),
        )
        .await
        .wrap_err("Failed to create users_email_unique_idx")?;

    users
        .create_index(
            IndexModel::builder()
                .keys(doc! { "preferred_username": 1_i32 })
                .options(
                    IndexOptions::builder()
                        .name(Some("users_preferred_username_unique_idx".to_string()))
                        .unique(true)
                        .build(),
                )
                .build(),
        )
        .await
        .wrap_err("Failed to create users_preferred_username_unique_idx")?;

    let applications = database.collection::<bson::Document>("applications");

    applications
        .create_index(
            IndexModel::builder()
                .keys(doc! { "client_id": 1_i32 })
                .options(
                    IndexOptions::builder()
                        .name(Some("applications_client_id_unique_idx".to_string()))
                        .unique(true)
                        .build(),
                )
                .build(),
        )
        .await
        .wrap_err("Failed to create applications_client_id_unique_idx")?;

    applications
        .create_index(
            IndexModel::builder()
                .keys(doc! { "slug": 1_i32 })
                .options(
                    IndexOptions::builder()
                        .name(Some("applications_slug_unique_idx".to_string()))
                        .unique(true)
                        .build(),
                )
                .build(),
        )
        .await
        .wrap_err("Failed to create applications_slug_unique_idx")?;

    Ok(())
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionRecord {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(default)]
    pub public_id: Option<String>,
    pub user_id: ObjectId,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: bson::DateTime,
    pub last_active: bson::DateTime,
}

pub async fn record_session(
    database: &Database,
    session_id: &str,
    user_id: &ObjectId,
    ip_address: &str,
    user_agent: &str,
) -> AxumResult<()> {
    let now = bson::DateTime::now();
    database
        .collection::<SessionRecord>("sessions")
        .update_one(
            doc! { "_id": session_id },
            doc! {
                "$set": {
                    "user_id": user_id,
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "last_active": now,
                },
                "$setOnInsert": {
                    "public_id": Uuid::new_v4().to_string(),
                    "created_at": now,
                }
            },
        )
        .upsert(true)
        .await
        .wrap_err("Failed to record session")?;

    database
        .collection::<SessionRecord>("sessions")
        .update_one(
            doc! {
                "_id": session_id,
                "public_id": { "$exists": false },
            },
            doc! {
                "$set": {
                    "public_id": Uuid::new_v4().to_string(),
                }
            },
        )
        .await
        .wrap_err("Failed to backfill public session ID")?;

    Ok(())
}

pub async fn invalidate_user_sessions(
    database: &Database,
    redis_pool: &Pool,
    user_id: &ObjectId,
    except_session_id: Option<&str>,
) -> Result<()> {
    let filter = if let Some(except) = except_session_id {
        doc! { "user_id": user_id, "_id": { "$ne": except } }
    } else {
        doc! { "user_id": user_id }
    };

    let mut cursor = database
        .collection::<SessionRecord>("sessions")
        .find(filter.clone())
        .await
        .wrap_err("Failed to query sessions for invalidation")?;

    use futures::TryStreamExt;
    while let Some(record) = cursor.try_next().await? {
        let _: i64 = redis_pool.del(&record.id).await.unwrap_or(0);
    }

    database
        .collection::<SessionRecord>("sessions")
        .delete_many(filter)
        .await
        .wrap_err("Failed to delete session records")?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct TOTPFactor {
    pub secret: String,
    pub display_name: String,
    pub fully_enabled: bool,
}

impl TOTPFactor {
    pub fn to_public(&self) -> PublicTOTPFactor {
        PublicTOTPFactor {
            display_name: self.display_name.clone(),
            fully_enabled: self.fully_enabled,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct WebAuthnFactor {
    pub credential_id: String,
    pub serialized_key: String,
    pub display_name: String,
}

impl From<WebAuthnFactor> for Bson {
    fn from(value: WebAuthnFactor) -> Self {
        bson::to_bson(&value).unwrap()
    }
}

impl WebAuthnFactor {
    pub fn to_public(&self) -> PublicWebAuthnFactor {
        PublicWebAuthnFactor {
            credential_id: self.credential_id.clone(),
            display_name: self.display_name.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct RecoveryCodeFactor {
    pub code_hash: String,
    pub used: bool,
}

impl From<RecoveryCodeFactor> for Bson {
    fn from(value: RecoveryCodeFactor) -> Self {
        bson::to_bson(&value).unwrap()
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct PGPFactor {
    pub public_key: String,
    pub fingerprint: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, Default)]
pub struct PasswordFactor {
    pub password_hash: Option<String>,
}

impl From<PGPFactor> for Bson {
    fn from(value: PGPFactor) -> Self {
        bson::to_bson(&value).unwrap()
    }
}

impl PGPFactor {
    pub fn to_public(&self) -> PublicPGPFactor {
        PublicPGPFactor {
            fingerprint: self.fingerprint.clone(),
            display_name: self.display_name.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, Default)]
pub struct RecentFactors {
    pub first_factor: Option<FirstFactor>,
    pub second_factor: Option<SecondFactor>,
}

/// Accepts both a single PGPFactor object (legacy) and a Vec<PGPFactor> (new format).
fn deserialize_pgp_factors<'de, D>(deserializer: D) -> Result<Vec<PGPFactor>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum PgpField {
        Vec(Vec<PGPFactor>),
        Single(PGPFactor),
    }

    match PgpField::deserialize(deserializer)? {
        PgpField::Vec(v) => Ok(v),
        PgpField::Single(f) => Ok(vec![f]),
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, Default)]
pub struct AuthFactors {
    pub totp: Option<TOTPFactor>,
    pub webauthn: Vec<WebAuthnFactor>,
    pub recovery_codes: Vec<RecoveryCodeFactor>,
    #[serde(deserialize_with = "deserialize_pgp_factors", default)]
    pub pgp: Vec<PGPFactor>,
    pub password: PasswordFactor,
    pub recent: RecentFactors,
}

impl AuthFactors {
    pub fn to_public(&self) -> PublicAuthFactors {
        let remaining_recovery_codes =
            self.recovery_codes.iter().filter(|code| !code.used).count() as u8;

        PublicAuthFactors {
            totp: self.totp.clone().map(|factor| factor.to_public()),
            webauthn: self
                .webauthn
                .iter()
                .map(|factor| factor.to_public())
                .collect(),
            recovery_codes: PublicRecoveryCodeFactor {
                remaining_codes: remaining_recovery_codes,
            },
            pgp: self.pgp.iter().map(|f| f.to_public()).collect(),
            password: PublicPasswordFactor {
                is_set: self.password.password_hash.is_some(),
            },
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct PublicTOTPFactor {
    pub display_name: String,
    pub fully_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, Default)]
pub struct PublicPasswordFactor {
    pub is_set: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct PublicWebAuthnFactor {
    pub credential_id: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, Default)]
pub struct PublicRecoveryCodeFactor {
    pub remaining_codes: u8,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct PublicPGPFactor {
    pub fingerprint: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, Default)]
pub struct PublicAuthFactors {
    pub totp: Option<PublicTOTPFactor>,
    pub webauthn: Vec<PublicWebAuthnFactor>,
    pub recovery_codes: PublicRecoveryCodeFactor,
    pub pgp: Vec<PublicPGPFactor>,
    pub password: PublicPasswordFactor,
    pub recent: RecentFactors,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
#[serde(rename_all = "lowercase")]
pub enum FirstFactor {
    Password,
    WebAuthnPasswordless,
    Pgp,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
#[serde(rename_all = "lowercase")]
pub enum SecondFactor {
    Totp,
    WebAuthn,
    RecoveryCode,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
#[serde(untagged)]
pub enum AnyFactor {
    First(FirstFactor),
    Second(SecondFactor),
}

impl From<FirstFactor> for AnyFactor {
    fn from(f: FirstFactor) -> Self {
        AnyFactor::First(f)
    }
}

impl From<SecondFactor> for AnyFactor {
    fn from(s: SecondFactor) -> Self {
        AnyFactor::Second(s)
    }
}

impl From<AnyFactor> for Bson {
    fn from(value: AnyFactor) -> Self {
        Bson::String(serde_plain::to_string(&value).unwrap())
    }
}

database_object!(User {
    #[serde(rename = "_id", with = "object_id_as_string_required")]
    #[schema(value_type = String)]
    id: ObjectId,
    uuid: Uuid,
    first_name: String,
    last_name: String,
    display_name: String,
    preferred_username: String,
    email: String,
    #[serde(default)]
    email_confirmed: bool,
    auth_factors: AuthFactors,

    #[serde(with = "vec_oid_to_vec_string")]
    #[schema(value_type = Vec<String>)]
    groups: Vec<ObjectId>,
});

#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ClientType {
    Public,
    Confidential,
}

database_object!(Application {
    #[serde(rename = "_id", with = "object_id_as_string_required")]
    #[schema(value_type = String)]
    id: ObjectId,
    name: String,
    slug: String,
    icon: Option<String>,
    client_type: ClientType,
    client_id: String,
    client_secret: Option<String>,
    redirect_uris: Vec<String>,

    #[serde(with = "vec_oid_to_vec_string")]
    #[schema(value_type = Vec<String>)]
    allowed_groups: Vec<ObjectId>,
});

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, Partial, Validate)]
#[partial(
    "EditApplicationBody",
    omit(id, client_id),
    derive(Debug, Serialize, Deserialize, ToSchema, Clone, Validate)
)]
pub struct PublicApplication {
    #[serde(rename = "_id", with = "object_id_as_string_required")]
    #[schema(value_type = String)]
    pub id: ObjectId,

    #[validate(length(min = 1, max = 32))]
    pub name: String,

    #[validate(custom(function = "slug_validator"), length(min = 1, max = 32))]
    pub slug: String,

    #[validate(length(min = 1, max = 256))]
    pub icon: Option<String>,

    pub client_type: ClientType,

    pub client_id: String,

    pub redirect_uris: Vec<String>,

    #[serde(with = "vec_oid_to_vec_string")]
    #[schema(value_type = Vec<String>)]
    pub allowed_groups: Vec<ObjectId>,
}

impl Application {
    pub fn to_public(&self) -> PublicApplication {
        PublicApplication {
            id: self.id,
            name: self.name.clone(),
            slug: self.slug.clone(),
            icon: self.icon.clone(),
            client_type: self.client_type.clone(),
            client_id: self.client_id.clone(),
            redirect_uris: self.redirect_uris.clone(),
            allowed_groups: self.allowed_groups.clone(),
        }
    }
}

pub async fn get_user(
    database: &Database,
    username_or_email: &str,
) -> std::result::Result<Option<User>, mongodb::error::Error> {
    database
        .collection::<User>("users")
        .find_one(doc! {
            "$or": [
                { "preferred_username": username_or_email },
                { "email": username_or_email }
            ]
        })
        .await
}

pub async fn get_user_by_id(
    database: &Database,
    user_id: &ObjectId,
) -> std::result::Result<Option<User>, mongodb::error::Error> {
    database
        .collection::<User>("users")
        .find_one(doc! { "_id": user_id })
        .await
}

pub async fn get_user_by_uuid(
    database: &Database,
    uuid: &uuid::Uuid,
) -> std::result::Result<Option<User>, mongodb::error::Error> {
    database
        .collection::<User>("users")
        .find_one(doc! { "uuid": bson::Binary { subtype: bson::spec::BinarySubtype::Generic, bytes: uuid.as_bytes().to_vec() } })
        .await
}

pub fn get_second_factors(user: &User) -> Vec<SecondFactor> {
    let mut second_factors = vec![];

    if !user.auth_factors.webauthn.is_empty() {
        second_factors.push(SecondFactor::WebAuthn);
    }

    if user
        .auth_factors
        .totp
        .clone()
        .is_some_and(|totp| totp.fully_enabled)
    {
        second_factors.push(SecondFactor::Totp);
    }

    if !user.auth_factors.recovery_codes.is_empty() {
        second_factors.push(SecondFactor::RecoveryCode);
    }

    second_factors
}

pub async fn set_recent_factor(
    database: &Database,
    user_id: &ObjectId,
    factor: AnyFactor,
) -> AxumResult<()> {
    let update_key = match &factor {
        AnyFactor::First(_) => "auth_factors.recent.first_factor",
        AnyFactor::Second(_) => "auth_factors.recent.second_factor",
    };

    database
        .collection::<User>("users")
        .update_one(
            doc! { "_id": user_id },
            doc! {
                "$set": {
                    update_key: factor
                }
            },
        )
        .await
        .wrap_err("Failed to update recent factor")?;

    Ok(())
}
