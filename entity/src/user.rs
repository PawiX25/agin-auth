use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub uuid: Uuid,
    pub first_name: String,
    pub last_name: String,
    pub display_name: String,
    pub preferred_username: String,
    pub email: String,
    pub is_admin: bool,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::auth_method::Entity")]
    AuthMethods,
    #[sea_orm(has_one = "super::password::Entity")]
    Password,
    #[sea_orm(has_one = "super::totp::Entity")]
    Totp,
    #[sea_orm(has_many = "super::webauthn::Entity")]
    Webauthn,
    #[sea_orm(has_many = "super::pgp::Entity")]
    Pgp,
    #[sea_orm(has_many = "super::recovery_code::Entity")]
    RecoveryCodes,
    #[sea_orm(has_many = "super::session::Entity")]
    Sessions,
}

impl Related<super::auth_method::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AuthMethods.def()
    }
}

impl Related<super::password::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Password.def()
    }
}

impl Related<super::totp::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Totp.def()
    }
}

impl Related<super::webauthn::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Webauthn.def()
    }
}

impl Related<super::pgp::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Pgp.def()
    }
}

impl Related<super::recovery_code::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RecoveryCodes.def()
    }
}

impl Related<super::session::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sessions.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
