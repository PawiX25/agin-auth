use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Users (must come first — most FKs reference this table)
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(pk_auto(Users::Id))
                    .col(uuid_uniq(Users::Uuid))
                    .col(string(Users::FirstName))
                    .col(string(Users::LastName))
                    .col(string(Users::DisplayName))
                    .col(string_uniq(Users::PreferredUsername))
                    .col(string_uniq(Users::Email))
                    .col(boolean(Users::EmailConfirmed))
                    .col(boolean(Users::IsAdmin))
                    .col(array_null(
                        Users::Groups,
                        ColumnType::String(StringLen::None),
                    ))
                    .col(timestamp_with_time_zone(Users::CreatedAt))
                    .to_owned(),
            )
            .await?;

        // Applications
        manager
            .create_table(
                Table::create()
                    .table(Applications::Table)
                    .if_not_exists()
                    .col(pk_auto(Applications::Id))
                    .col(string(Applications::Name))
                    .col(string_uniq(Applications::Slug))
                    .col(string_null(Applications::Icon))
                    .col(string(Applications::ClientType))
                    .col(string_uniq(Applications::ClientId))
                    .col(string_null(Applications::ClientSecret))
                    .col(array_null(
                        Applications::RedirectUris,
                        ColumnType::String(StringLen::None),
                    ))
                    .col(array_null(
                        Applications::AllowedGroups,
                        ColumnType::String(StringLen::None),
                    ))
                    .to_owned(),
            )
            .await?;

        // Password credentials
        manager
            .create_table(
                Table::create()
                    .table(PasswordCredentials::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PasswordCredentials::UserId)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(string(PasswordCredentials::PasswordHash))
                    .foreign_key(
                        ForeignKey::create()
                            .from(PasswordCredentials::Table, PasswordCredentials::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // TOTP credentials
        manager
            .create_table(
                Table::create()
                    .table(TotpCredentials::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TotpCredentials::UserId)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(string(TotpCredentials::DisplayName))
                    .col(string(TotpCredentials::Secret))
                    .col(boolean(TotpCredentials::FullyEnabled))
                    .foreign_key(
                        ForeignKey::create()
                            .from(TotpCredentials::Table, TotpCredentials::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // PGP credentials
        manager
            .create_table(
                Table::create()
                    .table(PgpCredentials::Table)
                    .if_not_exists()
                    .col(pk_auto(PgpCredentials::Id))
                    .col(integer(PgpCredentials::UserId))
                    .col(string(PgpCredentials::DisplayName))
                    .col(string(PgpCredentials::PublicKey))
                    .col(string(PgpCredentials::Fingerprint))
                    .foreign_key(
                        ForeignKey::create()
                            .from(PgpCredentials::Table, PgpCredentials::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // WebAuthn credentials
        manager
            .create_table(
                Table::create()
                    .table(WebauthnCredentials::Table)
                    .if_not_exists()
                    .col(pk_auto(WebauthnCredentials::Id))
                    .col(integer(WebauthnCredentials::UserId))
                    .col(string_uniq(WebauthnCredentials::CredentialId))
                    .col(string(WebauthnCredentials::DisplayName))
                    .col(string(WebauthnCredentials::SerializedKey))
                    .foreign_key(
                        ForeignKey::create()
                            .from(WebauthnCredentials::Table, WebauthnCredentials::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(WebauthnCredentials::Table)
                    .name("idx-webauthn-user_id")
                    .col(WebauthnCredentials::UserId)
                    .to_owned(),
            )
            .await?;

        // Recovery codes
        manager
            .create_table(
                Table::create()
                    .table(RecoveryCodeCredentials::Table)
                    .if_not_exists()
                    .col(pk_auto(RecoveryCodeCredentials::Id))
                    .col(integer(RecoveryCodeCredentials::UserId))
                    .col(string(RecoveryCodeCredentials::CodeHash))
                    .col(boolean(RecoveryCodeCredentials::Used))
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                RecoveryCodeCredentials::Table,
                                RecoveryCodeCredentials::UserId,
                            )
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Auth methods (composite PK: user_id + method_type)
        manager
            .create_table(
                Table::create()
                    .table(UserAuthMethods::Table)
                    .if_not_exists()
                    .col(integer(UserAuthMethods::UserId))
                    .col(string(UserAuthMethods::MethodType))
                    .col(boolean(UserAuthMethods::IsEnabled))
                    .col(timestamp_with_time_zone(UserAuthMethods::EnrolledAt))
                    .col(timestamp_with_time_zone(UserAuthMethods::ModifiedAt))
                    .col(timestamp_with_time_zone_null(UserAuthMethods::LastUsedAt))
                    .primary_key(
                        Index::create()
                            .col(UserAuthMethods::UserId)
                            .col(UserAuthMethods::MethodType),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UserAuthMethods::Table, UserAuthMethods::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Sessions
        manager
            .create_table(
                Table::create()
                    .table(Sessions::Table)
                    .if_not_exists()
                    .col(pk_auto(Sessions::Id))
                    .col(integer(Sessions::UserId))
                    .col(string_uniq(Sessions::SessionKey))
                    .col(uuid_uniq(Sessions::PublicId))
                    .col(string_null(Sessions::IpAddress))
                    .col(string_null(Sessions::UserAgent))
                    .col(timestamp_with_time_zone(Sessions::LastActive))
                    .col(timestamp_with_time_zone(Sessions::CreatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .from(Sessions::Table, Sessions::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Sessions::Table)
                    .name("idx-sessions-user_id")
                    .col(Sessions::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Sessions::Table)
                    .name("idx-sessions-last_active")
                    .col(Sessions::LastActive)
                    .to_owned(),
            )
            .await?;

        // Email confirmation tokens
        manager
            .create_table(
                Table::create()
                    .table(EmailConfirmationTokens::Table)
                    .if_not_exists()
                    .col(pk_auto(EmailConfirmationTokens::Id))
                    .col(string_uniq(EmailConfirmationTokens::TokenHash))
                    .col(integer(EmailConfirmationTokens::UserId))
                    .col(timestamp_with_time_zone(EmailConfirmationTokens::ExpiresAt))
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                EmailConfirmationTokens::Table,
                                EmailConfirmationTokens::UserId,
                            )
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(EmailConfirmationTokens::Table)
                    .name("idx-email_confirmation_tokens-user_id")
                    .col(EmailConfirmationTokens::UserId)
                    .to_owned(),
            )
            .await?;

        // Password reset tokens
        manager
            .create_table(
                Table::create()
                    .table(PasswordResetTokens::Table)
                    .if_not_exists()
                    .col(pk_auto(PasswordResetTokens::Id))
                    .col(string_uniq(PasswordResetTokens::TokenHash))
                    .col(integer(PasswordResetTokens::UserId))
                    .col(timestamp_with_time_zone(PasswordResetTokens::ExpiresAt))
                    .foreign_key(
                        ForeignKey::create()
                            .from(PasswordResetTokens::Table, PasswordResetTokens::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(PasswordResetTokens::Table)
                    .name("idx-password_reset_tokens-user_id")
                    .col(PasswordResetTokens::UserId)
                    .to_owned(),
            )
            .await?;

        // Authorization codes
        manager
            .create_table(
                Table::create()
                    .table(AuthorizationCodes::Table)
                    .if_not_exists()
                    .col(pk_auto(AuthorizationCodes::Id))
                    .col(string_uniq(AuthorizationCodes::CodeHash))
                    .col(string(AuthorizationCodes::ClientId))
                    .col(integer(AuthorizationCodes::UserId))
                    .col(string(AuthorizationCodes::RedirectUri))
                    .col(string(AuthorizationCodes::Scope))
                    .col(string_null(AuthorizationCodes::Nonce))
                    .col(string_null(AuthorizationCodes::CodeChallenge))
                    .col(string_null(AuthorizationCodes::CodeChallengeMethod))
                    .col(timestamp_with_time_zone(AuthorizationCodes::CreatedAt))
                    .col(boolean(AuthorizationCodes::Used))
                    .foreign_key(
                        ForeignKey::create()
                            .from(AuthorizationCodes::Table, AuthorizationCodes::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(AuthorizationCodes::Table)
                    .name("idx-authorization_codes-client_id")
                    .col(AuthorizationCodes::ClientId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(AuthorizationCodes::Table)
                    .name("idx-authorization_codes-user_id")
                    .col(AuthorizationCodes::UserId)
                    .to_owned(),
            )
            .await?;

        // Refresh tokens
        manager
            .create_table(
                Table::create()
                    .table(RefreshTokens::Table)
                    .if_not_exists()
                    .col(pk_auto(RefreshTokens::Id))
                    .col(string_uniq(RefreshTokens::TokenHash))
                    .col(string(RefreshTokens::ClientId))
                    .col(integer(RefreshTokens::UserId))
                    .col(string(RefreshTokens::Scope))
                    .col(timestamp_with_time_zone(RefreshTokens::CreatedAt))
                    .col(boolean(RefreshTokens::Revoked))
                    .foreign_key(
                        ForeignKey::create()
                            .from(RefreshTokens::Table, RefreshTokens::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(RefreshTokens::Table)
                    .name("idx-refresh_tokens-client_id")
                    .col(RefreshTokens::ClientId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(RefreshTokens::Table)
                    .name("idx-refresh_tokens-user_id")
                    .col(RefreshTokens::UserId)
                    .to_owned(),
            )
            .await?;

        // Revoked access tokens
        manager
            .create_table(
                Table::create()
                    .table(RevokedAccessTokens::Table)
                    .if_not_exists()
                    .col(pk_auto(RevokedAccessTokens::Id))
                    .col(string_uniq(RevokedAccessTokens::TokenHash))
                    .col(string(RevokedAccessTokens::ClientId))
                    .col(timestamp_with_time_zone(RevokedAccessTokens::CreatedAt))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(RevokedAccessTokens::Table)
                    .name("idx-revoked_access_tokens-client_id")
                    .col(RevokedAccessTokens::ClientId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop in reverse order of creation (respect FK dependencies)
        let tables = [
            RevokedAccessTokens::Table.into_table_ref(),
            RefreshTokens::Table.into_table_ref(),
            AuthorizationCodes::Table.into_table_ref(),
            PasswordResetTokens::Table.into_table_ref(),
            EmailConfirmationTokens::Table.into_table_ref(),
            Sessions::Table.into_table_ref(),
            UserAuthMethods::Table.into_table_ref(),
            RecoveryCodeCredentials::Table.into_table_ref(),
            WebauthnCredentials::Table.into_table_ref(),
            PgpCredentials::Table.into_table_ref(),
            TotpCredentials::Table.into_table_ref(),
            PasswordCredentials::Table.into_table_ref(),
            Applications::Table.into_table_ref(),
            Users::Table.into_table_ref(),
        ];

        for table in tables {
            manager
                .drop_table(Table::drop().table(table).to_owned())
                .await?;
        }

        Ok(())
    }
}

// Table identifiers matching entity table_name attributes

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Uuid,
    FirstName,
    LastName,
    DisplayName,
    PreferredUsername,
    Email,
    EmailConfirmed,
    IsAdmin,
    Groups,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Applications {
    Table,
    Id,
    Name,
    Slug,
    Icon,
    ClientType,
    ClientId,
    ClientSecret,
    RedirectUris,
    AllowedGroups,
}

#[derive(DeriveIden)]
enum PasswordCredentials {
    Table,
    UserId,
    PasswordHash,
}

#[derive(DeriveIden)]
enum TotpCredentials {
    Table,
    UserId,
    DisplayName,
    Secret,
    FullyEnabled,
}

#[derive(DeriveIden)]
enum PgpCredentials {
    Table,
    Id,
    UserId,
    DisplayName,
    PublicKey,
    Fingerprint,
}

#[derive(DeriveIden)]
enum WebauthnCredentials {
    Table,
    Id,
    UserId,
    CredentialId,
    DisplayName,
    SerializedKey,
}

#[derive(DeriveIden)]
enum RecoveryCodeCredentials {
    Table,
    Id,
    UserId,
    CodeHash,
    Used,
}

#[derive(DeriveIden)]
enum UserAuthMethods {
    Table,
    UserId,
    MethodType,
    IsEnabled,
    EnrolledAt,
    ModifiedAt,
    LastUsedAt,
}

#[derive(DeriveIden)]
enum Sessions {
    Table,
    Id,
    UserId,
    SessionKey,
    PublicId,
    IpAddress,
    UserAgent,
    LastActive,
    CreatedAt,
}

#[derive(DeriveIden)]
enum EmailConfirmationTokens {
    Table,
    Id,
    TokenHash,
    UserId,
    ExpiresAt,
}

#[derive(DeriveIden)]
enum PasswordResetTokens {
    Table,
    Id,
    TokenHash,
    UserId,
    ExpiresAt,
}

#[derive(DeriveIden)]
enum AuthorizationCodes {
    Table,
    Id,
    CodeHash,
    ClientId,
    UserId,
    RedirectUri,
    Scope,
    Nonce,
    CodeChallenge,
    CodeChallengeMethod,
    CreatedAt,
    Used,
}

#[derive(DeriveIden)]
enum RefreshTokens {
    Table,
    Id,
    TokenHash,
    ClientId,
    UserId,
    Scope,
    CreatedAt,
    Revoked,
}

#[derive(DeriveIden)]
enum RevokedAccessTokens {
    Table,
    Id,
    TokenHash,
    ClientId,
    CreatedAt,
}
