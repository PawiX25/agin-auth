pub mod state;

use std::fmt::Debug;

use async_trait::async_trait;
use color_eyre::eyre::Error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

use crate::FlowClaims;

#[derive(Debug, Error, ToSchema)]
#[schema(as = String)]
pub enum FactorError {
    #[error("Factor is not enabled")]
    NotEnabled,

    #[error(transparent)]
    #[schema(value_type = String)]
    Unauthorized(Error),

    #[error(transparent)]
    #[schema(value_type = String)]
    BadRequest(Error),

    #[error(transparent)]
    #[schema(value_type = String)]
    Other(#[from] Error),
}

#[derive(Debug, Error, ToSchema)]
pub enum FactorEnableError {
    #[error("Factor is already enabled")]
    AlreadyEnabled,

    #[error(transparent)]
    Other(#[from] FactorError),
}

#[derive(Debug, Error, ToSchema)]
pub enum FactorDisableError {
    #[error("Factor is not enabled")]
    NotEnabled,

    #[error("Cannot disable the only primary factor")]
    CannotDisableOnlyPrimary,

    #[error(transparent)]
    Other(#[from] FactorError),
}

/// Defines the type of authentication flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowType {
    /// A straightforward flow where the user provides credentials and gets authenticated in a single step.
    Simple,
    /// A multi-step flow that involves providing a challenge by the `Factor` and receiving a response from the user to complete authentication.
    RoundTrip,
}

/// Defines the security level provided by an authentication factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityLevel {
    /// A password or similar knowledge-based factor.
    Knowledge = 0,
    /// A factor that relies on an external channel, such as SMS or email codes.
    OutOfBand = 1,
    /// A possession-based software-backed factor, such as TOTP.
    Possession = 2,
    /// A possession-based hardware-backed factor, such as hardware security keys.
    Hardware = 3,
}

/// Defines if the factor is sufficient alone or requires other factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FactorRole {
    /// Can be used alone as the first/primary authentication factor.
    Primary,
    /// Can only be used as an additional factor, never alone.
    MultiFactorOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EnableResponse<T> {
    pub requires_confirmation: bool,
    pub enabled: bool,
    #[serde(flatten)]
    pub data: T,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfirmEnableResponse<T> {
    pub enabled: bool,
    #[serde(flatten)]
    pub data: T,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthenticateResponse<T> {
    pub fully_authenticated: bool,

    #[schema(value_type = ())]
    #[serde(skip)]
    pub claims: FlowClaims,

    #[serde(flatten)]
    pub data: T,
}

/// Use this struct in places that you would normally use `()`,
/// but you're unable to due to unsatisfied trait bounds.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NoData;

/// Defines metadata for the factor. `PolicyEngine` relies on this data.
pub trait FactorMetadata {
    const FLOW_TYPE: FlowType;
    const SECURITY_LEVEL: SecurityLevel;
    const ROLE: FactorRole;
}

/// Allows dynamic access to properties defined in [`FactorMetadata`].
pub trait FactorMetadataDynamic {
    fn flow_type(&self) -> FlowType;
    fn security_level(&self) -> SecurityLevel;
    fn role(&self) -> FactorRole;
}

impl<T: FactorMetadata> FactorMetadataDynamic for T {
    fn flow_type(&self) -> FlowType {
        Self::FLOW_TYPE
    }

    fn security_level(&self) -> SecurityLevel {
        Self::SECURITY_LEVEL
    }

    fn role(&self) -> FactorRole {
        Self::ROLE
    }
}

/// Defines [`Factor`]'s slug. Implemented automatically by the proc macro.
pub trait FactorSlug {
    const SLUG: &'static str;
}

/// Allows dynamic access to properties defined in [`FactorSlug`].
pub trait FactorSlugDynamic {
    fn slug(&self) -> &'static str;
}

impl<T: FactorSlug> FactorSlugDynamic for T {
    fn slug(&self) -> &'static str {
        Self::SLUG
    }
}

/// Defines the interface for an authentication factor.
///
/// Each factor can be enabled or disabled by the user, and multiple factors can be stacked
/// together to provide multi-factor authentication (MFA).
#[async_trait]
pub trait Factor: FactorMetadata + FactorSlug {
    /// Factor configuration stored in the database.
    type Config: Send + Sync + ToSchema + Serialize + for<'de> Deserialize<'de>;

    /// State accessed during the authentication flow for this factor.
    type FactorState: Send + Sync + Clone + Debug + Serialize + for<'de> Deserialize<'de>;

    type EnableRequest: Send + Sync + ToSchema;
    type EnableResponse: Send + Sync + ToSchema;

    async fn enable(
        &self,
        args: Self::EnableRequest,
    ) -> Result<EnableResponse<Self::EnableResponse>, FactorEnableError>;

    type DisableRequest: Send + Sync + ToSchema;
    type DisableResponse: Send + Sync + ToSchema;

    async fn disable(
        &self,
        args: Self::DisableRequest,
    ) -> Result<Self::DisableResponse, FactorDisableError>;

    type AuthenticateRequest: Send + Sync + ToSchema;
    type AuthenticateResponse: Send + Sync + ToSchema;

    async fn authenticate(
        &self,
        args: Self::AuthenticateRequest,
    ) -> Result<AuthenticateResponse<Self::AuthenticateResponse>, FactorError>;
}

#[async_trait]
pub trait FactorConfirmable: Factor {
    type ConfirmEnableRequest: Send + Sync + ToSchema;
    type ConfirmEnableResponse: Send + Sync + ToSchema;

    async fn confirm_enable(
        &self,
        args: Self::ConfirmEnableRequest,
    ) -> Result<ConfirmEnableResponse<Self::ConfirmEnableResponse>, FactorEnableError>;
}

#[async_trait]
pub trait FactorChallenge: Factor {
    type ChallengeResponse: Send + Sync + ToSchema;
    type ChallengeAuthenticationResult: Send + Sync + ToSchema;

    async fn authenticate_challenge_response(
        &self,
        response: Self::ChallengeResponse,
    ) -> Result<AuthenticateResponse<Self::ChallengeAuthenticationResult>, FactorError>;
}
