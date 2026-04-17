use serde::{Deserialize, Serialize};

use crate::ClaimedUserId;

/// A list of claims made by the user and proved by the factor.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct FlowClaims {
    pub user_id: Option<ClaimedUserId>,
}
