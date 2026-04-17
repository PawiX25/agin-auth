use std::fmt::Debug;

use serde::{Deserialize, Serialize};

mod private {
    pub trait Sealed {}
}

pub trait IdLike:
    Clone
    + Copy
    + PartialEq
    + Eq
    + Debug
    + Serialize
    + for<'de> Deserialize<'de>
    + private::Sealed
{
    fn as_i32(&self) -> i32;
}

/// Flow state indicates that the user *probably* has the claimed ID.
///
/// Do **NOT** grant privileges based on this claim.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct ClaimedUserId(i32);

impl ClaimedUserId {
    pub const fn new(id: i32) -> Self {
        Self(id)
    }
}

impl IdLike for ClaimedUserId {
    fn as_i32(&self) -> i32 {
        self.0
    }
}

/// Presence of this struct implies that the user is fully authenticated.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct UserId(i32);

impl UserId {
    /// Only construct if you're certain that the user is **fully authenticated**.
    pub const fn from_verified(id: i32) -> Self {
        Self(id)
    }

    pub const fn as_i32(&self) -> i32 {
        self.0
    }
}

impl IdLike for UserId {
    fn as_i32(&self) -> i32 {
        self.0
    }
}

impl private::Sealed for ClaimedUserId {}
impl private::Sealed for UserId {}
