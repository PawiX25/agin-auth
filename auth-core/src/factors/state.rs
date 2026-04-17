use std::{fmt::Debug, marker::PhantomData};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tower_sessions_core::Session;

/// State accessed during the authentication flow for this factor.
///
/// Keys are stored as `factors::{factor_name}::state` in the session.
pub struct FactorState<T>
where
    T: Send + Sync + Clone + Debug + Serialize + for<'de> Deserialize<'de>,
{
    factor_name: &'static str,
    _state: PhantomData<T>,
}

#[derive(Error, Debug)]
pub enum FactorStateError {
    #[error(transparent)]
    SessionError(#[from] tower_sessions_core::session::Error),
}

impl<T> FactorState<T>
where
    T: Send + Sync + Clone + Debug + Serialize + for<'de> Deserialize<'de>,
{
    pub const fn new(factor_name: &'static str) -> Self {
        Self {
            factor_name,
            _state: PhantomData,
        }
    }

    fn storage_key(&self) -> String {
        format!("factors::{}::state", &self.factor_name)
    }

    pub async fn get(&self, session: &Session) -> Result<Option<T>, FactorStateError> {
        let result = session.get(&self.storage_key()).await?;
        Ok(result)
    }

    pub async fn set(&self, session: &Session, data: T) -> Result<(), FactorStateError> {
        session.insert(&self.storage_key(), data).await?;
        Ok(())
    }

    pub async fn remove(&self, session: &Session) -> Result<Option<T>, FactorStateError> {
        let value = session.remove(&self.storage_key()).await?;
        Ok(value)
    }
}
