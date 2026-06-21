use crate::types::*;

#[derive(Debug, thiserror::Error)]
pub enum GuardianError {
    #[error("Guardian driver requires Windows")]
    NotWindows,
}

pub struct GuardianDevice;

impl GuardianDevice {
    pub fn open() -> Result<Self, GuardianError> {
        Err(GuardianError::NotWindows)
    }
}

pub struct GuardianClient;

impl GuardianClient {
    pub fn connect() -> Result<Self, GuardianError> {
        Err(GuardianError::NotWindows)
    }
}
