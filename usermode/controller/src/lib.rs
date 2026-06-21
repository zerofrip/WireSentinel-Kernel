pub mod ioctl;
pub mod protocol;
pub mod types;

#[cfg(windows)]
mod client_impl;
#[cfg(windows)]
mod device_impl;

#[cfg(not(windows))]
mod stub;

#[cfg(windows)]
pub use client_impl::{GuardianClient, GuardianError};
#[cfg(windows)]
pub use device_impl::GuardianDevice;

#[cfg(not(windows))]
pub use stub::{GuardianClient, GuardianError, GuardianDevice};

pub use types::*;
