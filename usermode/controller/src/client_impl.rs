use super::device_impl::GuardianDevice;
use crate::ioctl::*;
use crate::types::*;
use std::mem::size_of;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum GuardianError {
    #[error("failed to open Guardian device")]
    DeviceOpenFailed,
    #[error("windows API error: {0}")]
    Windows(#[from] windows::core::Error),
    #[error("ioctl returned insufficient bytes: {0}")]
    ShortRead(u32),
    #[error("invalid driver state version")]
    InvalidVersion,
}

pub struct GuardianClient {
    device: GuardianDevice,
}

impl GuardianClient {
    pub fn connect() -> Result<Self, GuardianError> {
        Ok(Self {
            device: GuardianDevice::open()?,
        })
    }

    pub fn driver_state(&self) -> Result<GuardianDriverStateV1, GuardianError> {
        let mut buf = [0u8; GuardianDriverStateV1::SIZE];
        let n = self
            .device
            .ioctl(IOCTL_GUARDIAN_GET_DRIVER_STATE, None, &mut buf)?;
        if n < GuardianDriverStateV1::SIZE as u32 {
            return Err(GuardianError::ShortRead(n));
        }
        let state =
            unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const GuardianDriverStateV1) };
        if state.version != GUARDIAN_DRIVER_STATE_VERSION {
            return Err(GuardianError::InvalidVersion);
        }
        Ok(state)
    }

    pub fn set_guardian_mode(&self, mode: GuardianMode) -> Result<(), GuardianError> {
        let bytes = (mode as u32).to_le_bytes();
        self.device
            .ioctl(IOCTL_GUARDIAN_SET_GUARDIAN_MODE, Some(&bytes), &mut [])?;
        Ok(())
    }

    pub fn set_app_policy(&self, policy: &GuardianAppPolicyV1) -> Result<(), GuardianError> {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (policy as *const GuardianAppPolicyV1) as *const u8,
                size_of::<GuardianAppPolicyV1>(),
            )
        };
        self.device
            .ioctl(IOCTL_GUARDIAN_SET_APP_POLICY, Some(bytes), &mut [])?;
        Ok(())
    }

    pub fn set_route(&self, route: &GuardianRouteAssignmentV1) -> Result<(), GuardianError> {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (route as *const GuardianRouteAssignmentV1) as *const u8,
                size_of::<GuardianRouteAssignmentV1>(),
            )
        };
        self.device
            .ioctl(IOCTL_GUARDIAN_SET_ROUTE, Some(bytes), &mut [])?;
        Ok(())
    }

    pub fn clear_route(&self, app_id: Uuid) -> Result<(), GuardianError> {
        let id = uuid_to_bytes(app_id);
        self.device
            .ioctl(IOCTL_GUARDIAN_CLEAR_ROUTE, Some(&id), &mut [])?;
        Ok(())
    }

    pub fn set_kill_switch(&self, config: &GuardianKillSwitchV1) -> Result<(), GuardianError> {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (config as *const GuardianKillSwitchV1) as *const u8,
                size_of::<GuardianKillSwitchV1>(),
            )
        };
        self.device
            .ioctl(IOCTL_GUARDIAN_SET_KILL_SWITCH, Some(bytes), &mut [])?;
        Ok(())
    }

    pub fn telemetry(&self) -> Result<GuardianTelemetryV1, GuardianError> {
        let mut buf = [0u8; size_of::<GuardianTelemetryV1>()];
        let n = self
            .device
            .ioctl(IOCTL_GUARDIAN_GET_TELEMETRY, None, &mut buf)?;
        if n < size_of::<GuardianTelemetryV1>() as u32 {
            return Err(GuardianError::ShortRead(n));
        }
        Ok(unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const GuardianTelemetryV1) })
    }

    pub fn perf_stats(&self) -> Result<GuardianPerfStatsV1, GuardianError> {
        let mut buf = [0u8; size_of::<GuardianPerfStatsV1>()];
        let n = self
            .device
            .ioctl(IOCTL_GUARDIAN_GET_PERF_STATS, None, &mut buf)?;
        if n < size_of::<GuardianPerfStatsV1>() as u32 {
            return Err(GuardianError::ShortRead(n));
        }
        Ok(unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const GuardianPerfStatsV1) })
    }

    pub fn dns_set_config(&self, config: &GuardianDnsConfigV1) -> Result<(), GuardianError> {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (config as *const GuardianDnsConfigV1) as *const u8,
                size_of::<GuardianDnsConfigV1>(),
            )
        };
        self.device
            .ioctl(IOCTL_GUARDIAN_DNS_SET_CONFIG, Some(bytes), &mut [])?;
        Ok(())
    }

    pub fn reconcile(&self) -> Result<GuardianReconcileResponseV1, GuardianError> {
        let mut out = [0u8; size_of::<GuardianReconcileResponseV1>()];
        let n = self
            .device
            .ioctl(IOCTL_GUARDIAN_RECONCILE, None, &mut out)?;
        if n < size_of::<GuardianReconcileResponseV1>() as u32 {
            return Err(GuardianError::ShortRead(n));
        }
        Ok(unsafe { std::ptr::read_unaligned(out.as_ptr() as *const GuardianReconcileResponseV1) })
    }

    pub fn export_state(&self) -> Result<GuardianStateBlobHeaderV1, GuardianError> {
        let mut buf = [0u8; size_of::<GuardianStateBlobHeaderV1>()];
        let n = self
            .device
            .ioctl(IOCTL_GUARDIAN_EXPORT_STATE, None, &mut buf)?;
        if n < size_of::<GuardianStateBlobHeaderV1>() as u32 {
            return Err(GuardianError::ShortRead(n));
        }
        Ok(unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const GuardianStateBlobHeaderV1) })
    }
}
