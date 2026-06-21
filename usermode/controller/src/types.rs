//! Binary layouts — mirrors `shared/structures/*.h`.

use std::mem::size_of;

pub const GUARDIAN_DRIVER_STATE_VERSION: u32 = 1;
pub const GUARDIAN_APP_POLICY_VERSION: u32 = 1;
pub const GUARDIAN_ROUTE_ASSIGNMENT_VERSION: u32 = 1;
pub const GUARDIAN_ROUTE_ASSIGNMENT_V2_VERSION: u32 = 2;
pub const GUARDIAN_KILL_SWITCH_VERSION: u32 = 1;
pub const GUARDIAN_TELEMETRY_VERSION: u32 = 1;
pub const GUARDIAN_PERF_STATS_VERSION: u32 = 1;
pub const GUARDIAN_DNS_CONFIG_VERSION: u32 = 1;
pub const GUARDIAN_STATE_BLOB_VERSION: u32 = 1;

pub const GUARDIAN_MAX_EXE_PATH_CHARS: usize = 520;
pub const GUARDIAN_MAX_PACKAGE_FAMILY_CHARS: usize = 128;
pub const GUARDIAN_SHA256_BYTES: usize = 32;
pub const GUARDIAN_MAX_SID_BYTES: usize = 68;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianLifecycleState {
    Stopped = 0,
    Starting = 1,
    Running = 2,
    Recovering = 3,
    Failed = 4,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianMode {
    Wfp = 0,
    Ndis = 1,
    Hybrid = 2,
}

impl GuardianMode {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(GuardianMode::Wfp),
            1 => Some(GuardianMode::Ndis),
            2 => Some(GuardianMode::Hybrid),
            _ => None,
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct GuardianDriverStateV1 {
    pub version: u32,
    pub version_major: u32,
    pub version_minor: u32,
    pub version_patch: u32,
    pub build_stamp: u32,
    pub lifecycle_state: u32,
    pub callouts_registered: u32,
    pub filter_count: u32,
    pub recovery_generation: u32,
    pub kill_switch_mode: u32,
    pub last_error: i32,
    pub guardian_mode: u32,
    pub reserved: [u8; 12],
}

impl GuardianDriverStateV1 {
    pub const SIZE: usize = size_of::<Self>();

    pub fn mode(&self) -> Option<GuardianMode> {
        GuardianMode::from_u32(self.guardian_mode)
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianPolicyAction {
    Allow = 0,
    Block = 1,
    Route = 2,
    Observe = 3,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianPolicyMatchKind {
    None = 0,
    ProcessPath = 1,
    ExeHash = 2,
    Sid = 3,
    PackageFamily = 4,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct GuardianAppPolicyV1 {
    pub version: u32,
    pub app_id: [u8; 16],
    pub action: u32,
    pub match_kind: u32,
    pub exe_path_length_chars: u32,
    pub exe_path: [u16; GUARDIAN_MAX_EXE_PATH_CHARS],
    pub exe_hash_sha256: [u8; GUARDIAN_SHA256_BYTES],
    pub sid_length_bytes: u32,
    pub sid_bytes: [u8; GUARDIAN_MAX_SID_BYTES],
    pub package_family_name: [u16; GUARDIAN_MAX_PACKAGE_FAMILY_CHARS],
    pub profile_id: u64,
    pub interface_luid: u64,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianRouteKind {
    Direct = 0,
    Vpn = 1,
    Tailnet = 2,
    Tor = 3,
    Anonymous = 4,
    Blocked = 5,
    Proxy = 6,
    Chain = 7,
    Katzenpost = 8,
    Loopix = 9,
    FederatedMixnet = 10,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct GuardianRouteAssignmentV1 {
    pub version: u32,
    pub app_id: [u8; 16],
    pub route_kind: u32,
    pub profile_id: u64,
    pub interface_luid: u64,
    pub socks_port: u16,
    pub reserved: [u8; 6],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct GuardianRouteAssignmentV2 {
    pub version: u32,
    pub app_id: [u8; 16],
    pub route_kind: u32,
    pub profile_id: u64,
    pub interface_luid: u64,
    pub socks_port: u16,
    pub reserved: [u8; 6],
    pub mixnet_profile_id: u64,
    pub transform_profile: u32,
    pub reserved2: [u8; 4],
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianKillSwitchMode {
    Off = 0,
    BlockAll = 1,
    AllowVpnOnly = 2,
    Restore = 3,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct GuardianKillSwitchV1 {
    pub version: u32,
    pub mode: u32,
    pub vpn_interface_luid: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GuardianTelemetryV1 {
    pub version: u32,
    pub classify_count: u64,
    pub block_count: u64,
    pub route_count: u64,
    pub permit_count: u64,
    pub observe_count: u64,
    pub error_count: u64,
    pub dns_observe_count: u64,
    pub avg_classify_latency_100ns: u64,
    pub max_classify_latency_100ns: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GuardianPerfStatsV1 {
    pub version: u32,
    pub ipc_dispatch_count: u64,
    pub ipc_reject_count: u64,
    pub avg_ipc_latency_100ns: u64,
    pub max_ipc_latency_100ns: u64,
    pub deferred_work_count: u64,
    pub active_policy_count: u32,
    pub active_route_count: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct GuardianDnsConfigV1 {
    pub version: u32,
    pub capabilities: u32,
    pub enabled: u8,
    pub observe_only: u8,
    pub reserved: [u8; 2],
    pub proxy_port: u16,
    pub excluded_pid_count: u32,
    pub excluded_pids: [u32; 16],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GuardianDnsStatsV1 {
    pub version: u32,
    pub observed_v4: u64,
    pub observed_v6: u64,
    pub skipped_loopback: u64,
    pub skipped_excluded: u64,
    pub skipped_disabled: u64,
    pub errors: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct GuardianStateBlobHeaderV1 {
    pub version: u32,
    pub policy_count: u32,
    pub route_count: u32,
    pub kill_switch_mode: u32,
    pub recovery_generation: u32,
    pub reserved: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GuardianReconcileResponseV1 {
    pub version: u32,
    pub removed_orphans: u32,
    pub recovery_generation: u32,
    pub recovery_status: u32,
}

pub fn uuid_to_bytes(id: uuid::Uuid) -> [u8; 16] {
    *id.as_bytes()
}

pub fn wide_path_bytes(path: &str) -> ([u16; GUARDIAN_MAX_EXE_PATH_CHARS], u32) {
    let mut buf = [0u16; GUARDIAN_MAX_EXE_PATH_CHARS];
    let units: Vec<u16> = path.encode_utf16().collect();
    let len = units.len().min(GUARDIAN_MAX_EXE_PATH_CHARS);
    buf[..len].copy_from_slice(&units[..len]);
    (buf, len as u32)
}

impl GuardianAppPolicyV1 {
    pub fn new_block(app_id: uuid::Uuid, exe_path: &str) -> Self {
        let (exe_path_buf, len) = wide_path_bytes(exe_path);
        Self {
            version: GUARDIAN_APP_POLICY_VERSION,
            app_id: uuid_to_bytes(app_id),
            action: GuardianPolicyAction::Block as u32,
            match_kind: GuardianPolicyMatchKind::ProcessPath as u32,
            exe_path_length_chars: len,
            exe_path: exe_path_buf,
            exe_hash_sha256: [0; GUARDIAN_SHA256_BYTES],
            sid_length_bytes: 0,
            sid_bytes: [0; GUARDIAN_MAX_SID_BYTES],
            package_family_name: [0; GUARDIAN_MAX_PACKAGE_FAMILY_CHARS],
            profile_id: 0,
            interface_luid: 0,
        }
    }
}

impl GuardianRouteAssignmentV1 {
    pub fn new_vpn(app_id: uuid::Uuid, profile_id: u64, interface_luid: u64) -> Self {
        Self {
            version: GUARDIAN_ROUTE_ASSIGNMENT_VERSION,
            app_id: uuid_to_bytes(app_id),
            route_kind: GuardianRouteKind::Vpn as u32,
            profile_id,
            interface_luid,
            socks_port: 0,
            reserved: [0; 6],
        }
    }

    pub fn new_proxy(app_id: uuid::Uuid, profile_id: u64, socks_port: u16) -> Self {
        Self {
            version: GUARDIAN_ROUTE_ASSIGNMENT_VERSION,
            app_id: uuid_to_bytes(app_id),
            route_kind: GuardianRouteKind::Proxy as u32,
            profile_id,
            interface_luid: 0,
            socks_port,
            reserved: [0; 6],
        }
    }

    pub fn new_proxy_chain(app_id: uuid::Uuid, chain_id: u64, socks_port: u16) -> Self {
        Self {
            version: GUARDIAN_ROUTE_ASSIGNMENT_VERSION,
            app_id: uuid_to_bytes(app_id),
            route_kind: GuardianRouteKind::Chain as u32,
            profile_id: chain_id,
            interface_luid: 0,
            socks_port,
            reserved: [0; 6],
        }
    }
}

impl GuardianKillSwitchV1 {
    pub fn block_all() -> Self {
        Self {
            version: GUARDIAN_KILL_SWITCH_VERSION,
            mode: GuardianKillSwitchMode::BlockAll as u32,
            vpn_interface_luid: 0,
        }
    }

    pub fn restore() -> Self {
        Self {
            version: GUARDIAN_KILL_SWITCH_VERSION,
            mode: GuardianKillSwitchMode::Restore as u32,
            vpn_interface_luid: 0,
        }
    }
}
