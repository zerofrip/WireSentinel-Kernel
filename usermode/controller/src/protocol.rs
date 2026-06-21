//! GuardianMessage header — mirrors `shared/protocol/guardian_message.h`.

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianMessageType {
    GetDriverState = 1,
    SetAppPolicy = 2,
    SyncPolicies = 3,
    SetRoute = 4,
    ClearRoute = 5,
    SyncRoutes = 6,
    SetKillSwitch = 7,
    GetTelemetry = 8,
    ExportState = 9,
    ImportState = 10,
    Reconcile = 11,
    DnsSetConfig = 12,
    GetPerfStats = 13,
    GetDnsStats = 14,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct GuardianMessageHeader {
    pub version: u32,
    pub message_type: u32,
    pub payload_bytes: u32,
    pub sequence_id: u32,
    pub request_id: u64,
}
