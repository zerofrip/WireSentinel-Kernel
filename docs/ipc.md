# Guardian IPC Protocol

## Transport

- **Device**: `\\.\WireSentinelGuardian`
- **Method**: `DeviceIoControl` only (`METHOD_BUFFERED`)
- **ACL**: LocalSystem + Administrators

## IOCTL device type

`0x8010`

## IOCTL codes

| IOCTL | Code | Input | Output |
|-------|------|-------|--------|
| `GET_DRIVER_STATE` | 0x800 | — | `GUARDIAN_DRIVER_STATE_V1` |
| `SET_APP_POLICY` | 0x801 | `GUARDIAN_APP_POLICY_V1` | — |
| `SYNC_POLICIES` | 0x802 | `GUARDIAN_SYNC_POLICIES_V1` | — |
| `SET_ROUTE` | 0x803 | `GUARDIAN_ROUTE_ASSIGNMENT_V1` | — |
| `CLEAR_ROUTE` | 0x804 | 16-byte UUID | — |
| `SYNC_ROUTES` | 0x805 | `GUARDIAN_SYNC_ROUTES_V1` | — |
| `SET_KILL_SWITCH` | 0x806 | `GUARDIAN_KILL_SWITCH_V1` | — |
| `GET_TELEMETRY` | 0x807 | — | `GUARDIAN_TELEMETRY_V1` |
| `EXPORT_STATE` | 0x808 | — | state blob header |
| `IMPORT_STATE` | 0x809 | state blob | — |
| `RECONCILE` | 0x80A | optional filter IDs | `GUARDIAN_RECONCILE_RESPONSE_V1` |
| `DNS_SET_CONFIG` | 0x80B | `GUARDIAN_DNS_CONFIG_V1` | — |
| `GET_PERF_STATS` | 0x80C | — | `GUARDIAN_PERF_STATS_V1` |
| `GET_DNS_STATS` | 0x80D | — | `GUARDIAN_DNS_STATS_V1` |

## GuardianMessage header

All payloads are versioned. Header layout (`GUARDIAN_MESSAGE_HEADER`):

| Field | Type | Description |
|-------|------|-------------|
| Version | UINT32 | Protocol version (1) |
| MessageType | UINT32 | See `guardian_message.h` |
| PayloadBytes | UINT32 | Payload size |
| SequenceId | UINT32 | Monotonic sequence |
| RequestId | UINT64 | Correlation id |

## Versioning

- Bump struct `Version` field on breaking layout changes
- Kernel rejects unknown versions with `STATUS_INVALID_PARAMETER`
- Rust client: `guardian-controller` crate mirrors C layouts

## Security

See [security.md](security.md).
