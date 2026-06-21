# WireSentinel Guardian — Architecture

## Overview

Guardian.sys is the kernel enforcement layer for WireSentinel. It does **not** replace Core policy evaluation — Core decides routes; Guardian enforces them at WFP classify time.

## Layers

```
WireSentinel Core (userspace)
  PolicyEngine → SplitTunnelEngine → KernelCalloutEngine
        ↓ DeviceIoControl
Guardian.sys (kernel)
  IOCTL → ApplicationPolicyEngine / RouteAssignment / KillSwitch
  WFP Callouts → classify → Permit / Block / Route
```

## Modules

| Path | Responsibility |
|------|----------------|
| `driver/guardian/` | KMDF DriverEntry, control device, lifecycle |
| `driver/callouts/` | WFP callout registration and classify |
| `driver/classify/` | Connection classification orchestration |
| `driver/policy/` | Per-app policy table |
| `driver/route/` | Per-app route assignments |
| `driver/killswitch/` | Kernel kill switch modes |
| `driver/state/` | In-memory state + export/import |
| `driver/ipc/` | IOCTL dispatch + validation |
| `driver/telemetry/` | Per-CPU counters and latency |
| `driver/recovery/` | Orphan cleanup and reconcile |
| `driver/filters/` | Future NDIS filter stubs |
| `shared/` | Kernel/userspace protocol headers |
| `usermode/controller/` | Rust IOCTL client |

## WFP Callouts

- `ALE_AUTH_CONNECT_V4/V6` — primary enforcement
- `ALE_FLOW_ESTABLISHED_V4/V6` — flow telemetry
- `DATAGRAM_DATA_V4/V6` — DNS observe-only (Phase 8-I)

## Future extensions

- NDIS lightweight filters (`driver/filters/`)
- DPI engines (packet inspection hooks in `classify/`)
- Mixnet routing (new route kinds)
- Enterprise policy distribution via Core sync IOCTLs

## Platform support

| OS | Arch | Status |
|----|------|--------|
| Windows 10 | x64 | Supported |
| Windows 11 | x64 | Supported |
| Windows Server 2022 | x64 | Supported |
| ARM64 | arm64 | Build-ready |
