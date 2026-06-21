# WFP Callouts

## Registered callouts

| GUID suffix | Layer | Handler |
|-------------|-------|---------|
| AuthConnectV4 | `FWPM_LAYER_ALE_AUTH_CONNECT_V4` | `GuardianAuthConnectClassifyV4` |
| AuthConnectV6 | `FWPM_LAYER_ALE_AUTH_CONNECT_V6` | `GuardianAuthConnectClassifyV6` |
| FlowEstablishedV4 | `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4` | `GuardianFlowEstablishedClassify` |
| FlowEstablishedV6 | `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6` | `GuardianFlowEstablishedClassify` |
| DnsDatagramV4/V6 | `FWPM_LAYER_DATAGRAM_DATA_*` | observe-only (Phase 8-I) |

GUIDs are defined in `shared/ids/guardian_guids.h`.

## Classify flow

```mermaid
flowchart TD
    A[AuthConnect classify] --> B{Kill switch?}
    B -->|BlockAll| X[BLOCK]
    B -->|AllowVpnOnly| V{On VPN LUID?}
    V -->|no| X
    V -->|yes| P[PERMIT]
    B -->|off| C[App policy lookup]
    C --> D[Route lookup]
    D --> E{Action}
    E -->|Block| X
    E -->|Route| P
    E -->|Observe/Allow| P
```

## Action matrix

| Policy action | WFP result |
|---------------|------------|
| Allow | PERMIT |
| Block | BLOCK + ABSORB |
| Route | PERMIT (interface bind via route table) |
| Observe | PERMIT + telemetry |

## Userspace filter registration

Core opens an FWPM session and adds filters referencing Guardian callout GUIDs. Kernel registers callouts via `FwpsCalloutRegister1`; userspace adds filters via `FwpmCalloutAdd0` + `FwpmFilterAdd0`.

## Telemetry

Each classify records action type and sampled latency via `KernelTelemetryRecordClassify`.
