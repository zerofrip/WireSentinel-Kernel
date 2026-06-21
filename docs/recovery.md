# Driver Recovery

## Scenarios

| Event | Guardian behavior |
|-------|-------------------|
| Driver reload | `RecoveryGeneration++`, state = Recovering |
| Core service restart | Kill switch persisted in registry; policies re-imported via IOCTL |
| Orphan WFP filters | `IOCTL_GUARDIAN_RECONCILE` removes unknown filter IDs |
| Userspace crash | Kill switch remains active in kernel |

## Startup sequence

1. `DriverEntry` → initialize subsystems
2. `GuardianCreateDevice` → IOCTL endpoint
3. `GuardianCalloutManagerRegister` → WFP callouts
4. `GuardianRecoveryManagerBegin` → increment generation, orphan scan
5. State = `Running` (awaits Core `IMPORT_STATE` / `SYNC_*`)

## Core integration

WireSentinel Core `WfpLifecycleManager::reconcile` mirrors kernel reconcile:

```
Core startup
  → KernelCalloutEngine::init()
  → sync_rules / sync_routes from SQLite
  → IOCTL_GUARDIAN_RECONCILE with known filter IDs
  → emit DriverRecovered or DriverRecoveryFailed
```

## Registry keys

`HKLM\SYSTEM\CurrentControlSet\Services\WireSentinelGuardian\Parameters\`

| Value | Purpose |
|-------|---------|
| `KillSwitchMode` | Persisted kill switch |
| `RecoveryGeneration` | Crash recovery marker |

## Events

Core `ServiceEvent`:

- `DriverRecovered` — reconcile succeeded
- `DriverRecoveryFailed` — reconcile or import failed
