# Security

## Threat model

### In scope

- Malicious userspace processes attempting to modify enforcement policy
- IOCTL buffer overflows and integer overflows
- Privilege escalation via device handle

### Out of scope (Core responsibility)

- Policy content validation (malicious rules from UI/API)
- VPN credential protection
- DNS content filtering logic

## Controls

| Control | Implementation |
|---------|----------------|
| Device ACL | `SDDL_DEVOBJ_SYS_ALL_ADM_RWX` — only LocalSystem and Administrators |
| IOCTL validation | `GuardianValidateIoctlBuffer` — size, version, bounds |
| Transfer method | `METHOD_BUFFERED` only — no `METHOD_NEITHER` |
| Caller verification | Optional service PID check on policy IOCTLs |
| Driver signing | Authenticode EV + WHQL path via `scripts/sign.ps1` |

## Fail-open vs fail-closed

| Scenario | Behavior |
|----------|----------|
| Classify internal error | PERMIT (log + telemetry error) |
| Kill switch BlockAll | BLOCK all connections |
| Invalid IOCTL | reject with NTSTATUS |
| Unsigned driver (production) | Windows Code Integrity blocks load |

## Least privilege

- Guardian device is not accessible to standard users
- No raw sockets or named pipes
- Kernel modules use non-paged pool with pool tag `dnrG`

## Recommendations

1. Ship only EV-signed `.sys` in production installers
2. Enable Core validation check for `wfp_engine_impl=kernel`
3. Monitor `PluginSecurityViolation`-class events for IOCTL reject counts
