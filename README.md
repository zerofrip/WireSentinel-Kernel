# WireSentinel Guardian — Kernel Enforcement Platform

Windows kernel-mode companion to [WireSentinel Core](https://github.com/WireSentinel/WireSentinel). Provides KMDF + WFP callout enforcement for application firewall, split tunneling, kill switch, and DNS observation.

## Requirements

- Windows 10 / 11 / Server 2022
- Visual Studio 2022 + WDK 10.0.22621+
- Rust toolchain (usermode controller + tests)

## Build

```powershell
.\scripts\build.ps1 -Configuration Release -Platform x64
```

ARM64: `-Platform ARM64`

## Install (test signing)

```powershell
bcdedit /set testsigning on
pnputil /add-driver guardian\guardian.inf /install
sc start WireSentinelGuardian
```

## Test

```powershell
.\scripts\run-tests.ps1
```

## Architecture

See [docs/architecture.md](docs/architecture.md).

## Core integration

Set `wfp_engine_impl=kernel` in WireSentinel Core. The `guardian-controller` crate implements the `WfpEngine` trait via IOCTL.

## License

Apache-2.0
