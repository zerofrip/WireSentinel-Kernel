//! Integration tests for Guardian.sys — require loaded driver on Windows.

mod bench_ipc;
mod hybrid;
mod security;

use guardian_controller::GuardianKillSwitchV1;

#[test]
#[cfg(not(windows))]
fn protocol_types_compile_on_non_windows() {
    let _ = GuardianKillSwitchV1::block_all();
}

#[test]
#[cfg(windows)]
fn driver_load_state() {
    use guardian_controller::{GuardianClient, GuardianLifecycleState};
    let client = match GuardianClient::connect() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Guardian driver not loaded — skipping");
            return;
        }
    };
    let state = client.driver_state().expect("driver state");
    assert_eq!(state.version, 1);
    assert!(
        state.lifecycle_state == GuardianLifecycleState::Running as u32
            || state.lifecycle_state == GuardianLifecycleState::Recovering as u32
    );
}

#[test]
#[cfg(windows)]
fn ipc_roundtrip_policy_route_killswitch() {
    use guardian_controller::{GuardianAppPolicyV1, GuardianClient};
    use uuid::Uuid;
    let client = match GuardianClient::connect() {
        Ok(c) => c,
        Err(_) => return,
    };

    let app_id = Uuid::new_v4();
    let policy = GuardianAppPolicyV1::new_block(app_id, "C:\\Windows\\System32\\cmd.exe");
    client.set_app_policy(&policy).expect("set policy");

    let route = guardian_controller::GuardianRouteAssignmentV1::new_vpn(app_id, 1, 42);
    client.set_route(&route).expect("set route");

    client
        .set_kill_switch(&GuardianKillSwitchV1::block_all())
        .expect("kill switch");

    let telemetry = client.telemetry().expect("telemetry");
    assert!(telemetry.version >= 1);

    client
        .set_kill_switch(&GuardianKillSwitchV1::restore())
        .expect("restore");

    client.clear_route(app_id).expect("clear route");
}

#[test]
#[cfg(windows)]
fn dns_observe_config() {
    use guardian_controller::{GuardianClient, GuardianDnsConfigV1, GUARDIAN_DNS_CONFIG_VERSION};
    let client = match GuardianClient::connect() {
        Ok(c) => c,
        Err(_) => return,
    };

    let config = GuardianDnsConfigV1 {
        version: GUARDIAN_DNS_CONFIG_VERSION,
        capabilities: 1,
        enabled: 1,
        observe_only: 1,
        reserved: [0; 2],
        proxy_port: 5353,
        excluded_pid_count: 0,
        excluded_pids: [0; 16],
    };
    client.dns_set_config(&config).expect("dns config");
}

#[test]
#[cfg(windows)]
fn recovery_reconcile() {
    use guardian_controller::GuardianClient;
    let client = match GuardianClient::connect() {
        Ok(c) => c,
        Err(_) => return,
    };
    let response = client.reconcile().expect("reconcile");
    assert_eq!(response.version, 1);
}

#[test]
fn ioctl_codes_unique() {
    use guardian_controller::ioctl::*;
    let codes = [
        IOCTL_GUARDIAN_GET_DRIVER_STATE,
        IOCTL_GUARDIAN_SET_APP_POLICY,
        IOCTL_GUARDIAN_SYNC_POLICIES,
        IOCTL_GUARDIAN_SET_ROUTE,
        IOCTL_GUARDIAN_CLEAR_ROUTE,
        IOCTL_GUARDIAN_SYNC_ROUTES,
        IOCTL_GUARDIAN_SET_KILL_SWITCH,
        IOCTL_GUARDIAN_GET_TELEMETRY,
        IOCTL_GUARDIAN_EXPORT_STATE,
        IOCTL_GUARDIAN_IMPORT_STATE,
        IOCTL_GUARDIAN_RECONCILE,
        IOCTL_GUARDIAN_DNS_SET_CONFIG,
        IOCTL_GUARDIAN_GET_PERF_STATS,
        IOCTL_GUARDIAN_GET_DNS_STATS,
        IOCTL_GUARDIAN_SET_GUARDIAN_MODE,
    ];
    for (i, a) in codes.iter().enumerate() {
        for (j, b) in codes.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}
