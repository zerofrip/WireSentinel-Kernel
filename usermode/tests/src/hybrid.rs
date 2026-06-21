use guardian_controller::{GuardianDriverStateV1, GuardianMode, GUARDIAN_DRIVER_STATE_VERSION};
use std::mem::size_of;

#[test]
fn guardian_mode_from_u32() {
    assert_eq!(GuardianMode::from_u32(0), Some(GuardianMode::Wfp));
    assert_eq!(GuardianMode::from_u32(1), Some(GuardianMode::Ndis));
    assert_eq!(GuardianMode::from_u32(2), Some(GuardianMode::Hybrid));
    assert_eq!(GuardianMode::from_u32(3), None);
    assert_eq!(GuardianMode::from_u32(u32::MAX), None);
}

#[test]
fn guardian_mode_discriminant_values() {
    assert_eq!(GuardianMode::Wfp as u32, 0);
    assert_eq!(GuardianMode::Ndis as u32, 1);
    assert_eq!(GuardianMode::Hybrid as u32, 2);
}

#[test]
fn driver_state_mode_parsing_defaults_to_wfp() {
    let state = GuardianDriverStateV1 {
        version: GUARDIAN_DRIVER_STATE_VERSION,
        version_major: 0,
        version_minor: 1,
        version_patch: 0,
        build_stamp: 0,
        lifecycle_state: 0,
        callouts_registered: 0,
        filter_count: 0,
        recovery_generation: 0,
        kill_switch_mode: 0,
        last_error: 0,
        guardian_mode: 0,
        reserved: [0; 12],
    };

    assert_eq!(state.mode(), Some(GuardianMode::Wfp));
}

#[test]
fn driver_state_mode_parsing_hybrid() {
    let state = GuardianDriverStateV1 {
        version: GUARDIAN_DRIVER_STATE_VERSION,
        version_major: 0,
        version_minor: 1,
        version_patch: 0,
        build_stamp: 0,
        lifecycle_state: 2,
        callouts_registered: 4,
        filter_count: 1,
        recovery_generation: 0,
        kill_switch_mode: 0,
        last_error: 0,
        guardian_mode: GuardianMode::Hybrid as u32,
        reserved: [0; 12],
    };

    assert_eq!(state.mode(), Some(GuardianMode::Hybrid));
}

#[test]
fn driver_state_layout_size_unchanged() {
    assert_eq!(
        GuardianDriverStateV1::SIZE,
        size_of::<GuardianDriverStateV1>()
    );
    assert_eq!(GuardianDriverStateV1::SIZE, 60);
}

#[test]
fn driver_state_mode_roundtrip_bytes() {
    let mut bytes = [0u8; GuardianDriverStateV1::SIZE];
    bytes[44..48].copy_from_slice(&(GuardianMode::Ndis as u32).to_le_bytes());

    let state = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const GuardianDriverStateV1) };
    assert_eq!(state.mode(), Some(GuardianMode::Ndis));
}
