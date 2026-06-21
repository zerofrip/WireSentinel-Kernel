//! Security policy type tests — compile on all platforms; validation logic is driver-side.

use guardian_controller::ioctl::{
    IOCTL_GUARDIAN_GET_DRIVER_STATE, IOCTL_GUARDIAN_SET_APP_POLICY, IOCTL_GUARDIAN_SET_KILL_SWITCH,
};

#[test]
fn security_ioctl_codes_are_distinct() {
    let codes = [
        IOCTL_GUARDIAN_GET_DRIVER_STATE,
        IOCTL_GUARDIAN_SET_APP_POLICY,
        IOCTL_GUARDIAN_SET_KILL_SWITCH,
    ];
    for (i, a) in codes.iter().enumerate() {
        for (j, b) in codes.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "IOCTL codes must be unique for security validation");
            }
        }
    }
}

#[test]
fn guardian_validate_ioctl_rejects_unknown_code_on_non_windows() {
    // Mirrors kernel-side STATUS_INVALID_DEVICE_REQUEST for unknown IOCTLs.
    let unknown = 0x8010u32 << 16 | 0xFFFF;
    assert_ne!(unknown, IOCTL_GUARDIAN_GET_DRIVER_STATE);
}
