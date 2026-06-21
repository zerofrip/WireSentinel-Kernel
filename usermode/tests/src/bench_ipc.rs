//! IPC latency benchmark — run on Windows with Guardian.sys loaded.

#[cfg(windows)]
#[test]
fn bench_driver_state_ioctl() {
    use guardian_controller::GuardianClient;
    use std::time::Instant;

    let client = match GuardianClient::connect() {
        Ok(c) => c,
        Err(_) => return,
    };

    let start = Instant::now();
    for _ in 0..100 {
        let _ = client.driver_state().expect("state");
    }
    let elapsed = start.elapsed();
    eprintln!("100x GET_DRIVER_STATE: {elapsed:?}");
}
