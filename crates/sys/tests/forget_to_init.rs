use tracing_perfetto_sdk_sys::ffi;

// This is in its own test file to get a new process for this test
#[test]
fn forget_to_init() {
    let result = ffi::new_tracing_session(&[], -1);
    if let Err(e) = result {
        let expected = "Must call perfetto_global_init before creating a tracing session";
        let actual = e.to_string();
        assert_eq!(expected, actual);
    } else {
        panic!("expected new_tracing_session to fail");
    }
}
