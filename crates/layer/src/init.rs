use std::sync;

use tracing_perfetto_sdk_sys::ffi;

static INIT: sync::Once = sync::Once::new();

pub fn global_init() {
    INIT.call_once(|| {
        ffi::perfetto_global_init(log_callback);
    });
}

fn log_callback(level: ffi::LogLev, line: i32, filename: &str, message: &str) {
    match level {
        ffi::LogLev::Debug => {
            tracing::debug!(target: "perfetto-sdk", filename, line, message);
        }
        ffi::LogLev::Info => {
            tracing::info!(target: "perfetto-sdk", filename, line, message);
        }
        ffi::LogLev::Important => {
            tracing::warn!(target: "perfetto-sdk", filename, line, message);
        }
        ffi::LogLev::Error => {
            tracing::error!(target: "perfetto-sdk", filename, line, message);
        }
        ffi::LogLev {
            repr: 4_u8..=u8::MAX,
        } => {}
    }
}
