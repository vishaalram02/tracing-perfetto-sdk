//! Internal module used to collect span attrs as Perfetto SDK
//! `DebugAnnotation`s
use tracing::field;
use tracing_perfetto_sdk_sys::ffi;

#[derive(Default)]
pub struct DebugAnnotations {
    strings: Vec<ffi::DebugStringAnnotation>,
    bools: Vec<ffi::DebugBoolAnnotation>,
    ints: Vec<ffi::DebugIntAnnotation>,
    doubles: Vec<ffi::DebugDoubleAnnotation>,
}

impl DebugAnnotations {
    pub fn as_ffi(&self) -> ffi::DebugAnnotations {
        ffi::DebugAnnotations {
            strings: self.strings.as_slice(),
            bools: self.bools.as_slice(),
            ints: self.ints.as_slice(),
            doubles: self.doubles.as_slice(),
        }
    }
}

impl field::Visit for DebugAnnotations {
    fn record_f64(&mut self, field: &field::Field, value: f64) {
        self.doubles.push(ffi::DebugDoubleAnnotation {
            key: field.name(),
            value,
        });
    }

    fn record_i64(&mut self, field: &field::Field, value: i64) {
        self.ints.push(ffi::DebugIntAnnotation {
            key: field.name(),
            value,
        });
    }

    fn record_u64(&mut self, field: &field::Field, value: u64) {
        if let Some(v) = i64::try_from(value).ok() {
            self.ints.push(ffi::DebugIntAnnotation {
                key: field.name(),
                value: v,
            });
        } else {
            self.strings.push(ffi::DebugStringAnnotation {
                key: field.name(),
                value: value.to_string(),
            });
        }
    }

    fn record_i128(&mut self, field: &field::Field, value: i128) {
        self.strings.push(ffi::DebugStringAnnotation {
            key: field.name(),
            value: value.to_string(),
        });
    }

    fn record_u128(&mut self, field: &field::Field, value: u128) {
        self.strings.push(ffi::DebugStringAnnotation {
            key: field.name(),
            value: value.to_string(),
        });
    }

    fn record_bool(&mut self, field: &field::Field, value: bool) {
        self.bools.push(ffi::DebugBoolAnnotation {
            key: field.name(),
            value,
        });
    }

    fn record_str(&mut self, field: &field::Field, value: &str) {
        self.strings.push(ffi::DebugStringAnnotation {
            key: field.name(),
            value: value.to_owned(),
        });
    }

    fn record_error(&mut self, field: &field::Field, value: &(dyn std::error::Error + 'static)) {
        self.strings.push(ffi::DebugStringAnnotation {
            key: field.name(),
            value: format!("{:#}", value),
        });
    }

    fn record_debug(&mut self, field: &field::Field, value: &dyn std::fmt::Debug) {
        self.strings.push(ffi::DebugStringAnnotation {
            key: field.name(),
            value: format!("{:?}", value),
        });
    }
}
