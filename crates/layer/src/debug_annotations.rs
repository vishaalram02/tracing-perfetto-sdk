//! Internal module used to collect span attrs as Perfetto SDK
//! `DebugAnnotation`s
use schema::debug_annotation;
use tracing::field;
use tracing_perfetto_sdk_schema as schema;
use tracing_perfetto_sdk_sys::ffi;

#[derive(Default)]
pub struct FFIDebugAnnotations {
    strings: Vec<ffi::DebugStringAnnotation>,
    bools: Vec<ffi::DebugBoolAnnotation>,
    ints: Vec<ffi::DebugIntAnnotation>,
    doubles: Vec<ffi::DebugDoubleAnnotation>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProtoDebugAnnotations {
    annotations: Vec<schema::DebugAnnotation>,
}

impl FFIDebugAnnotations {
    pub fn as_ffi(&self) -> ffi::DebugAnnotations {
        ffi::DebugAnnotations {
            strings: self.strings.as_slice(),
            bools: self.bools.as_slice(),
            ints: self.ints.as_slice(),
            doubles: self.doubles.as_slice(),
        }
    }
}

impl field::Visit for FFIDebugAnnotations {
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

impl ProtoDebugAnnotations {
    pub fn into_proto(self) -> Vec<schema::DebugAnnotation> {
        self.annotations
    }

    fn name_field(field: &field::Field) -> Option<debug_annotation::NameField> {
        Some(debug_annotation::NameField::Name(field.name().to_string()))
    }
}

impl field::Visit for ProtoDebugAnnotations {
    fn record_f64(&mut self, field: &field::Field, value: f64) {
        self.annotations.push(schema::DebugAnnotation {
            name_field: Self::name_field(field),
            value: Some(debug_annotation::Value::DoubleValue(value)),
            ..Default::default()
        });
    }

    fn record_i64(&mut self, field: &field::Field, value: i64) {
        self.annotations.push(schema::DebugAnnotation {
            name_field: Self::name_field(field),
            value: Some(debug_annotation::Value::IntValue(value)),
            ..Default::default()
        });
    }

    fn record_u64(&mut self, field: &field::Field, value: u64) {
        if let Some(v) = i64::try_from(value).ok() {
            self.annotations.push(schema::DebugAnnotation {
                name_field: Self::name_field(field),
                value: Some(debug_annotation::Value::IntValue(v)),
                ..Default::default()
            });
        } else {
            self.annotations.push(schema::DebugAnnotation {
                name_field: Self::name_field(field),
                value: Some(debug_annotation::Value::StringValue(value.to_string())),
                ..Default::default()
            });
        }
    }

    fn record_i128(&mut self, field: &field::Field, value: i128) {
        self.annotations.push(schema::DebugAnnotation {
            name_field: Self::name_field(field),
            value: Some(debug_annotation::Value::StringValue(value.to_string())),
            ..Default::default()
        });
    }

    fn record_u128(&mut self, field: &field::Field, value: u128) {
        self.annotations.push(schema::DebugAnnotation {
            name_field: Self::name_field(field),
            value: Some(debug_annotation::Value::StringValue(value.to_string())),
            ..Default::default()
        });
    }

    fn record_bool(&mut self, field: &field::Field, value: bool) {
        self.annotations.push(schema::DebugAnnotation {
            name_field: Self::name_field(field),
            value: Some(debug_annotation::Value::BoolValue(value)),
            ..Default::default()
        });
    }

    fn record_str(&mut self, field: &field::Field, value: &str) {
        self.annotations.push(schema::DebugAnnotation {
            name_field: Self::name_field(field),
            value: Some(debug_annotation::Value::StringValue(value.to_owned())),
            ..Default::default()
        });
    }

    fn record_error(&mut self, field: &field::Field, value: &(dyn std::error::Error + 'static)) {
        self.annotations.push(schema::DebugAnnotation {
            name_field: Self::name_field(field),
            value: Some(debug_annotation::Value::StringValue(format!("{:#}", value))),
            ..Default::default()
        });
    }

    fn record_debug(&mut self, field: &field::Field, value: &dyn std::fmt::Debug) {
        self.annotations.push(schema::DebugAnnotation {
            name_field: Self::name_field(field),
            value: Some(debug_annotation::Value::StringValue(format!("{:?}", value))),
            ..Default::default()
        });
    }
}
