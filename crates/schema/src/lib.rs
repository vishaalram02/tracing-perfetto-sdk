//! # `tracing-perfetto-sdk-schema`: Internal crate containing the raw Perfetto proto schemata.
#![deny(clippy::all)]
include!(concat!(env!("OUT_DIR"), "/perfetto.protos.rs"));
include!(concat!(env!("OUT_DIR"), "/perfetto.protos.serde.rs"));
