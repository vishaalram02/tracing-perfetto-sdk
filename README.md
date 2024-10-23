# `tracing-perfetto-sdk`

An implementation of tracing primitives for the Rust `tracing` crate using the Perfetto C++ SDK.

Crates in this workspace are:

  - [tracing-perfetto-sdk-sys](crates/sys) - Raw bindings to and static embedding of the Perfetto SDK.
  - [tracing-perfetto-sdk-schema](crates/schema) - Proto schema for Perfetto trace packets, etc.
  - [tracing-perfetto-sdk-layer](crates/layer) - A tracing layer compatible with Rust's `tracing-subscriber` crate.

