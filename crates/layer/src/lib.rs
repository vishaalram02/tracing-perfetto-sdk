#![deny(clippy::all)]
/// # `tracing-perfetto-sdk-layer`: A tracing layer that reports traces via the C++ Perfetto SDK
// Internal modules:
mod debug_annotations;
mod ids;
mod init;

// Public modules:
pub mod error;
pub mod native_layer;
pub mod sdk_layer;

// Convenience re-exports:
pub use error::Error;
pub use native_layer::NativeLayer;
pub use sdk_layer::SdkLayer;
