#![deny(clippy::all)]
/// # `tracing-perfetto-sdk-layer`: A tracing layer that reports traces via the C++ Perfetto SDK
// Internal modules:
mod debug;

// Public modules:
pub mod error;
pub mod layer;

// Convenience re-exports:
pub use error::Error;
pub use layer::PerfettoSdkLayer;
