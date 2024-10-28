//! Common error definitions

use std::io;

/// Generic error from the Perfetto SDK
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A generic C++ exception occurred in the C++ code.
    #[error("C++ code threw an exception: {0}")]
    Cxx(#[from] cxx::Exception),
    #[error("IO error: {0}")]
    IO(#[from] io::Error),
    #[error("Encountered a poisoned mutex")]
    PoisonedMutex,
    #[error("The layer has been stopped")]
    LayerStopped,
    #[error("Failed to complete operation before timeout was reached")]
    TimedOut,
    #[error("Failed to flush data due to some unknown reason (might also be due to timeout)")]
    FlushFailed,
}

/// Convenience alias for [`std::result::Result`] using our own `Error` type.
pub type Result<A> = std::result::Result<A, Error>;
