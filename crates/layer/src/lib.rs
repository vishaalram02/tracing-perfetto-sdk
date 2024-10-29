#![deny(clippy::all)]
//! # `tracing-perfetto-sdk-layer`
//! A suite of tracing layers that reports traces via the C++ Perfetto SDK
//!
//! There are currently two flavors of layers:
//!
//!   * [`NativeLayer`]: Writes tracing data using Rust code, but can
//!     additionally fetch further tracing data using the Perfetto SDK, e.g. via
//!     the `traced` daemon.
//!   * [`SdkLayer`]: Writes tracing data using the C++ SDK subroutines.  The
//!     SDK then decides how/if/when it interacts with other things in the
//!     Perfetto ecosystem.
//!
//! You can easily add a layer into your existing `tracing-subscriber` stack:
//!
//! ```no_run
//! use std::{fs, thread, time};
//! use tracing_subscriber::layer::SubscriberExt as _;
//! use tracing_perfetto_sdk_layer::NativeLayer;
//!
//! let out_file = "native-layer-example.pftrace";
//! let trace_config = todo!();
//! let out_file = fs::File::create(out_file)?;
//! let layer = NativeLayer::from_config(trace_config, out_file).build()?;
//!
//! let subscriber = tracing_subscriber::registry().with(layer);
//!
//! tracing::subscriber::with_default(subscriber, || {
//!     tracing::info!(foo = "baz", int = 7, "hello trace!");
//!
//!     let span = tracing::info_span!("hi", foo = "bar", int = 3);
//!     let guard = span.enter();
//!     thread::sleep(time::Duration::from_secs(1));
//!     drop(guard);
//! });
//! ```
//!
//! ## Using counters
//!
//! When logging trace events, such as when calling `tracing::info!()` and
//! similar macros, it is possible to additionally specify counters that will be
//! reported in the trace.
//!
//! Any field within the trace event can be a counter if it starts with the
//! `counter.` prefix and has a numeric value:
//!
//! ```no_run
//! tracing::info!(counter.mem_usage=42, counter.cpu_usage=23.2, "hi!");
//! ```
//!
//! It is recommended to specify the unit of the counter as the last
//! `.`-separated part of the field:
//!
//! ```no_run
//! tracing::info!(counter.mem_usage.bytes=42, counter.cpu_usage.percent=23.2, "hi!");
//! ```
//!
//! **NOTE**: at the time of writing, counters are only implemented by the
//! [`NativeLayer`].
//!
//! ## Controlling output destinations
//!
//! For [`NativeLayer`], traces can be written to anything that implements the
//! [`tracing_subscriber::fmt::MakeWriter`] trait.  It might be a good idea to
//! use the [`tracing_appender::non_blocking`] output if you want to defer the
//! writing to actual disk to a background thread.
//!
//! For [`SdkLayer`], since the write operation happens in C++ code, a real file
//! with an open file descriptor must be used instead.
//!
//! ## Tokio support
//!
//! If the `tokio` feature is enabled, the layers will be aware of spans coming
//! from the `tokio` runtime vs. normal OS threads.  Spans coming from the
//! `tokio` runtime will be reported to a special `tokio-runtime` track.
//!
//! ## Forcing flavors
//!
//! The layers will report spans to Perfetto using either a sync or async
//! flavor:
//!
//!  * The sync flavor implies that spans are reported when they are entered and
//!    exited.
//!  * The async flavor implies that spans are reported using RAII semantics, ie
//!    upon construction and until they are dropped.
//!
//! By default, a heuristic is used to determine whether a span is sync or
//! async. A specific flavor can instead be forced using the
//! `.with_force_flavor` method on layer builders.
//!
//! ## In-process vs system mode
//!
//! By default, layers are configured to run in-process mode only. That means
//! that the only data sources that are consulted are the ones embedded in the
//! actual application binary.
//!
//! In addition, (or instead of) in-process mode, the system mode can be
//! activated too.  This will (in the case of [`SdkLayer`]) write traces to the
//! system's `traced` daemon, or (in the case of [`NativeLayer`]) poll for
//! system-wide traces from the `traced` daemon and include them in the trace
//! file.

// Internal modules:
mod debug_annotations;
mod ffi_utils;
mod ids;
mod init;

// Public modules:
pub mod error;
pub mod flavor;
pub mod native_layer;
pub mod sdk_layer;

// Convenience re-exports:
pub use error::Error;
pub use flavor::Flavor;
pub use native_layer::NativeLayer;
pub use sdk_layer::SdkLayer;
