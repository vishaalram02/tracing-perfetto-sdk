//! # `tracing-perfetto-sdk-sys`: C++ bindings to the raw Perfetto SDK
//!
//! This crate only contains low-level bindings to the C++ library.  While the
//! interface is safe, it is recommended to use a higher level API, for example
//! via the `tracing-perfetto-sdk-layer` crate.
#![deny(clippy::all)]

/// FFI bridge: Definitions of functions and types that are shared across the
/// C++ boundary.
#[cxx::bridge]
pub mod ffi {
    pub enum LogLev {
        Debug = 0,
        Info = 1,
        Important = 2,
        Error = 3,
    }

    pub struct DebugStringAnnotation {
        pub key: &'static str,
        pub value: String,
    }

    pub struct DebugBoolAnnotation {
        pub key: &'static str,
        pub value: bool,
    }

    pub struct DebugIntAnnotation {
        pub key: &'static str,
        pub value: i64,
    }

    pub struct DebugDoubleAnnotation {
        pub key: &'static str,
        pub value: f64,
    }

    pub struct DebugAnnotations<'a> {
        pub strings: &'a [DebugStringAnnotation],
        pub bools: &'a [DebugBoolAnnotation],
        pub ints: &'a [DebugIntAnnotation],
        pub doubles: &'a [DebugDoubleAnnotation],
    }

    extern "Rust" {
        // Opaque type passed to C++ code to be sent back during callbacks; essentially
        // like `void *context` but type-safe
        type PollTracesCtx;
    }

    unsafe extern "C++" {
        include!("src/perfetto-bindings.h");

        /// Initialize the global tracing infrastructure.
        ///
        /// Must be called once before all other functions in this module.
        ///
        /// `log_callback` parameters are `level, line, filename, message`.
        fn perfetto_global_init(log_callback: fn(LogLev, i32, &str, &str));

        /// The native C++ class that is safe to be passed across the C++/Rust
        /// boundary via a `unique_ptr`.
        type PerfettoTracingSession;

        /// Create a new tracing session using the provided Protobuf-encoded
        /// TraceConfig.
        ///
        /// If `output_fd` is non-negative, we will write traces directly to the
        /// provided file descriptor, in which case `poll_traces` will never
        /// return any data.
        fn new_tracing_session(
            trace_config_bytes: &[u8],
            output_fd: i32,
        ) -> Result<UniquePtr<PerfettoTracingSession>>;

        /// Create a trace event signifying that a new slice (aka span) begins.
        ///
        /// Make sure to call this in the hot path instead of delaying the call
        /// to some background queue, etc., as the call will collect additional
        /// timing data at the time of the actual call.
        ///
        /// This call is very cheap and will be a no-op if trace collection is
        /// not yet started/enabled.
        fn trace_track_event_slice_begin<'a>(
            track_uuid: u64,
            sequence_id: u32,
            name: &str,
            location_file: &str,
            location_line: u32,
            debug_annotations: &DebugAnnotations<'a>,
        );

        /// Create a trace event signifying that a slice (aka span) ends.
        ///
        /// Make sure to call this in the hot path instead of delaying the call
        /// to some background queue, etc., as the call will collect additional
        /// timing data at the time of the actual call.
        ///
        /// This call is very cheap and will be a no-op if trace collection is
        /// not yet started/enabled.
        fn trace_track_event_slice_end<'a>(
            track_uuid: u64,
            sequence_id: u32,
            name: &str,
            location_file: &str,
            location_line: u32,
        );

        /// Create a trace event signifying that an instant event has happened,
        /// similar to a log message or something else that takes ~zero time.
        ///
        /// Make sure to call this in the hot path instead of delaying the call
        /// to some background queue, etc., as the call will collect additional
        /// timing data at the time of the actual call.
        ///
        /// This call is very cheap and will be a no-op if trace collection is
        /// not yet started/enabled.
        fn trace_track_event_instant<'a>(
            track_uuid: u64,
            sequence_id: u32,
            name: &str,
            location_file: &str,
            location_line: u32,
            debug_annotations: &DebugAnnotations<'a>,
        );

        /// Create a track descriptor for a process.
        ///
        /// Make sure to call this in the hot path instead of delaying the call
        /// to some background queue, etc., as the call will collect additional
        /// timing data at the time of the actual call.
        ///
        /// This call is very cheap and will be a no-op if trace collection is
        /// not yet started/enabled.
        fn trace_track_descriptor_process<'a>(
            parent_uuid: u64,
            track_uuid: u64,
            process_name: &str,
            process_pid: u32,
        );

        /// Create a track descriptor for a thread.
        ///
        /// Make sure to call this in the hot path instead of delaying the call
        /// to some background queue, etc., as the call will collect additional
        /// timing data at the time of the actual call.
        ///
        /// This call is very cheap and will be a no-op if trace collection is
        /// not yet started/enabled.
        fn trace_track_descriptor_thread<'a>(
            parent_uuid: u64,
            track_uuid: u64,
            process_pid: u32,
            thread_name: &str,
            thread_tid: u32,
        );

        /// Start collecting traces from all data sources.
        fn start(self: Pin<&mut PerfettoTracingSession>);

        /// Stop collecting traces from all data sources.
        fn stop(self: Pin<&mut PerfettoTracingSession>);

        /// Flush buffered traces.
        fn flush(self: Pin<&mut PerfettoTracingSession>);

        /// Poll for new traces, and call the provided `done` callback with new
        /// trace records.
        ///
        /// Polling will only return data if an `output_fd` was *not* specified
        /// when creating the session.
        ///
        /// If there are no more records, the callback will be called with an
        /// empty slice and `has_more == true` as a special case to signal EOF.
        ///
        /// The data in the callback buffer is guaranteed to consist of complete
        /// trace records; in other words, there will not be any partial records
        /// that cross buffer boundaries.
        fn poll_traces(
            self: Pin<&mut PerfettoTracingSession>,
            ctx: Box<PollTracesCtx>,
            done: fn(Box<PollTracesCtx>, data: &[u8], has_more: bool),
        );
    }
}

// Safe to use session from all threads
unsafe impl Send for ffi::PerfettoTracingSession {}
unsafe impl Sync for ffi::PerfettoTracingSession {}

/// A context that will be passed-in in a call to [`ffi::poll_traces`] and later
/// passed back in the `done` callback when the async operation has completed.
pub struct PollTracesCtx {}
