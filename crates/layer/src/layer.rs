//! The main tracing layer and related utils exposed by this crate.
use std::sync::atomic;
use std::{env, fs, hash, process, sync, thread};
use std::hash::{Hash, Hasher};
#[cfg(feature = "tokio")]
use tokio::task;
use tracing::span;
use tracing_perfetto_sdk_schema as schema;
use tracing_perfetto_sdk_sys::ffi;
use tracing_subscriber::{layer, registry};

use crate::{debug, error};

static INIT: sync::Once = sync::Once::new();

// Seeds for consistent hashing of pid/tid/task id
const TRACK_UUID_NS: u32 = 1;
const SEQUENCE_ID_NS: u32 = 2;
const PROCESS_NS: u32 = 1;
const THREAD_NS: u32 = 2;
#[cfg(feature = "tokio")]
const TASK_NS: u32 = 3;

/// A layer to be used with `tracing-subscriber` that forwards collected spans
/// to the Perfetto SDK.
#[derive(Clone)]
#[repr(transparent)]
pub struct PerfettoSdkLayer {
    inner: sync::Arc<Inner>,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
struct TrackUuid(u64);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
struct SequenceId(u32);

struct ThreadLocalCtx {
    descriptor_sent: atomic::AtomicBool,
}

struct Inner {
    // Mutex is only held during start and stop, never otherwise
    ffi_session: sync::Mutex<Option<cxx::UniquePtr<ffi::PerfettoTracingSession>>>,
    output_file: sync::Mutex<Option<fs::File>>,
    process_track_uuid: TrackUuid,
    process_descriptor_sent: atomic::AtomicBool,
    thread_local_ctxs: thread_local::ThreadLocal<ThreadLocalCtx>,
}

impl PerfettoSdkLayer {
    pub fn from_config(
        config: schema::TraceConfig,
        output_file: Option<fs::File>,
    ) -> error::Result<Self> {
        use prost::Message as _;
        Self::from_config_bytes(&config.encode_to_vec(), output_file)
    }

    pub fn from_config_bytes(
        config_bytes: &[u8],
        output_file: Option<fs::File>,
    ) -> error::Result<Self> {
        use std::os::fd::AsRawFd as _;

        INIT.call_once(|| {
            ffi::perfetto_global_init(log_callback);
        });
        let fd = output_file.as_ref().map(|f| f.as_raw_fd()).unwrap_or(-1);
        // We send the config to the C++ code as encoded bytes, because it would be too
        // annoying to have some sort of shared proto struct between the Rust
        // and C++ worlds
        let mut ffi_session = ffi::new_tracing_session(config_bytes, fd)?;
        ffi_session.pin_mut().start();
        let ffi_session = sync::Mutex::new(Some(ffi_session));

        let output_file = sync::Mutex::new(output_file);

        let pid = process::id();
        let process_track_uuid = Self::process_track_uuid(pid);
        let process_descriptor_sent = atomic::AtomicBool::new(false);
        let thread_local_ctxs = thread_local::ThreadLocal::new();

        let inner = sync::Arc::new(Inner {
            ffi_session,
            output_file,
            process_track_uuid,
            process_descriptor_sent,
            thread_local_ctxs,
        });
        Ok(Self { inner })
    }

    fn ensure_context_known(&self) {
        self.ensure_process_known();
        self.ensure_thread_known();
    }

    fn ensure_process_known(&self) {
        let process_descriptor_sent = self
            .inner
            .process_descriptor_sent
            .fetch_or(true, atomic::Ordering::SeqCst);

        if !process_descriptor_sent {
            let process_name = env::current_exe()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();

            ffi::trace_track_descriptor_process(
                0,
                self.inner.process_track_uuid.0,
                &process_name,
                process::id(),
            );
        }
    }

    fn ensure_thread_known(&self) {
        let thread_local_ctx = self.inner
            .thread_local_ctxs
            .get_or(|| {
                ThreadLocalCtx {
                    descriptor_sent: atomic::AtomicBool::new(false),
                }
            });
        let thread_descriptor_sent = thread_local_ctx.descriptor_sent.fetch_or(true, atomic::Ordering::Relaxed);
        if !thread_descriptor_sent {
            let tid = thread_id::get();
            ffi::trace_track_descriptor_thread(
                self.inner.process_track_uuid.0,
                Self::thread_track_uuid(tid).0,
                process::id(),
                thread::current().name().unwrap_or(""),
                thread_id::get() as u32,
            );
        }
    }

    fn trace_context(&self) -> (TrackUuid, SequenceId) {
        #[cfg(feature = "tokio")]
        if let Some(task_id) = task::try_id() {
            return (self.inner.process_track_uuid, Self::task_sequence_id(task_id));
        }

        let tid = thread_id::get();
        (Self::thread_track_uuid(tid), Self::thread_sequence_id(tid))
    }

    pub fn flush(&self) -> error::Result<()> {
        self.inner.flush()
    }

    pub fn stop(&self) -> error::Result<()> {
        self.inner.stop()
    }

    fn process_track_uuid(pid: u32) -> TrackUuid {
        let mut h = hash::DefaultHasher::new();
        (TRACK_UUID_NS, PROCESS_NS, pid).hash(&mut h);
        TrackUuid(h.finish())
    }

    fn thread_track_uuid(tid: usize) -> TrackUuid {
        let mut h = hash::DefaultHasher::new();
        (TRACK_UUID_NS, THREAD_NS, tid).hash(&mut h);
        TrackUuid(h.finish())
    }

    fn thread_sequence_id(tid: usize) -> SequenceId {
        let mut h = hash::DefaultHasher::new();
        (SEQUENCE_ID_NS, THREAD_NS, tid).hash(&mut h);
        SequenceId(h.finish() as u32)
    }

    #[cfg(feature = "tokio")]
    fn task_sequence_id(tid: task::Id) -> SequenceId {
        let mut h = hash::DefaultHasher::new();
        (SEQUENCE_ID_NS, TASK_NS, tid).hash(&mut h);
        SequenceId(h.finish() as u32)
    }
}

impl<S> tracing_subscriber::Layer<S> for PerfettoSdkLayer
where
    S: tracing::Subscriber,
    S: for<'a> registry::LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: layer::Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };

        self.ensure_context_known();

        let mut debug_annotations = debug::DebugAnnotations::default();
        attrs.record(&mut debug_annotations);

        let (track_uuid, sequence_id) = self.trace_context();
        let meta = span.metadata();
        ffi::trace_track_event_slice_begin(
            track_uuid.0,
            sequence_id.0,
            meta.name(),
            meta.file().unwrap_or(""),
            meta.line().unwrap_or(0),
            &debug_annotations.as_ffi(),
        );
    }

    fn on_event(&self, event: &tracing::Event<'_>, _ctx: layer::Context<'_, S>) {
        self.ensure_process_known();
        self.ensure_thread_known();

        let mut debug_annotations = debug::DebugAnnotations::default();
        event.record(&mut debug_annotations);

        let meta = event.metadata();
        let (track_uuid, sequence_id) = self.trace_context();
        ffi::trace_track_event_instant(
            track_uuid.0,
            sequence_id.0,
            meta.name(),
            meta.file().unwrap_or(""),
            meta.line().unwrap_or(0),
            &debug_annotations.as_ffi(),
        );
    }

    fn on_close(&self, id: tracing::Id, ctx: layer::Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };

        let meta = span.metadata();
        let (track_uuid, sequence_id) = self.trace_context();
        ffi::trace_track_event_slice_end(
            track_uuid.0,
            sequence_id.0,
            meta.name(),
            meta.file().unwrap_or(""),
            meta.line().unwrap_or(0),
        );
    }
}

impl Inner {
    fn flush(&self) -> error::Result<()> {
        let mut ffi_session = self
            .ffi_session
            .lock()
            .map_err(|_| error::Error::PoisonedMutex)?;
        if let Some(ffi_session) = ffi_session.as_mut() {
            ffi_session.pin_mut().flush();
        }

        Ok(())
    }

    fn stop(&self) -> error::Result<()> {
        use std::io::Write as _;

        let mut ffi_session = self
            .ffi_session
            .lock()
            .map_err(|_| error::Error::PoisonedMutex)?;
        if let Some(mut ffi_session) = ffi_session.take() {
            ffi_session.pin_mut().stop();
        }

        let mut output_file = self
            .output_file
            .lock()
            .map_err(|_| error::Error::PoisonedMutex)?;
        if let Some(mut output_file) = output_file.take() {
            output_file.flush()?;
        }

        Ok(())
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.stop();
    }
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
