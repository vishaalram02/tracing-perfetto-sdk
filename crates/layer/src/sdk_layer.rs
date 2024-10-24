//! The main tracing layer and related utils exposed by this crate.
use std::sync::atomic;
use std::{env, fs, process, sync, thread};

#[cfg(feature = "tokio")]
use tokio::task;
use tracing::span;
use tracing_perfetto_sdk_schema as schema;
use tracing_perfetto_sdk_sys::ffi;
use tracing_subscriber::{layer, registry};

use crate::{debug_annotations, error, ids, init};

/// A layer to be used with `tracing-subscriber` that forwards collected spans
/// to the Perfetto SDK via the C++ API.
#[derive(Clone)]
#[repr(transparent)]
pub struct SdkLayer {
    inner: sync::Arc<Inner>,
}

struct ThreadLocalCtx {
    descriptor_sent: atomic::AtomicBool,
}

struct Inner {
    // Mutex is only held during start and stop, never otherwise
    ffi_session: sync::Mutex<Option<cxx::UniquePtr<ffi::PerfettoTracingSession>>>,
    output_file: sync::Mutex<Option<fs::File>>,
    process_track_uuid: ids::TrackUuid,
    process_descriptor_sent: atomic::AtomicBool,
    #[cfg(feature = "tokio")]
    tokio_descriptor_sent: atomic::AtomicBool,
    #[cfg(feature = "tokio")]
    tokio_track_uuid: ids::TrackUuid,
    thread_local_ctxs: thread_local::ThreadLocal<ThreadLocalCtx>,
}

impl SdkLayer {
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

        // Shared global initialization for all layers
        init::global_init();

        let fd = output_file.as_ref().map(|f| f.as_raw_fd()).unwrap_or(-1);
        // We send the config to the C++ code as encoded bytes, because it would be too
        // annoying to have some sort of shared proto struct between the Rust
        // and C++ worlds
        let mut ffi_session = ffi::new_tracing_session(config_bytes, fd)?;
        ffi_session.pin_mut().start();
        let ffi_session = sync::Mutex::new(Some(ffi_session));

        let output_file = sync::Mutex::new(output_file);

        let process_track_uuid = ids::TrackUuid::for_process(process::id());
        let process_descriptor_sent = atomic::AtomicBool::new(false);
        #[cfg(feature = "tokio")]
        let tokio_descriptor_sent = atomic::AtomicBool::new(false);
        #[cfg(feature = "tokio")]
        let tokio_track_uuid = ids::TrackUuid::for_tokio();
        let thread_local_ctxs = thread_local::ThreadLocal::new();

        let inner = sync::Arc::new(Inner {
            ffi_session,
            output_file,
            process_track_uuid,
            process_descriptor_sent,
            #[cfg(feature = "tokio")]
            tokio_descriptor_sent,
            #[cfg(feature = "tokio")]
            tokio_track_uuid,
            thread_local_ctxs,
        });
        Ok(Self { inner })
    }

    fn ensure_context_known(&self) {
        self.ensure_process_known();
        self.ensure_thread_known();
        #[cfg(feature = "tokio")]
        self.ensure_tokio_runtime_known();
    }

    fn ensure_process_known(&self) {
        let process_descriptor_sent = self
            .inner
            .process_descriptor_sent
            .fetch_or(true, atomic::Ordering::Relaxed);

        if !process_descriptor_sent {
            let process_name = env::current_exe()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();

            let process_name = process_name.rsplit("/").next().unwrap_or("");

            ffi::trace_track_descriptor_process(
                0,
                self.inner.process_track_uuid.as_raw(),
                &process_name,
                process::id(),
            );
        }
    }

    fn ensure_thread_known(&self) {
        let thread_local_ctx = self.inner.thread_local_ctxs.get_or(|| ThreadLocalCtx {
            descriptor_sent: atomic::AtomicBool::new(false),
        });
        let thread_descriptor_sent = thread_local_ctx
            .descriptor_sent
            .fetch_or(true, atomic::Ordering::Relaxed);
        if !thread_descriptor_sent {
            let tid = thread_id::get();
            ffi::trace_track_descriptor_thread(
                self.inner.process_track_uuid.as_raw(),
                ids::TrackUuid::for_thread(tid).as_raw(),
                process::id(),
                thread::current().name().unwrap_or(""),
                thread_id::get() as u32,
            );
        }
    }

    #[cfg(feature = "tokio")]
    fn ensure_tokio_runtime_known(&self) {
        // Bogus thread ID; this is unlikely to ever be an actually real thread ID.
        const TOKIO_THREAD_ID: u32 = (i32::MAX - 1) as u32;

        let tokio_descriptor_sent = self
            .inner
            .tokio_descriptor_sent
            .fetch_or(true, atomic::Ordering::Relaxed);
        if !tokio_descriptor_sent {
            ffi::trace_track_descriptor_thread(
                self.inner.process_track_uuid.as_raw(),
                self.inner.tokio_track_uuid.as_raw(),
                process::id(),
                "tokio-runtime",
                TOKIO_THREAD_ID,
            );
        }
    }

    fn pick_trace_track(&self) -> ids::TrackUuid {
        #[cfg(feature = "tokio")]
        if task::try_id().is_some() {
            return self.inner.tokio_track_uuid;
        }

        ids::TrackUuid::for_thread(thread_id::get())
    }

    pub fn flush(&self) -> error::Result<()> {
        self.inner.flush()
    }

    pub fn stop(&self) -> error::Result<()> {
        self.inner.stop()
    }
}

impl<S> tracing_subscriber::Layer<S> for SdkLayer
where
    S: tracing::Subscriber,
    S: for<'a> registry::LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: layer::Context<'_, S>) {
        let span = ctx.span(id).expect("span to be found (this is a bug)");

        let track_uuid = self.pick_trace_track();
        let meta = span.metadata();

        let mut debug_annotations = debug_annotations::FFIDebugAnnotations::default();
        attrs.record(&mut debug_annotations);

        self.ensure_context_known();
        ffi::trace_track_event_slice_begin(
            track_uuid.as_raw(),
            meta.name(),
            meta.file().unwrap_or(""),
            meta.line().unwrap_or(0),
            &debug_annotations.as_ffi(),
        );
    }

    fn on_record(&self, id: &tracing::Id, values: &span::Record<'_>, ctx: layer::Context<'_, S>) {
        let span = ctx.span(id).expect("span to be found (this is a bug)");

        let mut extensions = span.extensions_mut();
        if let Some(debug_annotations) =
            extensions.get_mut::<debug_annotations::FFIDebugAnnotations>()
        {
            values.record(debug_annotations);
        } else {
            let mut debug_annotations = debug_annotations::FFIDebugAnnotations::default();
            values.record(&mut debug_annotations);
            extensions.insert(debug_annotations);
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, _ctx: layer::Context<'_, S>) {
        self.ensure_context_known();

        let mut debug_annotations = debug_annotations::FFIDebugAnnotations::default();
        event.record(&mut debug_annotations);

        let meta = event.metadata();
        let track_uuid = self.pick_trace_track();
        ffi::trace_track_event_instant(
            track_uuid.as_raw(),
            meta.name(),
            meta.file().unwrap_or(""),
            meta.line().unwrap_or(0),
            &debug_annotations.as_ffi(),
        );
    }

    fn on_close(&self, id: tracing::Id, ctx: layer::Context<'_, S>) {
        let span = ctx.span(&id).expect("span to be found (this is a bug)");

        let meta = span.metadata();
        let track_uuid = self.pick_trace_track();
        ffi::trace_track_event_slice_end(
            track_uuid.as_raw(),
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
