#![cfg(feature = "tokio")]
use std::{env, fs};

use schema::trace_packet;
use tokio::{runtime, time};
use tracing::{info, span};
use tracing_perfetto_sdk_layer as layer;
use tracing_perfetto_sdk_schema as schema;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::format;

#[tokio::test]
async fn kitchen_sink() -> anyhow::Result<()> {
    use prost::Message as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let trace_path = env::temp_dir().join("test.pftrace");
    let file = fs::File::create(&trace_path)?;
    let config = serde_yaml::from_str(
        r#"
buffers:
  - size_kb: 1024
data_sources:
  - config:
      name: "rust_tracing"
  - config:
      name: "linux.process_stats"
      process_stats_config:
        scan_all_processes_on_start: true
        proc_stats_poll_ms: 100
  - config:
      name: "linux.ftrace"
      ftrace_config:
        ftrace_events: ["kmem/rss_stat", "mm_event/mm_event_record"]
  - config:
      name: "linux.sys_stats"
      sys_stats_config:
        meminfo_period_ms: 100
        meminfo_counters: [MEMINFO_MEM_TOTAL, MEMINFO_MEM_FREE, MEMINFO_MEM_AVAILABLE]
        vmstat_period_ms: 100
        vmstat_counters: [VMSTAT_NR_FREE_PAGES, VMSTAT_NR_ALLOC_BATCH, VMSTAT_NR_INACTIVE_ANON, VMSTAT_NR_ACTIVE_ANON]
        stat_period_ms: 100
        stat_counters: [STAT_CPU_TIMES, STAT_FORK_COUNT]
"#,
    )?;
    let perfetto_layer = layer::SdkLayer::from_config(config, Some(file))?;

    let fmt_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .event_format(format::Format::default().with_thread_ids(true))
        .with_span_events(format::FmtSpan::FULL);

    let subscriber = tracing_subscriber::Registry::default()
        .with(fmt_layer)
        .with(perfetto_layer.clone());

    tracing::subscriber::set_global_default(subscriber)?;
    info!(?trace_path, "start");

    let demo_span = span!(tracing::Level::TRACE, "demo_span");
    let enter = demo_span.enter();

    info!("in span");
    sync_fn(1);
    let handle = runtime::Handle::current();
    let t = std::thread::spawn(move || {
        handle.spawn(async_fn());
    });
    t.join().unwrap();

    _ = tokio::spawn(async_fn()).await;

    time::sleep(time::Duration::from_secs(1)).await;

    drop(enter);
    perfetto_layer.flush()?;
    perfetto_layer.stop()?;

    let trace_data = fs::read(trace_path)?;
    let trace = schema::Trace::decode(&*trace_data)?;
    // eprintln!("trace = {}", serde_yaml::to_string(&trace)?);

    let process_td = trace
        .packet
        .iter()
        .find_map(|p| {
            let td = as_track_descriptor(p)?;
            if td
                .process
                .as_ref()?
                .process_name
                .as_ref()?
                .starts_with("kitchen_sink-")
            {
                Some(td)
            } else {
                None
            }
        })
        .expect("to find a process descriptor for this test");

    let thread_td = trace
        .packet
        .iter()
        .find_map(|p| {
            let td = as_track_descriptor(p)?;
            if td.thread.as_ref()?.thread_name.as_ref()? == "kitchen_sink" {
                Some(td)
            } else {
                None
            }
        })
        .expect("to find a track descriptor for this test");

    assert_eq!(process_td.uuid, thread_td.parent_uuid);

    let tokio_td = trace
        .packet
        .iter()
        .find_map(|p| {
            let td = as_track_descriptor(p)?;
            if td.thread.as_ref()?.thread_name.as_ref()? == "tokio-runtime" {
                Some(td)
            } else {
                None
            }
        })
        .expect("to find a track descriptor for the Tokio runtime");

    assert_eq!(process_td.uuid, tokio_td.parent_uuid);

    Ok(())
}

fn as_track_descriptor(packet: &schema::TracePacket) -> Option<&schema::TrackDescriptor> {
    match packet.data {
        Some(trace_packet::Data::TrackDescriptor(ref td)) => Some(td),
        _ => None,
    }
}

#[tracing::instrument]
fn sync_fn(i: i32) {
    info!("inside function");
    sync_inner(i + 1);
}

#[tracing::instrument(skip_all, level = "trace")]
fn sync_inner(x: i32) {
    info!(x, "inner");
}

#[tracing::instrument]
async fn async_fn() {
    info!(perfetto = true, "test");
    async_inner().await;
}

#[tracing::instrument]
async fn async_inner() {
    time::sleep(time::Duration::from_secs(1)).await;
}
