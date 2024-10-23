use std::{env, fs};

use tokio::{runtime, time};
use tracing::{info, span};
use tracing_perfetto_sdk_layer as layer;
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
    let perfetto_layer = layer::PerfettoSdkLayer::from_config(config, Some(file))?;

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
    let _enter = demo_span.enter();

    info!("in span");
    sync_fn(1);
    let handle = runtime::Handle::current();
    let t = std::thread::spawn(move || {
        handle.spawn(async_fn());
    });
    t.join().unwrap();

    _ = tokio::spawn(async_fn()).await;

    time::sleep(time::Duration::from_secs(1)).await;

    perfetto_layer.stop()?;

    let trace_data = fs::read(trace_path)?;
    let trace = tracing_perfetto_sdk_schema::Trace::decode(&*trace_data)?;
    eprintln!("trace = {}", serde_yaml::to_string(&trace)?);
    Ok(())
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
