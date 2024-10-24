/// Internal tracking of tracing flavor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Flavor {
    /// Sync: stack frames nest on a per-thread basis.
    Sync,
    /// Async: many tasks may execute concurrently on each thread.
    Async,
}
