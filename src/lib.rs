//! perch internals, exposed as a library so the integration tests can
//! drive the real pipeline (HTTP -> snapshot -> checks -> state machine) rather
//! than a reimplementation of it.

pub mod alpenglow;
pub mod checks;
pub mod config;
pub mod diagnose;
pub mod enrich;
pub mod fillrate;
pub mod heartbeat;
pub mod inhibit;
pub mod maint;
pub mod metrics;
pub mod node_exporter;
pub mod notify;
pub mod peer;
pub mod persist;
pub mod rpc;
pub mod selfcheck;
pub mod sfdp;

/// The git commit this binary was built from, stamped in by `build.rs`.
pub const COMMIT: &str = env!("PERCH_COMMIT");

/// Version and commit together, e.g. `1.0.0 (9d34f2d)`. This is what
/// `--version`, the startup line, and `perch_build_info` all report, so the
/// same string identifies a build everywhere it appears.
pub const BUILD: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("PERCH_COMMIT"), ")");
pub mod digest;
pub mod snapshot;
pub mod state;
pub mod status;
pub mod verdict;
pub mod web;
