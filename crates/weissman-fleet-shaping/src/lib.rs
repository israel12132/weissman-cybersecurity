//! Distributed fleet traffic shaping and lock-free telemetry for multi-replica Red Team workers.
//!
//! - **Atomic token bucket:** Redis Lua script — validate + deduct in one round-trip (zero RMW races).
//! - **Adaptive stealth:** target pain (429/503/TTFB/TCP reset) shrinks global rate in real time.
//! - **CRDT telemetry:** commutative `HINCRBY` micro-batches merge across N workers without locks.
//! - **Graceful degradation:** high Redis latency → heavily throttled local buckets (never unrestricted).

#![forbid(unsafe_code)]

mod adaptive;
mod config;
mod coordinator;
mod degraded;
mod error;
mod telemetry;
mod token_bucket;

pub use adaptive::{record_pain_and_multiplier, TargetPainSignal};
pub use config::FleetShapingConfig;
pub use coordinator::{redis_manager_from_env, FleetCoordinator};
pub use degraded::{DegradedLocalShaper, ShapingMode};
pub use error::FleetShapingError;
pub use telemetry::{FleetTelemetrySnapshot, TelemetryAggregator, TelemetryMetric};
pub use token_bucket::{acquire_tokens, AcquireOutcome, AcquireResult};
