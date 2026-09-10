//! Armored SOAR action execution — adapter routing, idempotency, verification, revert runbooks.

pub mod adapters;
pub mod audit;
pub mod blast_radius;
pub mod dispatch_record;
pub mod engine;
pub mod idempotency;
pub mod integrations;
pub mod integrations_vault;
pub mod revert;
pub mod stale;
pub mod types;
pub mod verification;
pub mod worker;

pub use engine::{approve_hitl, deny_hitl, execute_armored_action, revert_execution};
pub use types::{ActionOutcome, ExecutionStatus};
