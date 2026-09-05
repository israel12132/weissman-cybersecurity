//! Weissman endpoint agent library.
//!
//! The binary (`weissman-agent`) is a thin boot wrapper. Host detections,
//! direct-syscall inspection, and dry-run probes live here so CI and the
//! operator CLI share one implementation.

pub mod detections;
pub mod direct_syscalls;
pub mod hardening;
pub mod inner_crypto;
pub mod probe;
pub mod protocol;
pub mod transport;
