//! Weissman Endpoint Agent library — detections, Hell's Gate syscalls, transport.
//!
//! The binary (`src/main.rs`) owns process boot. This crate exists so CI and
//! host probes can run Hell's Gate / Halo's Gate and local detections without
//! enrolling.

pub mod detections;
pub mod direct_syscalls;
pub mod hardening;
pub mod inner_crypto;
pub mod probe;
pub mod protocol;
pub mod transport;
