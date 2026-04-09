//! HTTP API surface is composed in [`routes`] from `fingerprint_engine::http`. Global policy here
//! (body limits) runs before handler code; domain validation lives next to each route in the engine crate.

pub mod json_policy;
pub mod routes;
