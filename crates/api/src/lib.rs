//! HTTP surface for the iam service.
//!
//! This is the only crate that knows about HTTP. Handler logic is built into a
//! plain `axum::Router` by [`build_router`], deliberately independent of the
//! runtime: the native server (`bin/iam`) and the Lambda entry point (behind
//! the `lambda` feature) both mount the same router, and no runtime type ever
//! appears in a handler signature.

pub mod audit;
pub mod config;
pub mod error;
pub mod extract;
pub mod guard;
pub mod ip;
pub mod metrics;
pub mod ratelimit;
pub mod routes;
pub mod runtime;
pub mod seed;
pub mod state;

pub use config::Config;
pub use state::{AppState, AppStateParts, RateLimiters};

pub use routes::build_router;
