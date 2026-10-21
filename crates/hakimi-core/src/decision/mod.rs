//! Connection decision engine.
//!
//! This module is split by responsibility:
//! - [`plan`]: plans and probe traits exchanged with the proxy
//! - [`cursor`]: the lazy candidate/mode state machine
//! - [`engine`]: routing, plan cache and score bookkeeping
//! - [`score`]: per-IP quality scores
//! - [`types`]: small internal candidate/DoH types

mod cursor;
mod engine;
mod plan;
mod score;
mod types;

#[cfg(test)]
mod tests;

pub use cursor::{Route, RouteCursor};
pub use engine::DecisionEngine;
pub use plan::{ConnectPlan, DecisionOutcome, Prober};
