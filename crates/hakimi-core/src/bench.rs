//! Micro benchmarks for the hot paths.
//!
//! They are `#[ignore]`d by default: run them with
//! `cargo test -p hakimi-core --lib -- --ignored --nocapture`.
//!
//! The numbers are only comparable between two builds of the same
//! measurement (same machine, same command).  They measure the code under
//! test, not the network: everything is in-process and loopback free.

use std::time::Instant;

/// Run `body` `rounds` times and report the average per round.
pub fn measure(name: &str, rounds: u32, mut body: impl FnMut()) {
    // Warm up once so the first round does not pay the lazy allocations.
    body();
    let started = Instant::now();
    for _ in 0..rounds {
        body();
    }
    let elapsed = started.elapsed();
    println!(
        "{name:<28} {:>10.1} ns/op   ({rounds} rounds in {elapsed:?})",
        elapsed.as_nanos() as f64 / f64::from(rounds)
    );
}
