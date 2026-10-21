//! Per-domain IP quality scores.

#[derive(Clone, Copy, Default)]
pub(super) struct IpScore {
    pub(super) ewma_ms: f64,
    pub(super) successes: u32,
    pub(super) failures: u32,
}

impl IpScore {
    /// Lower is better. Latency dominates; failures are penalised hard.
    pub(super) fn rank(&self) -> f64 {
        if self.successes == 0 && self.failures == 0 {
            return f64::MAX;
        }
        let total = (self.successes + self.failures) as f64;
        let fail_rate = self.failures as f64 / total;
        let base = if self.successes == 0 {
            10_000.0
        } else {
            self.ewma_ms.max(1.0)
        };
        base * (1.0 + fail_rate * 8.0)
    }
}

/// How many (domain, ip) quality entries to keep in memory. The active set of a
/// heavy user stays well below this; growth past it evicts the worst-ranked.
/// A page loading assets from dozens of hosts already produces several hundred
/// entries, so a smaller cap made every connection sort the whole map.
pub(super) const IP_SCORE_CAP: usize = 1024;
/// Evict down to this many entries so the next few hundred observations do not
/// each pay for a full rank-and-sort pass.
pub(super) const IP_SCORE_PRUNE_TO: usize = IP_SCORE_CAP * 3 / 4;
