//! Per-domain IP quality scores.

/// Rank of an address that has never been observed. Lower is better.
///
/// It deliberately sits below the all-failure floor (90_000): an untested
/// address is a better bet than one that has only ever timed out, while any
/// address that has succeeded at least once still leads. Using `f64::MAX`
/// here made every failed address outrank every untested one, so a black-holed
/// cached route kept its first-place slot.
pub(super) const UNSEEN_RANK: f64 = 50_000.0;

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
            return UNSEEN_RANK;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unseen_addresses_rank_between_healthy_and_never_working() {
        let healthy = IpScore {
            ewma_ms: 100.0,
            successes: 1,
            failures: 0,
        }
        .rank();
        let failed = IpScore {
            ewma_ms: 10_000.0,
            successes: 0,
            failures: 1,
        }
        .rank();

        assert_eq!(IpScore::default().rank(), UNSEEN_RANK);
        assert!(healthy < UNSEEN_RANK, "a proven address must lead");
        assert!(
            UNSEEN_RANK < failed,
            "an untested address must rank ahead of a known-dead one"
        );
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
