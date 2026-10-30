//! Address gate for one route discovery.
//!
//! TCP reachability is a property of the address; TLS success is a property of
//! the (address, SNI, ECH) triple. The race used to treat every plan as an
//! independent candidate, so a silent address paid one full timeout per fake
//! SNI variant: with an eight-slot race window and five plans per address the
//! whole variant list of an address was already in flight before the first
//! timeout could retire it. Cursor-level bookkeeping could only skip plans that
//! had not been generated yet, which never happened.
//!
//! The gate keeps the two levels apart. The first plan of an address probes it;
//! the remaining variants wait for that attempt to report back:
//!
//! - an address-level failure (`tcp_timeout`, `tcp_refused`, `tcp_unreachable`)
//!   retires the address and drops the queue without spending a timeout each;
//! - a variant-level failure (`tls_reset`, `cert_invalid`, `tls_timeout`, ...)
//!   proves TCP came up, so the whole queue is released in one batch.
//!
//! A successful probe ends the race, so the queue is discarded with it: the
//! variants only cost a connection when the first one actually failed.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::decision::ConnectPlan;
use crate::strategy::FailureReason;

/// What the race knows about one address within a single discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressState {
    /// One plan is dialling the address; its variants wait for the verdict.
    Probing,
    /// The address answered and the first variant failed: the rest may race.
    Open,
    /// A TCP-level failure retired the address for the rest of the discovery.
    Dead,
}

pub(super) struct IpGate {
    states: HashMap<IpAddr, AddressState>,
    waiting: VecDeque<ConnectPlan>,
    discarded: usize,
}

impl IpGate {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            waiting: VecDeque::new(),
            discarded: 0,
        }
    }

    /// Hand a generated plan to the gate.
    ///
    /// `Some` starts the plan now. `None` means it was queued behind its
    /// address' probe, or discarded because the address is already dead.
    pub fn admit(&mut self, plan: ConnectPlan) -> Option<ConnectPlan> {
        match self.states.get(&plan.ip).copied() {
            Some(AddressState::Open) => Some(plan),
            Some(AddressState::Probing) => {
                self.waiting.push_back(plan);
                None
            }
            Some(AddressState::Dead) => {
                self.discarded += 1;
                None
            }
            None => {
                self.states.insert(plan.ip, AddressState::Probing);
                Some(plan)
            }
        }
    }

    /// A plan finished with `reason`.
    ///
    /// The reason carries the stage: only an address-level failure retires the
    /// address, anything else means the address answered and only this variant
    /// did not, which releases the queue.
    pub fn record_failure(&mut self, ip: IpAddr, reason: FailureReason) {
        if reason.is_ip_level() {
            self.states.insert(ip, AddressState::Dead);
            let before = self.waiting.len();
            self.waiting.retain(|plan| plan.ip != ip);
            self.discarded += before - self.waiting.len();
            return;
        }
        if self.states.get(&ip) != Some(&AddressState::Dead) {
            self.states.insert(ip, AddressState::Open);
        }
    }

    /// Plans that may start now, capped at `limit`. Queued plans of a dead
    /// address are dropped here as a safety net.
    pub fn drain_ready(&mut self, limit: usize) -> Vec<ConnectPlan> {
        let mut ready = Vec::new();
        let mut index = 0;
        while index < self.waiting.len() && ready.len() < limit {
            match self.states.get(&self.waiting[index].ip).copied() {
                Some(AddressState::Open) => {
                    if let Some(plan) = self.waiting.remove(index) {
                        ready.push(plan);
                    }
                }
                Some(AddressState::Dead) => {
                    self.waiting.remove(index);
                    self.discarded += 1;
                }
                _ => index += 1,
            }
        }
        ready
    }

    /// True when no queued plan can ever start again.
    pub fn is_idle(&self) -> bool {
        self.waiting.is_empty()
    }

    /// Variants dropped because their address was retired before they started.
    pub fn discarded(&self) -> usize {
        self.discarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::{IpSource, TlsMode};

    fn plan(ip: &str, sni: &str) -> ConnectPlan {
        ConnectPlan {
            domain: "example.com".into(),
            group_id: "g".into(),
            ip: ip.parse().unwrap(),
            port: 443,
            mode: TlsMode::FakeSni,
            sni: Some(sni.into()),
            ech_config: None,
            tls: true,
            source: IpSource::Remote,
        }
    }

    fn direct(ip: &str) -> ConnectPlan {
        ConnectPlan {
            mode: TlsMode::Direct,
            sni: None,
            ..plan(ip, "unused")
        }
    }

    #[test]
    fn only_the_first_plan_of_an_address_starts() {
        let mut gate = IpGate::new();
        assert!(gate.admit(plan("1.1.1.1", "a")).is_some());
        assert!(gate.admit(plan("1.1.1.1", "b")).is_none());
        assert!(gate.admit(plan("1.1.1.1", "c")).is_none());
        assert!(!gate.is_idle());
        assert_eq!(gate.discarded(), 0);
    }

    #[test]
    fn a_variant_failure_opens_every_variant_of_that_address() {
        let mut gate = IpGate::new();
        let first = gate.admit(plan("1.1.1.1", "a")).unwrap();
        gate.admit(plan("1.1.1.1", "b"));
        gate.admit(plan("1.1.1.1", "c"));
        // The first variant failed after TCP came up, so the address is usable.
        gate.record_failure(first.ip, FailureReason::TlsReset);
        let ready = gate.drain_ready(8);
        assert_eq!(ready.len(), 2, "the two queued variants must start");
        assert!(gate.admit(direct("1.1.1.1")).is_some(), "later plans pass");
        assert!(gate.is_idle());
    }

    #[test]
    fn a_tcp_failure_retires_the_address_and_its_queue() {
        let mut gate = IpGate::new();
        let first = gate.admit(plan("1.1.1.1", "a")).unwrap();
        gate.admit(plan("1.1.1.1", "b"));
        gate.admit(plan("1.1.1.1", "c"));
        gate.record_failure(first.ip, FailureReason::TcpTimeout);
        assert!(gate.is_idle(), "queued variants must be dropped");
        assert_eq!(gate.discarded(), 2);
        assert!(
            gate.admit(direct("1.1.1.1")).is_none(),
            "no new plan may start on a retired address"
        );
        assert!(gate.drain_ready(8).is_empty());
    }

    #[test]
    fn a_tls_failure_keeps_the_address_open() {
        let mut gate = IpGate::new();
        let first = gate.admit(plan("1.1.1.1", "a")).unwrap();
        gate.admit(plan("1.1.1.1", "b"));
        gate.record_failure(first.ip, FailureReason::TlsReset);
        assert_eq!(gate.drain_ready(8).len(), 1, "b must still be tried");
        assert!(gate.admit(direct("1.1.1.1")).is_some());
    }

    #[test]
    fn addresses_are_judged_independently() {
        let mut gate = IpGate::new();
        let dead = gate.admit(plan("1.1.1.1", "a")).unwrap();
        let live = gate.admit(plan("2.2.2.2", "a")).unwrap();
        gate.admit(plan("1.1.1.1", "b"));
        gate.admit(plan("2.2.2.2", "b"));

        gate.record_failure(dead.ip, FailureReason::TcpTimeout);
        gate.record_failure(live.ip, FailureReason::SniRejected);

        let ready = gate.drain_ready(8);
        assert_eq!(ready.len(), 1, "only the reachable address keeps variants");
        assert_eq!(ready[0].ip, live.ip);
        assert!(gate.is_idle());
    }

    #[test]
    fn draining_respects_the_window() {
        let mut gate = IpGate::new();
        let first = gate.admit(plan("1.1.1.1", "a")).unwrap();
        gate.admit(plan("1.1.1.1", "b"));
        gate.admit(plan("1.1.1.1", "c"));
        gate.record_failure(first.ip, FailureReason::TlsError);
        assert_eq!(gate.drain_ready(1).len(), 1);
        assert_eq!(gate.drain_ready(8).len(), 1);
        assert!(gate.is_idle());
    }
}
