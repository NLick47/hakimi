use std::net::IpAddr;

use crate::strategy::{DohSource, IpSource};

#[derive(Clone, Debug)]
pub(super) struct Candidate {
    pub(super) ip: IpAddr,
    pub(super) source: IpSource,
}

#[derive(Debug, Default)]
pub(super) struct DohExpansion {
    pub(super) source: Option<DohSource>,
    pub(super) error: Option<String>,
    pub(super) stale: bool,
}

/// Floor for the initial-candidate count at which DoH expansion is allowed.
/// The cursor only expands once the initial list is exhausted (or has room
/// below its cap), so a full catalog list delays DoH until every candidate
/// has failed; `prefetch_cold_route` covers that window for real traffic.
pub(super) const EARLY_DOH_AFTER: usize = 3;
