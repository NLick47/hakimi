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

/// Consume this many initial (catalog/cache) candidates before expanding with DoH.
pub(super) const EARLY_DOH_AFTER: usize = 3;
