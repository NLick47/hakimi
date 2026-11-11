//! Image relays: send a request for one host to a prefix on another host.
//!
//! `https://i.pximg.net/img-original/x.jpg` becomes
//! `https://relay.example/pximg/img-original/x.jpg`. Only the URL and a few
//! headers change; the response is forwarded untouched. This is the mechanism
//! behind "pixiv 图片中转", but nothing in here is pixiv-specific.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, StatusCode, Uri};
use parking_lot::RwLock;

use crate::config::{AppConfig, ImageRelayRule};

/// A relay that fails this many times in a row is parked instead of being
/// retried on every image, which would put the connect wait in front of the
/// direct fallback.
const FAILURES_BEFORE_COOLDOWN: usize = 3;
const COOLDOWN: Duration = Duration::from_secs(60);

pub(crate) struct RelayPlan {
    pub(crate) id: String,
    pub(crate) uri: Uri,
    pub(crate) headers: HeaderMap,
    pub(crate) fallback_direct: bool,
    pub(crate) parked: bool,
    /// Header-wait budget. A relay that cannot answer in this window is
    /// treated as failed, so a stuck relay costs this much, not a minute.
    pub(crate) timeout: Duration,
}

/// What a relayed body actually delivered. The header wait in the pool log
/// says nothing about the download, and a slow image has to be told apart from
/// a slow relay by the log alone.
pub(crate) struct BodyTrace {
    pub(crate) id: String,
    started: Instant,
    bytes: u64,
}

impl BodyTrace {
    pub(crate) fn new(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            started: Instant::now(),
            bytes: 0,
        }
    }

    pub(crate) fn note(&mut self, len: usize) {
        self.bytes += len as u64;
    }

    /// Bytes, milliseconds, and KiB/s for the finished body.
    pub(crate) fn finish(&self) -> (u64, u128, u64) {
        let ms = self.started.elapsed().as_millis().max(1);
        (self.bytes, ms, self.bytes * 1000 / ms as u64 / 1024)
    }
}

/// Pick the rule for this request and build the rewritten URI plus headers.
///
/// Returns `None` when no rule matches, the rule is disabled, or the request
/// cannot be replayed (`POST` has a body the empty retry cannot carry).
pub(crate) fn plan(
    config: &AppConfig,
    method: &Method,
    headers: &HeaderMap,
    uri: &Uri,
    health: &Health,
) -> Option<RelayPlan> {
    if *method != Method::GET && *method != Method::HEAD {
        return None;
    }
    let host = uri.host()?.trim_end_matches('.');
    // A rule only owns the request when its host list and its path list both
    // match. Otherwise the next rule gets its turn: a path filter is a reason
    // to skip this relay, not a reason to stop looking.
    let rule = config.advanced.image_relays.iter().find(|rule| {
        rule.enabled
            && rule.hosts.iter().any(|pattern| matches_host(pattern, host))
            && (rule.paths.is_empty()
                || rule
                    .paths
                    .iter()
                    .any(|prefix| uri.path().starts_with(prefix.as_str())))
    })?;
    let parked = health.is_parked(&rule.id);
    if parked && rule.fallback_direct {
        return None;
    }

    let base = rule.base.trim_end_matches('/');
    if base.is_empty() {
        return None;
    }
    let path = uri.path_and_query()?.as_str();
    let uri: Uri = format!("{base}{path}").parse().ok()?;
    let headers = relayed_headers(headers, rule, &uri);
    Some(RelayPlan {
        id: rule.id.clone(),
        fallback_direct: rule.fallback_direct,
        parked,
        timeout: Duration::from_millis(rule.timeout_ms),
        uri,
        headers,
    })
}

/// Same semantics as `DomainPattern`: an exact name, or `*.suffix` for
/// subdomains only. Written out by hand so the per-image path stays
/// allocation-free.
pub(crate) fn matches_host(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => {
            host.len() > suffix.len()
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
                && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        }
        None => host.eq_ignore_ascii_case(pattern),
    }
}

/// A relay that refuses or breaks should not keep the user waiting for bytes
/// that will never arrive, so these statuses count as "try the origin".
pub(crate) fn should_fallback(status: StatusCode) -> bool {
    status == StatusCode::FORBIDDEN
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn relayed_headers(source: &HeaderMap, rule: &ImageRelayRule, uri: &Uri) -> HeaderMap {
    let mut headers = source.clone();
    super::third_party::strip_request_credentials(&mut headers);

    if let Some(authority) = uri.authority() {
        if let Ok(value) = HeaderValue::from_str(authority.as_str()) {
            headers.insert(header::HOST, value);
        }
    }
    if let Some(referer) = rule.referer.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        if let Ok(value) = HeaderValue::from_str(referer) {
            headers.insert(header::REFERER, value);
        }
    }
    if let Some(agent) = rule
        .user_agent
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        if let Ok(value) = HeaderValue::from_str(agent) {
            headers.insert(header::USER_AGENT, value);
        }
    }
    headers
}

/// Consecutive-failure memory per rule, so a relay that is down costs one
/// failed attempt per minute instead of one per image.
#[derive(Default)]
pub(crate) struct Health {
    rules: RwLock<HashMap<String, Entry>>,
}

#[derive(Default)]
struct Entry {
    failures: usize,
    until: Option<Instant>,
}

impl Health {
    pub(crate) fn is_parked(&self, id: &str) -> bool {
        self.rules
            .read()
            .get(id)
            .and_then(|entry| entry.until)
            .is_some_and(|until| until > Instant::now())
    }

    pub(crate) fn note_success(&self, id: &str) {
        // A healthy relay has no entry; keep successful images off the write lock.
        if self.rules.read().contains_key(id) {
            self.rules.write().remove(id);
        }
    }

    pub(crate) fn note_failure(&self, id: &str) {
        let mut rules = self.rules.write();
        let entry = rules.entry(id.to_owned()).or_default();
        entry.failures += 1;
        if entry.failures >= FAILURES_BEFORE_COOLDOWN {
            entry.failures = 0;
            entry.until = Some(Instant::now() + COOLDOWN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ImageRelayRule;

    fn config_with(rule: ImageRelayRule) -> AppConfig {
        let mut config = AppConfig::default();
        config.advanced.image_relays = vec![rule];
        config
    }

    fn pixiv_rule() -> ImageRelayRule {
        ImageRelayRule {
            id: "pixiv".into(),
            enabled: true,
            hosts: vec!["i.pximg.net".into()],
            base: "https://relay.example/pximg".into(),
            referer: Some("https://www.pixiv.net/".into()),
            user_agent: Some("Relay/1.0".into()),
            fallback_direct: true,
            ..ImageRelayRule::default()
        }
    }

    fn request_uri() -> Uri {
        "https://i.pximg.net/img-original/img/2025/12/25/23/44/02/139062544_p0.jpg?x=1"
            .parse()
            .unwrap()
    }

    /// Every call in these tests wants a fresh health record; the cooldown
    /// behaviour has its own test below.
    fn try_plan(config: &AppConfig, method: &Method, headers: &HeaderMap, uri: &Uri) -> Option<RelayPlan> {
        plan(config, method, headers, uri, &Health::default())
    }

    #[test]
    fn rewrites_onto_the_prefix_and_keeps_path_and_query() {
        let config = config_with(pixiv_rule());
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("i.pximg.net"));
        let plan = try_plan(&config, &Method::GET, &headers, &request_uri()).expect("rule matches");
        assert_eq!(
            plan.uri.to_string(),
            "https://relay.example/pximg/img-original/img/2025/12/25/23/44/02/139062544_p0.jpg?x=1"
        );
        assert_eq!(
            plan.headers.get(header::HOST).unwrap(),
            "relay.example",
            "upstream must see the relay host, not the origin host"
        );
        assert_eq!(
            plan.headers.get(header::REFERER).unwrap(),
            "https://www.pixiv.net/"
        );
        assert_eq!(plan.headers.get(header::USER_AGENT).unwrap(), "Relay/1.0");
    }

    #[test]
    fn a_relay_never_sees_the_browser_session() {
        let config = config_with(pixiv_rule());
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("PHPSESSID=secret"));
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        let plan = try_plan(&config, &Method::GET, &headers, &request_uri()).unwrap();
        assert!(!plan.headers.contains_key(header::COOKIE));
        assert!(!plan.headers.contains_key(header::AUTHORIZATION));
    }

    #[test]
    fn a_disabled_rule_or_a_different_host_is_left_alone() {
        let mut rule = pixiv_rule();
        rule.enabled = false;
        let headers = HeaderMap::new();
        assert!(try_plan(&config_with(rule), &Method::GET, &headers, &request_uri()).is_none());

        let other: Uri = "https://s.pximg.net/a.jpg".parse().unwrap();
        assert!(try_plan(&config_with(pixiv_rule()), &Method::GET, &headers, &other).is_none());
    }

    #[test]
    fn only_replayable_methods_are_rewritten() {
        let config = config_with(pixiv_rule());
        let headers = HeaderMap::new();
        assert!(try_plan(&config, &Method::GET, &headers, &request_uri()).is_some());
        assert!(try_plan(&config, &Method::HEAD, &headers, &request_uri()).is_some());
        assert!(try_plan(&config, &Method::POST, &headers, &request_uri()).is_none());
    }

    #[test]
    fn wildcard_hosts_cover_subdomains_but_not_the_apex() {
        assert!(matches_host("*.pximg.net", "i.pximg.net"));
        assert!(matches_host("*.pximg.net", "a.b.pximg.net"));
        assert!(!matches_host("*.pximg.net", "pximg.net"));
        assert!(!matches_host("*.pximg.net", "notpximg.net"));
        assert!(matches_host("i.pximg.net", "I.PXIMG.NET"));
    }

    #[test]
    fn path_prefixes_keep_thumbnails_off_the_relay() {
        let mut rule = pixiv_rule();
        rule.paths = vec!["/img-original/".into()];
        let config = config_with(rule);
        let headers = HeaderMap::new();
        assert!(try_plan(&config, &Method::GET, &headers, &request_uri()).is_some());

        let thumbnail: Uri = "https://i.pximg.net/c/540x540_70/img-master/img/2025/12/25/23/44/02/139062544_p0_master1200.jpg".parse().unwrap();
        assert!(
            try_plan(&config, &Method::GET, &headers, &thumbnail).is_none(),
            "a size variant must stay on the origin path"
        );
    }

    /// Two lists, two independent "any of" checks: the host only has to be
    /// listed in `hosts`, the path only has to start with an entry in `paths`.
    /// Every pairing counts, and order inside either list is irrelevant.
    #[test]
    fn several_hosts_and_paths_are_two_independent_any_of_lists() {
        let mut rule = pixiv_rule();
        rule.hosts = vec!["i.pximg.net".into(), "*.pximg.net".into()];
        rule.paths = vec!["/img-original/".into(), "/img-master/".into()];
        let config = config_with(rule);
        let headers = HeaderMap::new();
        let relays = |url: &str| {
            let uri: Uri = url.parse().unwrap();
            try_plan(&config, &Method::GET, &headers, &uri).is_some()
        };

        assert!(relays("https://i.pximg.net/img-original/a.jpg"), "first host, first path");
        assert!(relays("https://i.pximg.net/img-master/a.jpg"), "first host, second path");
        assert!(relays("https://s.pximg.net/img-master/a.jpg"), "wildcard host, second path");
        assert!(
            !relays("https://i.pximg.net/c/250x250/img-master/a.jpg"),
            "a size variant starts with /c/, which is in neither path entry"
        );
        assert!(!relays("https://i.pximg.net/img/a.jpg"), "host matches, no path does");
        assert!(
            !relays("https://example.com/img-original/a.jpg"),
            "path matches, no host does"
        );
    }

    /// An empty list means "every path on those hosts", not "no path".
    #[test]
    fn an_empty_path_list_relays_every_path() {
        let mut rule = pixiv_rule();
        rule.paths.clear();
        let config = config_with(rule);
        let uri: Uri = "https://i.pximg.net/c/250x250/img-master/a.jpg"
            .parse()
            .unwrap();
        assert!(try_plan(&config, &Method::GET, &HeaderMap::new(), &uri).is_some());
    }

    /// A rule that matches the host but not the path does not own the request:
    /// the next rule still gets its turn.
    #[test]
    fn a_path_miss_falls_through_to_the_next_rule() {
        let mut original = pixiv_rule();
        original.id = "original".into();
        original.paths = vec!["/img-original/".into()];
        let mut preview = pixiv_rule();
        preview.id = "preview".into();
        preview.paths = vec!["/img-master/".into()];
        preview.base = "https://preview.example/pximg".into();
        let mut config = AppConfig::default();
        config.advanced.image_relays = vec![original, preview];

        let uri: Uri = "https://i.pximg.net/img-master/a.jpg".parse().unwrap();
        let plan = try_plan(&config, &Method::GET, &HeaderMap::new(), &uri)
            .expect("the second rule covers this path");
        assert_eq!(plan.id, "preview");
        assert_eq!(plan.uri.to_string(), "https://preview.example/pximg/img-master/a.jpg");
    }

    #[test]
    fn the_header_wait_budget_is_bounded() {
        let plan = try_plan(
            &config_with(pixiv_rule()),
            &Method::GET,
            &HeaderMap::new(),
            &request_uri(),
        )
        .unwrap();
        assert_eq!(plan.timeout, Duration::from_millis(5_000));
    }

    #[test]
    fn blocking_and_broken_relays_fall_back_but_a_missing_image_does_not() {
        assert!(should_fallback(StatusCode::FORBIDDEN));
        assert!(should_fallback(StatusCode::TOO_MANY_REQUESTS));
        assert!(should_fallback(StatusCode::BAD_GATEWAY));
        assert!(!should_fallback(StatusCode::NOT_FOUND));
        assert!(!should_fallback(StatusCode::OK));
    }

    #[test]
    fn a_relay_is_parked_after_three_failures_and_revived_by_a_success() {
        let health = Health::default();
        for _ in 0..FAILURES_BEFORE_COOLDOWN - 1 {
            health.note_failure("pixiv");
        }
        assert!(!health.is_parked("pixiv"));
        health.note_failure("pixiv");
        assert!(health.is_parked("pixiv"));
        health.note_success("pixiv");
        assert!(!health.is_parked("pixiv"));
    }

    #[test]
    fn a_parked_relay_only_bypasses_when_direct_fallback_is_allowed() {
        let health = Health::default();
        for _ in 0..FAILURES_BEFORE_COOLDOWN {
            health.note_failure("pixiv");
        }
        let headers = HeaderMap::new();
        let uri = request_uri();

        let allowed = config_with(pixiv_rule());
        assert!(plan(&allowed, &Method::GET, &headers, &uri, &health).is_none());

        let mut blocked_rule = pixiv_rule();
        blocked_rule.fallback_direct = false;
        let blocked = config_with(blocked_rule);
        let plan = plan(&blocked, &Method::GET, &headers, &uri, &health)
            .expect("the caller must see that the relay is parked");
        assert!(plan.parked);
        assert!(!plan.fallback_direct);
    }
}
