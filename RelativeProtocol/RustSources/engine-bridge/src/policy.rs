use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};
use wildmatch::WildMatch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShapingConfig {
    pub latency_ms: u32,
    pub jitter_ms: u32,
}

impl Default for ShapingConfig {
    fn default() -> Self {
        Self {
            latency_ms: 0,
            jitter_ms: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub enum RuleAction {
    Block,
    Shape(ShapingConfig),
}

#[derive(Clone, Debug)]
pub struct PolicyDecision {
    pub host: String,
    pub action: RuleAction,
}

#[derive(Clone, Debug)]
pub struct HostRule {
    pub id: u64,
    #[allow(dead_code)]
    pub pattern: String,
    matcher: WildMatch,
    pub action: RuleAction,
}

#[derive(Clone, Debug)]
struct ObservedHost {
    host: String,
    expires_at: StdInstant,
}

const DEFAULT_TTL_SECONDS: u32 = 60;
const MIN_TTL_SECONDS: u32 = 1;
const MAX_TTL_SECONDS: u32 = 3600;
const MAX_HOSTS_PER_IP: usize = 4;

pub struct PolicyManager {
    rules: RwLock<Vec<HostRule>>,
    next_id: AtomicU64,
    dns_map: RwLock<HashMap<IpAddr, Vec<ObservedHost>>>,
}

impl PolicyManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            rules: RwLock::new(Vec::new()),
            next_id: AtomicU64::new(1),
            dns_map: RwLock::new(HashMap::new()),
        })
    }

    pub fn install_rule(self: &Arc<Self>, pattern: &str, action: RuleAction) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let normalized = pattern.to_ascii_lowercase();
        let rule = HostRule {
            id,
            pattern: normalized.clone(),
            matcher: WildMatch::new(normalized.as_str()),
            action,
        };
        self.rules.write().push(rule);
        id
    }

    pub fn remove_rule(&self, id: u64) -> bool {
        let mut guard = self.rules.write();
        let len_before = guard.len();
        guard.retain(|rule| rule.id != id);
        len_before != guard.len()
    }

    pub fn observe_dns_mapping(&self, host: &str, addresses: &[IpAddr], ttl_seconds: Option<u32>) {
        if addresses.is_empty() {
            return;
        }
        let Some(normalized) = normalize_host(host) else {
            return;
        };
        let now = StdInstant::now();
        let expires_at = now + ttl_duration(ttl_seconds);
        let mut guard = self.dns_map.write();
        for addr in addresses {
            let entry = guard.entry(*addr).or_insert_with(Vec::new);
            retain_unexpired(entry, now);
            if let Some(existing) = entry.iter_mut().find(|record| record.host == normalized) {
                existing.expires_at = expires_at;
            } else {
                if entry.len() >= MAX_HOSTS_PER_IP {
                    entry.remove(0);
                }
                entry.push(ObservedHost {
                    host: normalized.clone(),
                    expires_at,
                });
            }
        }
    }

    pub fn decision_for_ip(&self, addr: &IpAddr) -> Option<PolicyDecision> {
        let now = StdInstant::now();
        let mut guard = self.dns_map.write();
        let entry = guard.get_mut(addr)?;
        retain_unexpired(entry, now);
        if entry.is_empty() {
            guard.remove(addr);
            return None;
        }
        for record in entry.iter().rev() {
            if let Some(action) = self.match_host(&record.host) {
                return Some(PolicyDecision {
                    host: record.host.clone(),
                    action,
                });
            }
        }
        None
    }

    pub fn match_host(&self, host: &str) -> Option<RuleAction> {
        let host_lower = host.to_ascii_lowercase();
        let guard = self.rules.read();
        for rule in guard.iter().rev() {
            if rule.matcher.matches(&host_lower) {
                return Some(rule.action.clone());
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn clear(&self) {
        self.rules.write().clear();
        self.dns_map.write().clear();
    }
}

fn normalize_host(host: &str) -> Option<String> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
}

fn ttl_duration(ttl_seconds: Option<u32>) -> Duration {
    let secs = ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    let clamped = secs.max(MIN_TTL_SECONDS).min(MAX_TTL_SECONDS);
    Duration::from_secs(clamped as u64)
}

fn retain_unexpired(entries: &mut Vec<ObservedHost>, now: StdInstant) {
    entries.retain(|record| record.expires_at > now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn decision_follows_dns_mapping() {
        let manager = PolicyManager::new();
        manager.install_rule("*.example.com", RuleAction::Block);
        let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        manager.observe_dns_mapping("Api.Example.com.", &[addr], Some(30));
        let decision = manager.decision_for_ip(&addr).expect("expected decision");
        assert_eq!(decision.host, "api.example.com");
        assert!(matches!(decision.action, RuleAction::Block));
    }

    #[test]
    fn decision_returns_shape_config() {
        let manager = PolicyManager::new();
        let config = ShapingConfig {
            latency_ms: 150,
            jitter_ms: 20,
        };
        manager.install_rule("video.host", RuleAction::Shape(config));
        let addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
        manager.observe_dns_mapping("video.host", &[addr], None);
        let decision = manager
            .decision_for_ip(&addr)
            .expect("expected shape decision");
        match decision.action {
            RuleAction::Shape(shape) => assert_eq!(shape, config),
            _ => panic!("expected shape decision"),
        }
    }

    #[test]
    fn ttl_expiration_removes_mappings() {
        let manager = PolicyManager::new();
        manager.install_rule("*.ttl.test", RuleAction::Block);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        manager.observe_dns_mapping("api.ttl.test", &[addr], Some(1));
        assert!(manager.decision_for_ip(&addr).is_some());
        thread::sleep(Duration::from_millis(1100));
        assert!(manager.decision_for_ip(&addr).is_none());
    }
}
