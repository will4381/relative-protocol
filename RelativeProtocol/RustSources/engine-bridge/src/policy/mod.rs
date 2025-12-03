use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};
use wildmatch::WildMatch;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShapingConfig {
    pub latency_ms: u32,
    pub jitter_ms: u32,
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
    ip_target: Option<IpAddr>,
}

#[derive(Clone, Debug)]
struct ObservedHost {
    host: String,
    expires_at: StdInstant,
}

const DEFAULT_TTL_SECONDS: u32 = 60;
const MIN_TTL_SECONDS: u32 = 1;
const MAX_TTL_SECONDS: u32 = 3600;
const MAX_HOSTS_PER_IP: usize = 16;
const STALE_GRACE_SECONDS: u64 = 5;

pub struct PolicyManager {
    rules: RwLock<Vec<HostRule>>,
    next_id: AtomicU64,
    dns_map: RwLock<HashMap<IpAddr, Vec<ObservedHost>>>,
    ip_rules: RwLock<HashMap<IpAddr, RuleAction>>,
}

impl PolicyManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            rules: RwLock::new(Vec::new()),
            next_id: AtomicU64::new(1),
            dns_map: RwLock::new(HashMap::new()),
            ip_rules: RwLock::new(HashMap::new()),
        })
    }

    pub fn install_rule(self: &Arc<Self>, pattern: &str, action: RuleAction) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let normalized = pattern.to_ascii_lowercase();
        let ip_target = normalized.parse::<IpAddr>().ok();
        if let Some(ip) = ip_target {
            self.ip_rules.write().insert(ip, action.clone());
        }
        let matcher = WildMatch::new(&normalized);
        let rule = HostRule {
            id,
            pattern: normalized,
            matcher,
            action,
            ip_target,
        };
        self.rules.write().push(rule);
        id
    }

    pub fn remove_rule(&self, id: u64) -> bool {
        let mut removed_ip = None;
        let mut guard = self.rules.write();
        let len_before = guard.len();
        guard.retain(|rule| {
            if rule.id == id {
                if removed_ip.is_none() {
                    removed_ip = rule.ip_target;
                }
                false
            } else {
                true
            }
        });
        drop(guard);
        if let Some(ip) = removed_ip {
            let should_keep = self
                .rules
                .read()
                .iter()
                .any(|rule| rule.ip_target == Some(ip));
            if !should_keep {
                self.ip_rules.write().remove(&ip);
            }
        }
        len_before != self.rules.read().len()
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
        // Track if we've already cloned the host string
        let mut cloned_host: Option<String> = None;
        for addr in addresses {
            let entry = guard.entry(*addr).or_default();
            retain_with_grace(entry, now);
            if let Some(existing) = entry.iter_mut().find(|record| record.host == normalized) {
                existing.expires_at = expires_at;
            } else {
                if entry.len() >= MAX_HOSTS_PER_IP {
                    entry.remove(0);
                }
                // Only clone the host string once, reuse for subsequent addresses
                let host_string = cloned_host.get_or_insert_with(|| normalized.clone()).clone();
                entry.push(ObservedHost {
                    host: host_string,
                    expires_at,
                });
            }
        }
    }

    pub fn decision_for_ip(&self, addr: &IpAddr) -> Option<PolicyDecision> {
        if let Some(action) = self.ip_rules.read().get(addr).cloned() {
            return Some(PolicyDecision {
                host: addr.to_string(),
                action,
            });
        }

        let now = StdInstant::now();
        let mut guard = self.dns_map.write();
        let entry = guard.get_mut(addr)?;
        retain_with_grace(entry, now);
        if entry.is_empty() {
            guard.remove(addr);
            return None;
        }
        let mut stale_candidate: Option<PolicyDecision> = None;
        for record in entry.iter().rev() {
            if let Some(action) = self.match_host(&record.host) {
                if record.expires_at > now {
                    return Some(PolicyDecision {
                        host: record.host.clone(),
                        action,
                    });
                }
                if stale_candidate.is_none() {
                    stale_candidate = Some(PolicyDecision {
                        host: record.host.clone(),
                        action,
                    });
                }
            }
        }
        stale_candidate
    }

    pub fn match_host(&self, host: &str) -> Option<RuleAction> {
        let guard = self.rules.read();
        // Early return if no rules - avoids lowercase allocation
        if guard.is_empty() {
            return None;
        }
        let host_lower = host.to_ascii_lowercase();
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
        self.ip_rules.write().clear();
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
    let clamped = secs.clamp(MIN_TTL_SECONDS, MAX_TTL_SECONDS);
    Duration::from_secs(clamped as u64)
}

fn retain_with_grace(entries: &mut Vec<ObservedHost>, now: StdInstant) {
    let grace = Duration::from_secs(STALE_GRACE_SECONDS);
    entries.retain(|record| record.expires_at + grace > now);
}

#[cfg(test)]
mod tests;
