use super::{ResolveError, ResolveOutcome, Resolver};
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

const MAX_CACHE_ENTRIES: usize = 512;
const MAX_HOST_LENGTH: usize = 255;
const DEFAULT_TTL: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct CacheEntry {
    expires_at: Instant,
    addresses: Vec<String>,
}

/// Blocking resolver backed by the platform `getaddrinfo` implementation.
/// Keeps a small LRU cache so repeated lookups avoid hammering system DNS.
#[derive(Debug)]
pub struct SystemResolver {
    cache: RwLock<HashMap<String, CacheEntry>>,
    order: RwLock<VecDeque<String>>,
    ttl: Duration,
}

impl Default for SystemResolver {
    fn default() -> Self {
        Self::new(DEFAULT_TTL)
    }
}

impl SystemResolver {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            order: RwLock::new(VecDeque::new()),
            ttl: ttl.max(Duration::from_secs(1)),
        }
    }

    fn cache_lookup(&self, host: &str) -> Option<Vec<String>> {
        let now = Instant::now();
        if let Some(entry) = self.cache.read().get(host) {
            if entry.expires_at > now {
                return Some(entry.addresses.clone());
            }
        }
        // Drop expired entry if it exists.
        {
            let mut cache = self.cache.write();
            if let std::collections::hash_map::Entry::Occupied(entry) =
                cache.entry(host.to_string())
            {
                if entry.get().expires_at <= now {
                    entry.remove();
                    self.remove_from_order(host);
                }
            }
        }
        None
    }

    fn cache_insert(&self, host: &str, addresses: &[String]) {
        if addresses.is_empty() {
            return;
        }
        let expires_at = Instant::now() + self.ttl;
        {
            let mut cache = self.cache.write();
            cache.insert(
                host.to_string(),
                CacheEntry {
                    expires_at,
                    addresses: addresses.to_vec(),
                },
            );
        }
        let mut evicted = Vec::new();
        {
            let mut order = self.order.write();
            order.retain(|entry| entry != host);
            order.push_back(host.to_string());
            while order.len() > MAX_CACHE_ENTRIES {
                if let Some(oldest) = order.pop_front() {
                    evicted.push(oldest);
                }
            }
        }
        if !evicted.is_empty() {
            let mut cache = self.cache.write();
            for key in evicted {
                cache.remove(&key);
            }
        }
    }

    fn remove_from_order(&self, host: &str) {
        let mut order = self.order.write();
        if let Some(position) = order.iter().position(|entry| entry == host) {
            order.remove(position);
        }
    }

    fn query_system(&self, host: &str) -> Result<Vec<String>, ResolveError> {
        let iter = (host, 0)
            .to_socket_addrs()
            .map_err(|error| ResolveError::LookupFailed(error.to_string()))?;
        let mut results: Vec<String> = Vec::new();
        for socket in iter {
            let address = socket.ip().to_string();
            if !results.contains(&address) {
                results.push(address);
            }
        }
        if results.is_empty() {
            Err(ResolveError::LookupFailed(
                "resolver returned no addresses".into(),
            ))
        } else {
            Ok(results)
        }
    }
}

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> Result<ResolveOutcome, ResolveError> {
        let trimmed = host.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_HOST_LENGTH {
            return Err(ResolveError::Unsupported);
        }
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Ok(ResolveOutcome {
                addresses: vec![ip.to_string()],
                ttl: self.ttl,
            });
        }
        if let Some(cached) = self.cache_lookup(trimmed) {
            return Ok(ResolveOutcome {
                addresses: cached,
                ttl: self.ttl,
            });
        }
        let addresses = self.query_system(trimmed)?;
        self.cache_insert(trimmed, &addresses);
        Ok(ResolveOutcome {
            addresses,
            ttl: self.ttl,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_hosts() {
        let resolver = SystemResolver::default();
        assert!(matches!(
            resolver.resolve(""),
            Err(ResolveError::Unsupported)
        ));
    }

    #[test]
    fn resolves_ip_literals() {
        let resolver = SystemResolver::default();
        let result = resolver.resolve("2001:4860:4860::8888").unwrap();
        assert_eq!(result.addresses, vec!["2001:4860:4860::8888".to_string()]);
    }

    #[test]
    fn resolves_localhost() {
        let resolver = SystemResolver::default();
        let result = resolver.resolve("localhost").unwrap();
        assert!(!result.addresses.is_empty());
    }
}
