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
    assert!(
        manager.decision_for_ip(&addr).is_some(),
        "entry should survive ttl while within grace period"
    );
    thread::sleep(Duration::from_millis((STALE_GRACE_SECONDS * 1000) + 1500));
    assert!(manager.decision_for_ip(&addr).is_none());
}
