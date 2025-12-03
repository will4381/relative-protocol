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
