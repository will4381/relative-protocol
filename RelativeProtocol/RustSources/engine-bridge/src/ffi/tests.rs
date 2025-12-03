use super::*;

#[test]
fn populate_sets_addresses_and_ttl() {
    let mut result = BridgeResolveResult::default();
    let values = vec!["1.1.1.1".to_string(), "2606:4700:4700::1111".to_string()];
    assert!(result.populate(&values, 42).is_ok());
    assert_eq!(result.count, 2);
    assert_eq!(result.ttl_seconds, 42);
    unsafe {
        let slice = std::slice::from_raw_parts(result.addresses, result.count);
        for ptr in slice {
            assert!(!ptr.is_null());
            let text = std::ffi::CStr::from_ptr(*ptr);
            assert!(!text.to_string_lossy().is_empty());
        }
    }
    result.reset();
    assert_eq!(result.count, 0);
    assert!(result.addresses.is_null());
    assert_eq!(result.ttl_seconds, 0);
}
