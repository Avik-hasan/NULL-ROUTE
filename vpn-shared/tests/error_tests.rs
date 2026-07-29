use vpn_shared::VpnError;

#[test]
fn test_vpn_error_display() {
    let err = VpnError::Config("missing nodes".into());
    assert_eq!(err.to_string(), "Configuration error: missing nodes");

    let err = VpnError::Timeout(5000);
    assert_eq!(err.to_string(), "Operation timed out after 5000ms");
}
