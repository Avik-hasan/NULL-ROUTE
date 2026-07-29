use vpn_shared::config::ClientConfig;

#[test]
fn test_client_config_defaults() {
    let raw_json = r#"{
        "nodes": [],
        "client_private_key": "some_key",
        "preshared_key": "some_psk"
    }"#;

    let cfg: ClientConfig = serde_json::from_str(raw_json).unwrap();
    
    // Test defaults applied correctly
    assert_eq!(cfg.hop_interval_secs, 300);
    assert_eq!(cfg.block_webrtc, true);
    assert_eq!(cfg.kill_switch, true);
}

#[test]
fn test_client_config_overrides() {
    let raw_json = r#"{
        "nodes": [],
        "client_private_key": "some_key",
        "preshared_key": "some_psk",
        "hop_interval_secs": 60,
        "block_webrtc": false,
        "kill_switch": false
    }"#;

    let cfg: ClientConfig = serde_json::from_str(raw_json).unwrap();
    
    // Test overrides applied correctly
    assert_eq!(cfg.hop_interval_secs, 60);
    assert_eq!(cfg.block_webrtc, false);
    assert_eq!(cfg.kill_switch, false);
}
