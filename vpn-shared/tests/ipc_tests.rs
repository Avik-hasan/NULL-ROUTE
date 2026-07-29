use vpn_shared::ipc::{IpcCommand, IpcResponse};
use vpn_shared::PROTOCOL_VERSION;

#[test]
fn test_ipc_hello_serialization() {
    let cmd = IpcCommand::Hello { protocol_version: PROTOCOL_VERSION };
    let json = serde_json::to_string(&cmd).unwrap();
    assert!(json.contains(r#""cmd":"hello""#));
    assert!(json.contains(&format!(r#""protocol_version":{}"#, PROTOCOL_VERSION)));
}

#[test]
fn test_ipc_connect_serialization() {
    let cmd = IpcCommand::Connect { node_index: 2 };
    let json = serde_json::to_string(&cmd).unwrap();
    assert!(json.contains(r#""cmd":"connect""#));
    assert!(json.contains(r#""node_index":2"#));
}

#[test]
fn test_ipc_response_error() {
    let resp = IpcResponse::Error { message: "test error".into() };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains(r#""resp":"error""#));
    assert!(json.contains(r#""message":"test error""#));
}
