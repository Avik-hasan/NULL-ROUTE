use vpn_shared::telemetry::{LogEvent, LogLevel};

#[test]
fn test_log_event_creation() {
    let msg = "test diagnostic line";
    let event = LogEvent::now(LogLevel::Warn, msg);
    
    assert_eq!(event.level, LogLevel::Warn);
    assert_eq!(event.message, msg);
    // Timestamp should be valid ISO 8601
    assert!(event.timestamp.ends_with('Z') || event.timestamp.contains('+'));
}
