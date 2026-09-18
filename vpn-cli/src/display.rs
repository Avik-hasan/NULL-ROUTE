use vpn_shared::telemetry::Telemetry;

pub fn print_status(telemetry: &Telemetry) {
    println!("=== NULL-ROUTE Connection Status ===");
    println!("State:         {:?}", telemetry.state);
    println!("Active Node:   {}", telemetry.active_node.as_deref().unwrap_or("None"));
    
    if telemetry.bytes_rx > 0 || telemetry.bytes_tx > 0 {
        println!();
        println!("--- Traffic Statistics ---");
        println!("Data Sent:     {} bytes", format_bytes(telemetry.bytes_tx));
        println!("Data Received: {} bytes", format_bytes(telemetry.bytes_rx));
    }
    
    println!("====================================");
}

pub fn print_error(msg: &str) {
    eprintln!("\x1b[31m[ERROR]\x1b[0m {}", msg);
}

pub fn print_success(msg: &str) {
    println!("\x1b[32m[SUCCESS]\x1b[0m {}", msg);
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}")
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / 1048576.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1073741824.0)
    }
}
