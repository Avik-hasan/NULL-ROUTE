//! Enrollment helper: generate X25519 static keypairs and a PSK, base64-encoded
//! for pasting into client.json / server.json.
//!
//! NOTE: `tools/keygen` is intentionally NOT a workspace member so `cargo build
//! --workspace` stays focused on shippable artifacts. Build it explicitly:
//!   cargo run --manifest-path tools/keygen/Cargo.toml

use rand::RngCore;
use vpn_core::crypto::generate_static_keypair;
use vpn_shared::Result;

fn b64(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn main() -> Result<()> {
    let server = generate_static_keypair()?;
    let client = generate_static_keypair()?;
    let mut psk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut psk);

    println!("# --- shared ---");
    println!("preshared_key       = {}", b64(&psk));
    println!("# --- server ---");
    println!("server_private_key  = {}", b64(&server.private));
    println!("server_public_key   = {}", b64(&server.public));
    println!("# --- client ---");
    println!("client_private_key  = {}", b64(&client.private));
    println!("client_public_key   = {}", b64(&client.public));
    Ok(())
}
