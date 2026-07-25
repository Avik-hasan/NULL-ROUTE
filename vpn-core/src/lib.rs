//! Core library for the NULL-ROUTE VPN.
//!
//! Contains the cryptographic session engine, wire protocol, and
//! TCP MSS clamping logic shared between the client and server binaries.

pub mod crypto;
pub mod mss_clamp;
pub mod protocol;

/// The Noise protocol pattern string used across all handshakes.
pub const NOISE_PARAMS: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
