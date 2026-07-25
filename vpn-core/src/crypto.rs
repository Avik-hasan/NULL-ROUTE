//! Noise handshake + authenticated data-plane cipher.
//!
//! Handshake: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` via the `snow` crate.
//! Data plane: the negotiated `snow::TransportState` (ChaCha20-Poly1305) with an
//! **explicit monotonic counter** that is (a) placed in the wire header, (b)
//! used to derive the AEAD nonce, and (c) validated by the anti-replay window in
//! [`crate::protocol`].
//!
//! There are no `unwrap()`/`expect()` calls: every `snow`/cipher error is mapped
//! into [`VpnError`].

use snow::{Builder, Keypair};

use crate::NOISE_PARAMS;
use vpn_shared::{Result, VpnError};

/// Generate a fresh X25519 static keypair for enrollment.
pub fn generate_static_keypair() -> Result<Keypair> {
    let params = NOISE_PARAMS
        .parse()
        .map_err(|e| VpnError::Crypto(format!("bad noise params: {e}")))?;
    Builder::new(params)
        .generate_keypair()
        .map_err(|e| VpnError::Crypto(format!("keypair generation failed: {e}")))
}

/// Role in the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}
