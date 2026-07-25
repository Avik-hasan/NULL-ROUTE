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

use snow::{Builder, HandshakeState, Keypair};

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

/// Builds a [`HandshakeState`] for either side of `Noise_IKpsk2`.
pub fn build_handshake(
    role: Role,
    local_private: &[u8],
    remote_public: Option<&[u8]>,
    psk: &[u8],
) -> Result<HandshakeState> {
    let params = NOISE_PARAMS
        .parse()
        .map_err(|e| VpnError::Crypto(format!("bad noise params: {e}")))?;

    let mut builder = Builder::new(params)
        .local_private_key(local_private)
        // psk2 => the PSK is mixed at message index 2.
        .psk(2, psk);

    // IK requires the initiator to already know the responder's static key.
    if role == Role::Initiator {
        let rk = remote_public.ok_or_else(|| {
            VpnError::Handshake("initiator requires remote static public key".into())
        })?;
        builder = builder
            .remote_public_key(rk);
    }

    let hs = match role {
        Role::Initiator => builder.build_initiator(),
        Role::Responder => builder.build_responder(),
    }
    .map_err(|e| VpnError::Handshake(format!("handshake build failed: {e}")))?;
    Ok(hs)
}
