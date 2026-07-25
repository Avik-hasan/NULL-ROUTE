//! Data-plane packet framing and the **anti-replay sliding window**.
//!
//! Wire frame (after Noise transport decryption the *inner* header is authed;
//! the *outer* header below is what rides on UDP and is protected by the AEAD
//! tag, so tampering with the counter breaks decryption):
//!
//! ```text
//! | u8 kind | u32 session_id (BE) | u64 counter (BE) | ...AEAD ciphertext... |
//! ```
//!
//! The `counter` is the monotonic per-session nonce. Because ChaCha20-Poly1305
//! needs a unique 96-bit nonce per key, we derive the nonce directly from this
//! counter (see `crypto::nonce_from_counter`), and we additionally gate inbound
//! packets through [`AntiReplayWindow`] to reject duplicates and stale frames.

use vpn_shared::{Result, VpnError};

/// Packet kinds on the data plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketKind {
    /// Encapsulated IP datagram.
    Data = 0x01,
    /// Keepalive / latency probe (carries an echo timestamp).
    Keepalive = 0x02,
    /// Handover control: "prepare to migrate to session N".
    HandoverPrepare = 0x03,
    /// Handover control: "commit — all further data uses the new session".
    HandoverCommit = 0x04,
}

impl PacketKind {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::Keepalive),
            0x03 => Ok(Self::HandoverPrepare),
            0x04 => Ok(Self::HandoverCommit),
            other => Err(VpnError::MalformedPacket(format!("unknown kind 0x{other:02x}"))),
        }
    }
}

/// Fixed outer-header length: kind(1) + session_id(4) + counter(8).
pub const HEADER_LEN: usize = 1 + 4 + 8;

/// Parsed outer header.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub kind: PacketKind,
    pub session_id: u32,
    pub counter: u64,
}

impl Header {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.kind as u8);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.counter.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(VpnError::MalformedPacket(format!(
                "frame too short: {} < {}",
                buf.len(),
                HEADER_LEN
            )));
        }
        let kind = PacketKind::from_u8(buf[0])?;
        let session_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let counter = u64::from_be_bytes([
            buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
        ]);
        Ok(Self { kind, session_id, counter })
    }
}
