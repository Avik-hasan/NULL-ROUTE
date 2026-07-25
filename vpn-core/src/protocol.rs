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

use parking_lot::Mutex;
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

/// Window size in packets. 64 fits in a single `u64` bitmap word.
pub const REPLAY_WINDOW: u64 = 64;

/// Thread-safe anti-replay sliding window (RFC 6479 / RFC 4303 §3.4.3 style).
///
/// * Accepts out-of-order packets within `REPLAY_WINDOW` of the highest seen.
/// * Silently drops exact duplicates (bit already set).
/// * Silently drops packets that trail more than `REPLAY_WINDOW` behind.
///
/// The bit for the highest counter is the LSB (bit 0). Older counters occupy
/// higher bits. Advancing the window shifts the bitmap left.
#[derive(Debug)]
pub struct AntiReplayWindow {
    inner: Mutex<WindowState>,
}

#[derive(Debug, Clone, Copy)]
struct WindowState {
    /// Highest counter accepted so far. `0` means "nothing accepted yet".
    highest: u64,
    /// Bitmap of the `REPLAY_WINDOW` counters ending at `highest`.
    bitmap: u64,
    /// Whether any packet has been accepted (distinguishes counter 0 legitimacy).
    seeded: bool,
}

impl Default for AntiReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiReplayWindow {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(WindowState { highest: 0, bitmap: 0, seeded: false }),
        }
    }

    /// Read-only pre-authentication gate.
    pub fn check(&self, counter: u64) -> Result<()> {
        let st = self.inner.lock();
        if !st.seeded {
            return Ok(());
        }
        if counter > st.highest {
            return Ok(());
        }
        let offset = st.highest - counter;
        if offset >= REPLAY_WINDOW {
            return Err(VpnError::Replay {
                counter,
                floor: st.highest.saturating_sub(REPLAY_WINDOW - 1),
            });
        }
        if st.bitmap & (1u64 << offset) != 0 {
            return Err(VpnError::Replay {
                counter,
                floor: st.highest.saturating_sub(REPLAY_WINDOW - 1),
            });
        }
        Ok(())
    }

    /// Commit an inbound counter to the window *after* it has been authenticated.
    #[inline]
    pub fn commit(&self, counter: u64) -> Result<()> {
        self.validate(counter)
    }

    pub fn validate(&self, counter: u64) -> Result<()> {
        let mut st = self.inner.lock();
        if !st.seeded {
            st.seeded = true;
            st.highest = counter;
            st.bitmap = 1;
            return Ok(());
        }
        if counter > st.highest {
            let shift = counter - st.highest;
            if shift >= REPLAY_WINDOW {
                st.bitmap = 1;
            } else {
                st.bitmap = (st.bitmap << shift) | 1;
            }
            st.highest = counter;
            Ok(())
        } else {
            let offset = st.highest - counter;
            if offset >= REPLAY_WINDOW {
                return Err(VpnError::Replay {
                    counter,
                    floor: st.highest.saturating_sub(REPLAY_WINDOW - 1),
                });
            }
            let mask = 1u64 << offset;
            if st.bitmap & mask != 0 {
                return Err(VpnError::Replay {
                    counter,
                    floor: st.highest.saturating_sub(REPLAY_WINDOW - 1),
                });
            }
            st.bitmap |= mask;
            Ok(())
        }
    }

    pub fn highest(&self) -> u64 {
        self.inner.lock().highest
    }
}
