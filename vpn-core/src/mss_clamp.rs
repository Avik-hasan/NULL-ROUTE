//! Dynamic TCP MSS clamping for Path-MTU mitigation.
//!
//! On restricted links (public Wi-Fi, mobile hotspots, PPPoE) the effective
//! path MTU is often well below 1500. Because our encapsulation adds overhead,
//! large TCP segments get fragmented or black-holed. We rewrite the MSS option
//! in outbound TCP SYN / SYN-ACK segments so both endpoints negotiate a segment
//! size that fits inside the tunnel, then fix up the TCP checksum.
//!
//! This operates on the *inner* IPv4 packets (pre-encapsulation on TX, and on
//! the server for traffic leaving the TUN toward the internet).

use vpn_shared::TUNNEL_MTU;

/// Overhead of our encapsulation: outer IPv4(20) + UDP(8) + our header(13) +
/// AEAD tag(16) = 57 bytes. Rounded to 60 for safety margin.
pub const ENCAP_OVERHEAD: u16 = 60;

/// Maximum MSS we permit inside the tunnel: MTU - IPv4(20) - TCP(20).
pub fn tunnel_mss() -> u16 {
    TUNNEL_MTU.saturating_sub(ENCAP_OVERHEAD).saturating_sub(40)
}

const IPV4_PROTO_TCP: u8 = 6;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_OPT_END: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_MSS: u8 = 2;

/// Inspect an inbound/outbound IPv4 packet in `buf`; if it is a TCP SYN whose
/// advertised MSS exceeds `max_mss`, clamp it in place and fix checksums.
///
/// Returns `true` if the packet was modified. Never panics: all indexing is
/// bounds-checked and malformed packets are left untouched.
pub fn clamp_ipv4_tcp_mss(buf: &mut [u8], max_mss: u16) -> bool {
    // --- IPv4 header ---
    if buf.len() < 20 {
        return false;
    }
    let version = buf[0] >> 4;
    if version != 4 {
        return false;
    }
    let ihl = ((buf[0] & 0x0f) as usize) * 4;
    if ihl < 20 || buf.len() < ihl {
        return false;
    }
    if buf[9] != IPV4_PROTO_TCP {
        return false;
    }

    // --- TCP header ---
    let tcp = ihl;
    if buf.len() < tcp + 20 {
        return false;
    }
    let flags = buf[tcp + 13];
    if flags & TCP_FLAG_SYN == 0 {
        // MSS option only meaningful on SYN / SYN-ACK.
        return false;
    }
    let data_offset = ((buf[tcp + 12] >> 4) as usize) * 4;
    if data_offset < 20 || buf.len() < tcp + data_offset {
        return false;
    }

    // --- Walk TCP options for kind=2 (MSS) ---
    let opt_start = tcp + 20;
    let opt_end = tcp + data_offset;
    let mut i = opt_start;
    let mut modified = false;

    while i < opt_end {
        match buf[i] {
            TCP_OPT_END => break,
            TCP_OPT_NOP => {
                i += 1;
            }
            TCP_OPT_MSS => {
                if i + 3 >= opt_end + 1 || i + 4 > opt_end {
                    break;
                }
                if buf[i + 1] != 4 {
                    break; // malformed length
                }
                let cur = u16::from_be_bytes([buf[i + 2], buf[i + 3]]);
                if cur > max_mss {
                    let new = max_mss.to_be_bytes();
                    // Incrementally correct the TCP checksum (RFC 1624).
                    fix_tcp_checksum_u16(buf, tcp, cur, max_mss);
                    buf[i + 2] = new[0];
                    buf[i + 3] = new[1];
                    modified = true;
                }
                i += 4;
            }
            _ => {
                // Other options: [kind][len][data...]
                if i + 1 >= opt_end {
                    break;
                }
                let len = buf[i + 1] as usize;
                if len < 2 {
                    break; // malformed
                }
                i += len;
            }
        }
    }

    modified
}

/// Convenience wrapper that clamps to the current tunnel MSS.
pub fn clamp_to_tunnel(buf: &mut [u8]) -> bool {
    clamp_ipv4_tcp_mss(buf, tunnel_mss())
}

/// RFC 1624 incremental checksum update for a single changed 16-bit word.
fn fix_tcp_checksum_u16(buf: &mut [u8], tcp: usize, old: u16, new: u16) {
    let ck_off = tcp + 16;
    if buf.len() < ck_off + 2 {
        return;
    }
    let old_ck = u16::from_be_bytes([buf[ck_off], buf[ck_off + 1]]);
    // HC' = ~(~HC + ~m + m')
    let mut sum = (!old_ck) as u32;
    sum += (!old) as u32 & 0xffff;
    sum += new as u32;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let new_ck = !(sum as u16);
    let b = new_ck.to_be_bytes();
    buf[ck_off] = b[0];
    buf[ck_off + 1] = b[1];
}
