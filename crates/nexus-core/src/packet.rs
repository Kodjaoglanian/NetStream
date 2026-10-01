//! Datagram helpers: message type sniffing, NAT punch packets, and the
//! ICMPv4 echo packets used by `nexus ping`.

use crate::crypto::KEY_LEN;
use crate::error::{NexusError, Result};
use std::net::Ipv4Addr;

/// Punch datagram type — carried over the data-plane UDP socket to open
/// NAT mappings before the handshake completes. Layout:
/// `type(4) | magic(4) = "NXMP" | sender_wg_pub(32) | nonce(8)` = 48 bytes.
pub const MSG_TYPE_PUNCH: u32 = 5;
pub const PUNCH_MAGIC: &[u8; 4] = b"NXMP";
pub const PUNCH_LEN: usize = 48;

/// Read the 4-byte little-endian message type of a datagram.
pub fn packet_type(buf: &[u8]) -> Option<u32> {
    if buf.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes(buf[0..4].try_into().ok()?))
}

/// Build a punch datagram advertising our WG public key so the receiver can
/// attribute the punched path to a peer.
pub fn build_punch(our_wg_pub: &[u8; KEY_LEN], nonce: u64) -> [u8; PUNCH_LEN] {
    let mut msg = [0u8; PUNCH_LEN];
    msg[0..4].copy_from_slice(&MSG_TYPE_PUNCH.to_le_bytes());
    msg[4..8].copy_from_slice(PUNCH_MAGIC);
    msg[8..40].copy_from_slice(our_wg_pub);
    msg[40..48].copy_from_slice(&nonce.to_le_bytes());
    msg
}

/// Parse a punch datagram; returns the sender's WG public key when valid.
pub fn parse_punch(buf: &[u8]) -> Option<[u8; KEY_LEN]> {
    if buf.len() < PUNCH_LEN {
        return None;
    }
    if packet_type(buf) != Some(MSG_TYPE_PUNCH) || &buf[4..8] != PUNCH_MAGIC {
        return None;
    }
    let mut pub_key = [0u8; KEY_LEN];
    pub_key.copy_from_slice(&buf[8..40]);
    Some(pub_key)
}

// ---------------------------------------------------------------------------
// ICMPv4 echo — `nexus ping` crafts these and pushes them down the tunnel so
// the peer's kernel answers them like ordinary traffic.
// ---------------------------------------------------------------------------

/// 16-bit Internet checksum over `data`.
fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for w in &mut chunks {
        sum += u16::from_be_bytes([w[0], w[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a complete IPv4 packet carrying an ICMP echo request.
pub fn icmpv4_echo_request(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ident: u16,
    seq: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > 1400 {
        return Err(NexusError::Packet("ping payload too large".into()));
    }
    let icmp_len = 8 + payload.len();
    let total_len = 20 + icmp_len;
    let mut pkt = vec![0u8; total_len];

    // IPv4 header
    pkt[0] = 0x45;
    pkt[1] = 0; // DSCP/ECN
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64; // TTL
    pkt[9] = 1; // ICMP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let ip_sum = inet_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    // ICMP echo request
    pkt[20] = 8; // type: echo request
    pkt[21] = 0; // code
                 // bytes 22..24 (checksum) stay zero until computed below
    pkt[24..26].copy_from_slice(&ident.to_be_bytes());
    pkt[26..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..28 + payload.len()].copy_from_slice(payload);
    let icmp_sum = inet_checksum(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
    Ok(pkt)
}

/// If `pkt` is an IPv4 ICMP echo reply matching `ident`, return its sequence
/// number and the embedded timestamp payload (16-byte value, if present).
pub fn parse_icmpv4_echo_reply(pkt: &[u8], ident: u16) -> Option<(u16, Option<u64>)> {
    if pkt.len() < 28 {
        return None;
    }
    if pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if pkt.len() < ihl + 8 {
        return None;
    }
    let icmp = &pkt[ihl..];
    if icmp[0] != 0 || icmp[1] != 0 {
        return None; // echo reply, code 0
    }
    let id = u16::from_be_bytes([icmp[4], icmp[5]]);
    if id != ident {
        return None;
    }
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    let ts = if icmp.len() >= 16 {
        Some(u64::from_be_bytes(icmp[8..16].try_into().ok()?))
    } else {
        None
    };
    Some((seq, ts))
}
