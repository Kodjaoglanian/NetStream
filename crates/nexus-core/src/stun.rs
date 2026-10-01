//! Minimal RFC 5389 STUN binding-message codec.
//!
//! The control plane runs a STUN responder so agents can discover their
//! public `ip:port` reflexive endpoint before hole punching. Only what the
//! binding transaction needs is implemented: request/response types, the
//! magic cookie, and XOR-MAPPED-ADDRESS (IPv4 + IPv6).

use crate::error::{NexusError, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_RESPONSE: u16 = 0x0101;
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

const HEADER_LEN: usize = 20;

/// Cheap check that a UDP datagram looks like a STUN message.
pub fn is_stun_message(buf: &[u8]) -> bool {
    buf.len() >= HEADER_LEN && buf[0] & 0xC0 == 0 && buf[4..8] == MAGIC_COOKIE.to_be_bytes()
}

/// Build a binding request. Returns the message and its transaction id.
pub fn build_binding_request() -> ([u8; HEADER_LEN], [u8; 12]) {
    let mut txid = [0u8; 12];
    OsRng.fill_bytes(&mut txid);
    let mut msg = [0u8; HEADER_LEN];
    msg[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg[2..4].copy_from_slice(&0u16.to_be_bytes()); // length: no attrs
    msg[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg[8..20].copy_from_slice(&txid);
    (msg, txid)
}

/// Server side: validate a binding request and return its transaction id.
pub fn parse_binding_request(buf: &[u8]) -> Result<[u8; 12]> {
    if !is_stun_message(buf) {
        return Err(NexusError::Stun("not a STUN message".into()));
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_REQUEST {
        return Err(NexusError::Stun(format!(
            "unsupported STUN type 0x{msg_type:04x}"
        )));
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&buf[8..20]);
    Ok(txid)
}

/// Server side: build a success response carrying `observed` as the
/// XOR-MAPPED-ADDRESS attribute.
pub fn build_binding_response(txid: &[u8; 12], observed: SocketAddr) -> Vec<u8> {
    let (family, addr_len, addr_bytes): (u8, usize, Vec<u8>) = match observed.ip() {
        IpAddr::V4(v4) => (0x01, 4, v4.octets().to_vec()),
        IpAddr::V6(v6) => (0x02, 16, v6.octets().to_vec()),
    };
    let attr_len = 4 + addr_len;
    let mut msg = Vec::with_capacity(HEADER_LEN + 4 + attr_len);
    msg.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
    msg.extend_from_slice(&((4 + attr_len) as u16).to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(txid);

    msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    msg.extend_from_slice(&(attr_len as u16).to_be_bytes());
    msg.push(0); // reserved
    msg.push(family);
    let xport = observed.port() ^ (MAGIC_COOKIE >> 16) as u16;
    msg.extend_from_slice(&xport.to_be_bytes());
    for (i, b) in addr_bytes.iter().enumerate() {
        let mask = if i < 4 {
            MAGIC_COOKIE.to_be_bytes()[i]
        } else {
            txid[i - 4]
        };
        msg.push(b ^ mask);
    }
    msg
}

/// Client side: parse a binding response and extract the XOR-MAPPED-ADDRESS
/// (or legacy MAPPED-ADDRESS) reflexive endpoint.
pub fn parse_binding_response(buf: &[u8], expected_txid: &[u8; 12]) -> Result<SocketAddr> {
    if !is_stun_message(buf) {
        return Err(NexusError::Stun("not a STUN message".into()));
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != BINDING_RESPONSE {
        return Err(NexusError::Stun("not a binding response".into()));
    }
    if &buf[8..20] != expected_txid {
        return Err(NexusError::Stun("transaction id mismatch".into()));
    }
    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let attrs_end = (HEADER_LEN + total_len).min(buf.len());

    let mut mapped: Option<SocketAddr> = None;
    let mut i = HEADER_LEN;
    while i + 4 <= attrs_end {
        let attr_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let attr_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let val_start = i + 4;
        if val_start + attr_len > attrs_end {
            break;
        }
        let val = &buf[val_start..val_start + attr_len];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                return decode_mapped(val, true, expected_txid);
            }
            ATTR_MAPPED_ADDRESS => {
                mapped = decode_mapped(val, false, expected_txid).ok();
            }
            _ => {}
        }
        // Attributes are padded to 32-bit boundaries.
        i = val_start + ((attr_len + 3) & !3);
    }
    mapped.ok_or_else(|| NexusError::Stun("no MAPPED-ADDRESS attribute".into()))
}

fn decode_mapped(val: &[u8], xor: bool, txid: &[u8; 12]) -> Result<SocketAddr> {
    if val.len() < 8 {
        return Err(NexusError::Stun("short mapped address".into()));
    }
    let family = val[1];
    let mut port = u16::from_be_bytes([val[2], val[3]]);
    if xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }
    match family {
        0x01 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(&val[4..8]);
            if xor {
                let cookie = MAGIC_COOKIE.to_be_bytes();
                for (b, m) in a.iter_mut().zip(cookie.iter()) {
                    *b ^= m;
                }
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), port))
        }
        0x02 => {
            if val.len() < 20 {
                return Err(NexusError::Stun("short mapped address".into()));
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&val[4..20]);
            if xor {
                for (i, b) in a.iter_mut().enumerate() {
                    *b ^= if i < 4 {
                        MAGIC_COOKIE.to_be_bytes()[i]
                    } else {
                        txid[i - 4]
                    };
                }
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), port))
        }
        f => Err(NexusError::Stun(format!("unknown address family {f}"))),
    }
}
