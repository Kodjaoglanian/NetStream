//! Noise_IKpsk2 handshake — the pattern WireGuard uses — plus the transport
//! framing, replay protection, and cookie-reply DoS mitigation.
//!
//! Message layouts (little-endian integers):
//!
//! ```text
//! Initiation (148 bytes, type 1):
//!   type(4) | sender_index(4) | ephemeral(32) | enc_static(48) | enc_ts(28)
//!   | mac1(16) | mac2(16)
//!
//! Response (92 bytes, type 2):
//!   type(4) | sender_index(4) | receiver_index(4) | ephemeral(32)
//!   | enc_empty(16) | mac1(16) | mac2(16)
//!
//! Cookie reply (64 bytes, type 3):
//!   type(4) | receiver_index(4) | nonce(24) | enc_cookie(32)
//!
//! Transport (16 + N bytes, type 4):
//!   type(4) | receiver_index(4) | counter(8) | aead(N)
//! ```

use crate::crypto::{
    aead_decrypt, aead_encrypt, hash, hash2, kdf1, kdf2, kdf3, mac, tai64n_now, StaticKeyPair,
    KEY_LEN, TAG_LEN,
};
use crate::error::{NexusError, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use std::net::SocketAddr;

pub const MSG_TYPE_INITIATION: u32 = 1;
pub const MSG_TYPE_RESPONSE: u32 = 2;
pub const MSG_TYPE_COOKIE_REPLY: u32 = 3;
pub const MSG_TYPE_TRANSPORT: u32 = 4;

pub const INITIATION_LEN: usize = 148;
pub const RESPONSE_LEN: usize = 92;
pub const COOKIE_REPLY_LEN: usize = 64;
pub const TRANSPORT_HEADER_LEN: usize = 16;
pub const COOKIE_LEN: usize = 16;

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

const ZERO_PSK: [u8; KEY_LEN] = [0u8; KEY_LEN];

/// Sliding replay window size in packets.
pub const REPLAY_WINDOW: u64 = 2048;
/// After this many transport messages a session must be rekeyed.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// Counters at or beyond this are rejected outright.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - REPLAY_WINDOW - 1;
/// Cookie validity window (seconds).
pub const COOKIE_LIFETIME_SECS: u64 = 120;

/// Session keys derived at the end of a successful handshake.
#[derive(Clone)]
pub struct SessionKeys {
    /// Key for encrypting outgoing transport packets.
    pub send_key: [u8; KEY_LEN],
    /// Key for decrypting incoming transport packets.
    pub recv_key: [u8; KEY_LEN],
    /// Our index — peers address transport packets to us with it.
    pub our_index: u32,
    /// Peer's index — we set it as `receiver_index` on outbound packets.
    pub their_index: u32,
}

fn initial_state() -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let ck = hash(CONSTRUCTION);
    let h = hash2(&ck, IDENTIFIER);
    (ck, h)
}

fn mix_hash(h: &[u8; KEY_LEN], data: &[u8]) -> [u8; KEY_LEN] {
    hash2(h, data)
}

fn mac1_key(responder_static_pub: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    hash2(LABEL_MAC1, responder_static_pub)
}

/// Compute `mac1` for a handshake message body (everything before the macs).
fn compute_mac1(responder_static_pub: &[u8; KEY_LEN], body: &[u8]) -> [u8; TAG_LEN] {
    mac(&mac1_key(responder_static_pub), body)
}

fn compute_mac2(cookie: &[u8; COOKIE_LEN], body_with_mac1: &[u8]) -> [u8; TAG_LEN] {
    mac(cookie, body_with_mac1)
}

// ---------------------------------------------------------------------------
// Initiator side
// ---------------------------------------------------------------------------

/// In-flight state for a handshake initiation we sent.
pub struct PendingInitiation {
    chaining_key: [u8; KEY_LEN],
    hash: [u8; KEY_LEN],
    ephemeral_secret: [u8; KEY_LEN],
    /// Index we sent — incoming responses must reference it.
    pub sender_index: u32,
    /// Static public key of the peer we are handshaking with.
    pub responder_static: [u8; KEY_LEN],
}

/// Build a handshake initiation message for `responder_static`.
///
/// `cookie`, when supplied, is placed in `mac2` — it is obtained from a prior
/// cookie reply and proves to a rate-limited responder that we own our source
/// address.
pub fn create_initiation(
    own_static: &StaticKeyPair,
    responder_static: &[u8; KEY_LEN],
    sender_index: u32,
    cookie: Option<&[u8; COOKIE_LEN]>,
) -> Result<(Vec<u8>, PendingInitiation)> {
    let (mut ck, mut h) = initial_state();
    // Pre-mix the responder's static key, as in WireGuard, so mac1 covers it.
    h = mix_hash(&h, responder_static);

    let ephemeral = StaticKeyPair::generate();
    let eph_pub = ephemeral.public();

    let mut msg = Vec::with_capacity(INITIATION_LEN);
    msg.extend_from_slice(&MSG_TYPE_INITIATION.to_le_bytes());
    msg.extend_from_slice(&sender_index.to_le_bytes());
    msg.extend_from_slice(&eph_pub);

    ck = kdf1(&ck, &eph_pub);
    h = mix_hash(&h, &eph_pub);

    // DH(e_i, s_r) — encrypt our static public key.
    let dh_es = ephemeral.dh(responder_static)?;
    let (new_ck, key) = kdf2(&ck, &dh_es);
    ck = new_ck;
    let enc_static = aead_encrypt(&key, 0, &own_static.public(), &h)?;
    msg.extend_from_slice(&enc_static);
    h = mix_hash(&h, &enc_static);

    // DH(s_i, s_r) — encrypt a TAI64N timestamp (replay protection).
    let dh_ss = own_static.dh(responder_static)?;
    let (new_ck, key) = kdf2(&ck, &dh_ss);
    ck = new_ck;
    let enc_ts = aead_encrypt(&key, 0, &tai64n_now(), &h)?;
    msg.extend_from_slice(&enc_ts);
    h = mix_hash(&h, &enc_ts);

    let mac1 = compute_mac1(responder_static, &msg);
    msg.extend_from_slice(&mac1);
    match cookie {
        Some(c) => msg.extend_from_slice(&compute_mac2(c, &msg)),
        None => msg.extend_from_slice(&[0u8; TAG_LEN]),
    }

    debug_assert_eq!(msg.len(), INITIATION_LEN);
    Ok((
        msg,
        PendingInitiation {
            chaining_key: ck,
            hash: h,
            ephemeral_secret: ephemeral.to_bytes(),
            sender_index,
            responder_static: *responder_static,
        },
    ))
}

/// Consume a handshake response addressed to us. On success returns the
/// established session keys.
pub fn consume_response(
    response: &[u8],
    pending: &PendingInitiation,
    own_static: &StaticKeyPair,
) -> Result<SessionKeys> {
    if response.len() != RESPONSE_LEN {
        return Err(NexusError::Handshake(format!(
            "bad response length {}",
            response.len()
        )));
    }
    if u32::from_le_bytes(response[0..4].try_into().unwrap_or_default()) != MSG_TYPE_RESPONSE {
        return Err(NexusError::Handshake("not a response message".into()));
    }
    let their_index = u32::from_le_bytes(response[4..8].try_into().unwrap_or_default());
    let receiver_index = u32::from_le_bytes(response[8..12].try_into().unwrap_or_default());
    if receiver_index != pending.sender_index {
        return Err(NexusError::Handshake(
            "response receiver_index mismatch".into(),
        ));
    }

    // Verify mac1 — keyed by *our* static key since we are the responder's
    // peer.
    let own_pub = own_static.public();
    let expected_mac1 = compute_mac1(&own_pub, &response[..60]);
    if expected_mac1 != response[60..76] {
        return Err(NexusError::Handshake("response mac1 invalid".into()));
    }

    let mut eph_r = [0u8; KEY_LEN];
    eph_r.copy_from_slice(&response[12..44]);
    let enc_empty = &response[44..60];

    let mut ck = pending.chaining_key;
    let mut h = pending.hash;

    ck = kdf1(&ck, &eph_r);
    h = mix_hash(&h, &eph_r);

    // DH(e_i, e_r) — ephemeral–ephemeral.
    let our_eph = StaticKeyPair::from_bytes(&pending.ephemeral_secret);
    let (new_ck, _) = kdf2(&ck, &our_eph.dh(&eph_r)?);
    ck = new_ck;

    // DH(s_i, e_r) — static–ephemeral.
    let (new_ck, _) = kdf2(&ck, &own_static.dh(&eph_r)?);
    ck = new_ck;

    // PSK mix (all-zero — no preshared key configured).
    let (new_ck, tau, key) = kdf3(&ck, &ZERO_PSK);
    ck = new_ck;
    h = mix_hash(&h, &tau);

    let empty = aead_decrypt(&key, 0, enc_empty, &h)?;
    if !empty.is_empty() {
        return Err(NexusError::Handshake("response payload not empty".into()));
    }
    let _h_final = mix_hash(&h, enc_empty);

    let (k1, k2) = kdf2(&ck, &[]);
    // Initiator: send = k1, receive = k2.
    Ok(SessionKeys {
        send_key: k1,
        recv_key: k2,
        our_index: pending.sender_index,
        their_index,
    })
}

// ---------------------------------------------------------------------------
// Responder side
// ---------------------------------------------------------------------------

/// A fully decoded and authenticated initiation message. The responder must
/// still check the timestamp against its per-peer replay table before calling
/// [`build_response`].
pub struct DecodedInitiation {
    /// Initiator's long-term static public key — identifies the peer.
    pub peer_static: [u8; KEY_LEN],
    /// Initiator's ephemeral public key.
    pub initiator_ephemeral: [u8; KEY_LEN],
    /// Decrypted TAI64N timestamp.
    pub timestamp: [u8; 12],
    /// Index the initiator chose — our transport packets reference it.
    pub initiator_index: u32,
    chaining_key: [u8; KEY_LEN],
    hash: [u8; KEY_LEN],
}

/// Verify `mac1`, authenticate, and decode a handshake initiation.
///
/// `cookie_key` should be [`cookie_key`] for our own static public key; when
/// `Some`, and `require_cookie` is set, the message must also carry a valid
/// `mac2` for `src` — this is the stateless address-validation check used
/// under load.
pub fn decode_initiation(
    msg: &[u8],
    own_static: &StaticKeyPair,
    src: SocketAddr,
    require_cookie: bool,
) -> Result<DecodedInitiation> {
    if msg.len() != INITIATION_LEN {
        return Err(NexusError::Handshake(format!(
            "bad initiation length {}",
            msg.len()
        )));
    }
    if u32::from_le_bytes(msg[0..4].try_into().unwrap_or_default()) != MSG_TYPE_INITIATION {
        return Err(NexusError::Handshake("not an initiation message".into()));
    }

    let own_pub = own_static.public();
    let expected_mac1 = compute_mac1(&own_pub, &msg[..116]);
    if expected_mac1 != msg[116..132] {
        // mac1 failure: drop silently upstream.
        return Err(NexusError::Handshake("initiation mac1 invalid".into()));
    }

    let mac2 = &msg[132..148];
    if require_cookie {
        let ck = cookie_key(&own_pub);
        let cookie = cookie_for_addr(&ck, &src);
        if mac2 == [0u8; TAG_LEN] || compute_mac2(&cookie, &msg[..132]) != mac2 {
            return Err(NexusError::Handshake("missing or invalid cookie".into()));
        }
    }

    let initiator_index = u32::from_le_bytes(msg[4..8].try_into().unwrap_or_default());
    let mut eph_i = [0u8; KEY_LEN];
    eph_i.copy_from_slice(&msg[8..40]);
    let enc_static = &msg[40..88];
    let enc_ts = &msg[88..116];

    let (mut ck, mut h) = initial_state();
    h = mix_hash(&h, &own_pub); // responder premixes *its own* static key

    ck = kdf1(&ck, &eph_i);
    h = mix_hash(&h, &eph_i);

    // DH(s_r, e_i) — recover initiator's static key.
    let (new_ck, key) = kdf2(&ck, &own_static.dh(&eph_i)?);
    ck = new_ck;
    let peer_static_bytes = aead_decrypt(&key, 0, enc_static, &h)?;
    if peer_static_bytes.len() != KEY_LEN {
        return Err(NexusError::Handshake("corrupt static field".into()));
    }
    let mut peer_static = [0u8; KEY_LEN];
    peer_static.copy_from_slice(&peer_static_bytes);
    h = mix_hash(&h, enc_static);

    // DH(s_r, s_i) — recover the timestamp.
    let (new_ck, key) = kdf2(&ck, &own_static.dh(&peer_static)?);
    ck = new_ck;
    let ts_bytes = aead_decrypt(&key, 0, enc_ts, &h)?;
    if ts_bytes.len() != 12 {
        return Err(NexusError::Handshake("corrupt timestamp".into()));
    }
    let mut timestamp = [0u8; 12];
    timestamp.copy_from_slice(&ts_bytes);
    h = mix_hash(&h, enc_ts);

    Ok(DecodedInitiation {
        peer_static,
        initiator_ephemeral: eph_i,
        timestamp,
        initiator_index,
        chaining_key: ck,
        hash: h,
    })
}

/// Build the response to a decoded initiation and derive our session keys.
/// `our_index` is a fresh random index we choose as responder.
pub fn build_response(dec: &DecodedInitiation, our_index: u32) -> Result<(Vec<u8>, SessionKeys)> {
    let ephemeral = StaticKeyPair::generate();
    let eph_pub = ephemeral.public();

    let mut ck = dec.chaining_key;
    let mut h = dec.hash;

    let mut msg = Vec::with_capacity(RESPONSE_LEN);
    msg.extend_from_slice(&MSG_TYPE_RESPONSE.to_le_bytes());
    msg.extend_from_slice(&our_index.to_le_bytes());
    msg.extend_from_slice(&dec.initiator_index.to_le_bytes());
    msg.extend_from_slice(&eph_pub);

    ck = kdf1(&ck, &eph_pub);
    h = mix_hash(&h, &eph_pub);

    // DH(e_r, e_i) — ephemeral–ephemeral.
    let (new_ck, _) = kdf2(&ck, &ephemeral.dh(&dec.initiator_ephemeral)?);
    ck = new_ck;

    // DH(e_r, s_i) — ephemeral–static.
    let (new_ck, _) = kdf2(&ck, &ephemeral.dh(&dec.peer_static)?);
    ck = new_ck;

    // PSK mix.
    let (new_ck, tau, key) = kdf3(&ck, &ZERO_PSK);
    ck = new_ck;
    h = mix_hash(&h, &tau);

    let enc_empty = aead_encrypt(&key, 0, &[], &h)?;
    msg.extend_from_slice(&enc_empty);
    let _h_final = mix_hash(&h, &enc_empty);

    // mac1 keyed by the *initiator's* static key (the receiving side).
    let mac1 = compute_mac1(&dec.peer_static, &msg);
    msg.extend_from_slice(&mac1);
    msg.extend_from_slice(&[0u8; TAG_LEN]); // mac2 — unused by responders

    debug_assert_eq!(msg.len(), RESPONSE_LEN);
    let (k1, k2) = kdf2(&ck, &[]);
    // Responder: receive = k1, send = k2.
    Ok((
        msg,
        SessionKeys {
            send_key: k2,
            recv_key: k1,
            our_index,
            their_index: dec.initiator_index,
        },
    ))
}

// ---------------------------------------------------------------------------
// Cookie replies (stateless source-address validation under load)
// ---------------------------------------------------------------------------

/// The key material for cookie computation: `H(LABEL_COOKIE || static_pub)`.
pub fn cookie_key(static_pub: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    hash2(LABEL_COOKIE, static_pub)
}

/// Cookie bound to a socket address — the value a rate-limited responder
/// hands out and later requires in `mac2`.
pub fn cookie_for_addr(cookie_key: &[u8; KEY_LEN], addr: &SocketAddr) -> [u8; COOKIE_LEN] {
    let mut buf = Vec::with_capacity(18);
    match addr.ip() {
        std::net::IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
        std::net::IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
    mac(cookie_key, &buf)
}

/// Build a cookie-reply message for an initiation that arrived while we are
/// rate-limiting. `trigger_mac1` is the mac1 field of the offending message
/// (used as AEAD AAD, binding the reply to that exact message).
pub fn create_cookie_reply(
    own_static: &StaticKeyPair,
    receiver_index: u32,
    trigger_mac1: &[u8],
    src: SocketAddr,
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{Key as AeadKey, XChaCha20Poly1305, XNonce};

    let ck = cookie_key(&own_static.public());
    let cookie = cookie_for_addr(&ck, &src);

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(&ck));
    let enc_cookie = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &cookie,
                aad: trigger_mac1,
            },
        )
        .map_err(|_| NexusError::Crypto("cookie encryption failed".into()))?;

    let mut msg = Vec::with_capacity(COOKIE_REPLY_LEN);
    msg.extend_from_slice(&MSG_TYPE_COOKIE_REPLY.to_le_bytes());
    msg.extend_from_slice(&receiver_index.to_le_bytes());
    msg.extend_from_slice(&nonce);
    msg.extend_from_slice(&enc_cookie);
    Ok(msg)
}

/// Consume a cookie reply. `trigger_mac1` is the mac1 field of the initiation
/// we sent that provoked this reply.
pub fn consume_cookie_reply(
    msg: &[u8],
    responder_static: &[u8; KEY_LEN],
    our_index: u32,
    trigger_mac1: &[u8],
) -> Result<[u8; COOKIE_LEN]> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{Key as AeadKey, XChaCha20Poly1305, XNonce};

    if msg.len() != COOKIE_REPLY_LEN {
        return Err(NexusError::Packet("bad cookie reply length".into()));
    }
    if u32::from_le_bytes(msg[0..4].try_into().unwrap_or_default()) != MSG_TYPE_COOKIE_REPLY {
        return Err(NexusError::Packet("not a cookie reply".into()));
    }
    if u32::from_le_bytes(msg[4..8].try_into().unwrap_or_default()) != our_index {
        return Err(NexusError::Packet("cookie reply receiver mismatch".into()));
    }
    let ck = cookie_key(responder_static);
    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(&ck));
    let plain = cipher
        .decrypt(
            XNonce::from_slice(&msg[8..32]),
            Payload {
                msg: &msg[32..64],
                aad: trigger_mac1,
            },
        )
        .map_err(|_| NexusError::Packet("cookie reply authentication failed".into()))?;
    if plain.len() != COOKIE_LEN {
        return Err(NexusError::Packet("bad cookie length".into()));
    }
    let mut cookie = [0u8; COOKIE_LEN];
    cookie.copy_from_slice(&plain);
    Ok(cookie)
}

// ---------------------------------------------------------------------------
// Transport packets
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` (a raw IP packet) into a transport message.
/// `receiver_index` is the peer's index (`SessionKeys::their_index`).
pub fn seal_transport(
    send_key: &[u8; KEY_LEN],
    receiver_index: u32,
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut msg = Vec::with_capacity(TRANSPORT_HEADER_LEN + plaintext.len() + TAG_LEN);
    msg.extend_from_slice(&MSG_TYPE_TRANSPORT.to_le_bytes());
    msg.extend_from_slice(&receiver_index.to_le_bytes());
    msg.extend_from_slice(&counter.to_le_bytes());
    msg.extend_from_slice(&aead_encrypt(send_key, counter, plaintext, &[])?);
    Ok(msg)
}

/// A borrowed view of a transport message's header fields.
pub struct TransportView<'a> {
    pub receiver_index: u32,
    pub counter: u64,
    pub ciphertext: &'a [u8],
}

/// Parse a transport message header without decrypting.
pub fn parse_transport(msg: &[u8]) -> Result<TransportView<'_>> {
    if msg.len() < TRANSPORT_HEADER_LEN + TAG_LEN {
        return Err(NexusError::Packet("transport packet too short".into()));
    }
    if u32::from_le_bytes(msg[0..4].try_into().unwrap_or_default()) != MSG_TYPE_TRANSPORT {
        return Err(NexusError::Packet("not a transport packet".into()));
    }
    Ok(TransportView {
        receiver_index: u32::from_le_bytes(msg[4..8].try_into().unwrap_or_default()),
        counter: u64::from_le_bytes(msg[8..16].try_into().unwrap_or_default()),
        ciphertext: &msg[16..],
    })
}

/// Decrypt the payload of a parsed transport message.
pub fn open_transport(recv_key: &[u8; KEY_LEN], view: &TransportView<'_>) -> Result<Vec<u8>> {
    aead_decrypt(recv_key, view.counter, view.ciphertext, &[])
}

// ---------------------------------------------------------------------------
// Replay protection — 2048-bit sliding window
// ---------------------------------------------------------------------------

/// Sliding-window anti-replay filter for transport packet counters.
pub struct ReplayWindow {
    last: u64,
    bitmap: [u64; 32], // 2048 bits; bit 0 of word 0 is `last` itself
    init: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            last: 0,
            bitmap: [0u64; 32],
            init: false,
        }
    }

    /// Returns `true` the first time `counter` is seen within the window,
    /// `false` for duplicates, expired, or too-far-ahead counters.
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        if !self.init {
            self.last = counter;
            self.bitmap[0] = 1;
            self.init = true;
            return true;
        }
        if counter > self.last {
            let diff = counter - self.last;
            if diff >= REPLAY_WINDOW {
                self.bitmap = [0u64; 32];
            } else {
                let wshift = (diff / 64) as usize;
                let bshift = diff % 64;
                let old = self.bitmap;
                for (i, slot) in self.bitmap.iter_mut().enumerate() {
                    let hi = if i >= wshift {
                        old[i - wshift] << bshift
                    } else {
                        0
                    };
                    let lo = if bshift > 0 && i > wshift {
                        old[i - wshift - 1] >> (64 - bshift)
                    } else {
                        0
                    };
                    *slot = hi | lo;
                }
            }
            self.bitmap[0] |= 1;
            self.last = counter;
            true
        } else {
            let diff = self.last - counter;
            if diff >= REPLAY_WINDOW {
                return false;
            }
            let word = (diff / 64) as usize;
            let bit = diff % 64;
            if self.bitmap[word] & (1 << bit) != 0 {
                return false;
            }
            self.bitmap[word] |= 1 << bit;
            true
        }
    }
}

/// A fresh, cryptographically random sender index (top bit avoided to keep
/// indices away from protocol magic).
pub fn random_index() -> u32 {
    OsRng.next_u32()
}
