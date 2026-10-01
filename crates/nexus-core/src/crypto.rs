//! Cryptographic primitives for NexusMesh.
//!
//! - **Identity**: Ed25519 keypair per node — the long-lived identity used to
//!   sign the node's WireGuard static key at registration time.
//! - **Transport**: X25519 static keypair per node plus the Noise handshake in
//!   [`crate::noise`] producing ChaCha20-Poly1305 session keys.
//! - All hashing uses BLAKE2s-256 (matching the WireGuard primitive set) and
//!   key derivation uses HKDF-BLAKE2s with an empty info string.

use crate::error::{NexusError, Result};
use blake2::digest::consts::U16;
use blake2::digest::Mac;
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as AeadKey, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::Path;

pub const KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const TAG_LEN: usize = 16;

/// Auth keys issued by the control plane (`nexus_sec_` + 48 hex chars).
pub const AUTHKEY_PREFIX: &str = "nexus_sec_";
/// Bearer session tokens issued to registered nodes (`nexus_tok_` + 48 hex chars).
pub const TOKEN_PREFIX: &str = "nexus_tok_";

// ---------------------------------------------------------------------------
// Ed25519 node identity
// ---------------------------------------------------------------------------

/// Long-lived Ed25519 identity keypair. The verifying key *is* the node
/// identity fingerprint shown in `nexus status`.
#[derive(Clone)]
pub struct IdentityKey {
    signing: ed25519_dalek::SigningKey,
}

impl IdentityKey {
    pub fn generate() -> Self {
        Self {
            signing: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        Self {
            signing: ed25519_dalek::SigningKey::from_bytes(bytes),
        }
    }

    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.signing.to_bytes()
    }

    pub fn public_bytes(&self) -> [u8; KEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public_bytes())
    }

    /// Produce an Ed25519 detached signature over `msg`.
    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        use ed25519_dalek::Signer;
        self.signing.sign(msg).to_bytes()
    }

    /// Load the identity key from `path`, generating and persisting a fresh
    /// keypair when the file does not exist.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match read_secret_key(path)? {
            Some(bytes) => Ok(Self::from_bytes(&bytes)),
            None => {
                let key = Self::generate();
                write_secret_key(path, &key.to_bytes())?;
                Ok(key)
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_secret_key(path, &self.to_bytes())
    }
}

/// Verify an Ed25519 detached signature against a public identity key.
pub fn verify_identity(
    pubkey: &[u8; KEY_LEN],
    msg: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pubkey)
        .map_err(|e| NexusError::InvalidKey(format!("bad ed25519 public key: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    use ed25519_dalek::Verifier;
    vk.verify(msg, &sig)
        .map_err(|_| NexusError::Crypto("identity signature verification failed".into()))
}

// ---------------------------------------------------------------------------
// X25519 ("WireGuard") static keypair
// ---------------------------------------------------------------------------

/// X25519 static keypair — the node's WireGuard transport identity.
#[derive(Clone)]
pub struct StaticKeyPair {
    secret: x25519_dalek::StaticSecret,
}

impl StaticKeyPair {
    pub fn generate() -> Self {
        Self {
            secret: x25519_dalek::StaticSecret::random_from_rng(OsRng),
        }
    }

    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        Self {
            secret: x25519_dalek::StaticSecret::from(*bytes),
        }
    }

    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.secret.to_bytes()
    }

    pub fn public(&self) -> [u8; KEY_LEN] {
        x25519_dalek::PublicKey::from(&self.secret).to_bytes()
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public())
    }

    /// X25519 Diffie–Hellman against a peer public key. Rejects non-contributory
    /// (low-order) public keys, which must never produce session material.
    pub fn dh(&self, peer_public: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN]> {
        let peer = x25519_dalek::PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(NexusError::Crypto(
                "x25519 shared secret is non-contributory".into(),
            ));
        }
        Ok(*shared.as_bytes())
    }

    /// Load the static key from `path`, generating and persisting a fresh
    /// keypair when the file does not exist.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match read_secret_key(path)? {
            Some(bytes) => Ok(Self::from_bytes(&bytes)),
            None => {
                let key = Self::generate();
                write_secret_key(path, &key.to_bytes())?;
                Ok(key)
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_secret_key(path, &self.to_bytes())
    }
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD (WireGuard-style 64-bit counter nonces)
// ---------------------------------------------------------------------------

/// Build the 96-bit nonce for a transport/handshake packet: 4 zero bytes
/// followed by the little-endian 64-bit packet counter.
fn counter_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// AEAD encrypt. Returns `plaintext.len() + TAG_LEN` bytes.
pub fn aead_encrypt(
    key: &[u8; KEY_LEN],
    counter: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(&counter_nonce(counter)),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| NexusError::Crypto("chacha20-poly1305 encryption failed".into()))
}

/// AEAD decrypt. Fails if the tag does not verify.
pub fn aead_decrypt(
    key: &[u8; KEY_LEN],
    counter: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(&counter_nonce(counter)),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| NexusError::Crypto("chacha20-poly1305 authentication failed".into()))
}

// ---------------------------------------------------------------------------
// BLAKE2s hashing / keyed MAC / HKDF
// ---------------------------------------------------------------------------

/// BLAKE2s-256 hash of `data`.
pub fn hash(data: &[u8]) -> [u8; KEY_LEN] {
    Blake2s256::digest(data).into()
}

/// BLAKE2s-256 of `a || b`.
pub fn hash2(a: &[u8], b: &[u8]) -> [u8; KEY_LEN] {
    let mut h = Blake2s256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// Keyed BLAKE2s-128 — the `MAC(key, input)` primitive used for `mac1`.
pub fn mac(key: &[u8], data: &[u8]) -> [u8; TAG_LEN] {
    let mut m = <Blake2sMac<U16> as Mac>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("blake2s accepts arbitrary key sizes"));
    m.update(data);
    let out = m.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&out);
    tag
}

fn hkdf_expand<const N: usize>(salt: &[u8], ikm: &[u8]) -> [[u8; KEY_LEN]; N] {
    // SimpleHmac lets HKDF drive Blake2s256 (a lazy-buffer variable core).
    let hk = hkdf::SimpleHkdf::<Blake2s256>::new(Some(salt), ikm);
    let mut okm = [0u8; KEY_LEN * 3]; // N never exceeds 3
                                      // `info` is empty per the WireGuard KDFn definition.
    hk.expand(b"", &mut okm[..KEY_LEN * N])
        .unwrap_or_else(|_| unreachable!("okm length is fixed and valid"));
    let mut out = [[0u8; KEY_LEN]; N];
    for (i, chunk) in out.iter_mut().enumerate() {
        chunk.copy_from_slice(&okm[i * KEY_LEN..(i + 1) * KEY_LEN]);
    }
    out
}

/// KDF1 — returns the new chaining key.
pub fn kdf1(ck: &[u8; KEY_LEN], input: &[u8]) -> [u8; KEY_LEN] {
    hkdf_expand::<1>(ck, input)[0]
}

/// KDF2 — returns (chaining key, derived key).
pub fn kdf2(ck: &[u8; KEY_LEN], input: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let [a, b] = hkdf_expand::<2>(ck, input);
    (a, b)
}

/// KDF3 — returns (chaining key, hash-mix value, derived key).
pub fn kdf3(ck: &[u8; KEY_LEN], input: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN], [u8; KEY_LEN]) {
    let [a, b, c] = hkdf_expand::<3>(ck, input);
    (a, b, c)
}

/// SHA-256 — used for at-rest hashing of auth keys and session tokens.
pub fn sha256(data: &[u8]) -> [u8; KEY_LEN] {
    use sha2::Digest as _;
    sha2::Sha256::digest(data).into()
}

// ---------------------------------------------------------------------------
// TAI64N timestamps (handshake replay protection)
// ---------------------------------------------------------------------------

/// TAI64N base offset as used by WireGuard (`2^62 + 10`).
pub const TAI64N_BASE: u64 = 0x4000_0000_0000_000a;

/// Current time as a 12-byte big-endian TAI64N label.
pub fn tai64n_now() -> [u8; 12] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&(now.as_secs() + TAI64N_BASE).to_be_bytes());
    out[8..].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    out
}

/// `true` if TAI64N label `a` is strictly later than `b` (byte-wise compare).
pub fn tai64n_after(a: &[u8; 12], b: &[u8; 12]) -> bool {
    a > b
}

// ---------------------------------------------------------------------------
// Token generation
// ---------------------------------------------------------------------------

/// `nexus_sec_` + 48 lowercase hex chars (192 bits of entropy).
pub fn generate_authkey() -> String {
    let mut buf = [0u8; 24];
    OsRng.fill_bytes(&mut buf);
    format!("{}{}", AUTHKEY_PREFIX, hex::encode(buf))
}

/// `nexus_tok_` + 48 lowercase hex chars.
pub fn generate_session_token() -> String {
    let mut buf = [0u8; 24];
    OsRng.fill_bytes(&mut buf);
    format!("{}{}", TOKEN_PREFIX, hex::encode(buf))
}

/// Returns `true` if `s` looks like a well-formed NexusMesh auth key.
pub fn is_authkey(s: &str) -> bool {
    s.starts_with(AUTHKEY_PREFIX)
        && s.len() == AUTHKEY_PREFIX.len() + 48
        && s[AUTHKEY_PREFIX.len()..]
            .chars()
            .all(|c| c.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Secret key file helpers (mode 0600)
// ---------------------------------------------------------------------------

/// Write a 32-byte secret as hex to `path` with mode 0600.
pub fn write_secret_key(path: &Path, key: &[u8; KEY_LEN]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(hex::encode(key).as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

/// Read a 32-byte secret stored as hex (or raw binary) at `path`.
/// Returns `Ok(None)` when the file does not exist.
pub fn read_secret_key(path: &Path) -> Result<Option<[u8; KEY_LEN]>> {
    let raw = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let text = String::from_utf8_lossy(&raw);
    let trimmed = text.trim();
    if trimmed.len() == KEY_LEN * 2 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let decoded = hex::decode(trimmed)?;
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&decoded);
        return Ok(Some(key));
    }
    if raw.len() >= KEY_LEN {
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&raw[..KEY_LEN]);
        return Ok(Some(key));
    }
    Err(NexusError::InvalidKey(format!(
        "malformed key file {}",
        path.display()
    )))
}
