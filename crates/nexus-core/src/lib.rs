//! # NexusMesh Core
//!
//! Shared primitives for the NexusMesh P2P mesh VPN:
//!
//! - [`crypto`] — Ed25519 node identities, X25519 ("WireGuard") static keys,
//!   ChaCha20-Poly1305 AEAD, BLAKE2s hashing/MAC, HKDF, and TAI64N timestamps.
//! - [`noise`] — the Noise_IKpsk2 handshake state machine (the same handshake
//!   pattern used by WireGuard) producing bidirectional transport session keys.
//! - [`packet`] — wire framing for handshake, transport, and NAT-punch datagrams.
//! - [`stun`] — minimal RFC 5389 STUN binding client/server message codec.
//! - [`protocol`] — control-plane REST/signaling message types (serde).
//! - [`ipc`] — local IPC protocol between `nexus`/`nexus-tui` and `nexus-agent`.
//! - [`model`] — shared domain models (peers, connection modes, stats).

pub mod crypto;
pub mod error;
pub mod ipc;
pub mod model;
pub mod noise;
pub mod packet;
pub mod protocol;
pub mod stun;

pub use error::{NexusError, Result};
