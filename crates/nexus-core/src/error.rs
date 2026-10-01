use thiserror::Error;

/// Unified error type for nexus-core primitives.
#[derive(Debug, Error)]
pub enum NexusError {
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("invalid key material: {0}")]
    InvalidKey(String),

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("malformed packet: {0}")]
    Packet(String),

    #[error("STUN error: {0}")]
    Stun(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("ipc error: {0}")]
    Ipc(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}

pub type Result<T> = std::result::Result<T, NexusError>;
