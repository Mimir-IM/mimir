/// Errors returned across the FFI boundary.
#[derive(Debug, thiserror::Error)]
pub enum MimirError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("I/O error: {0}")]
    Io(String),
}