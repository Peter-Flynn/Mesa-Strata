pub mod cpace;
pub mod fault;
pub mod frame;
pub mod hs;
pub mod kdf;
pub mod local;
pub mod msg;
pub mod names;
pub mod sd;
pub mod session;
pub mod zipc;

pub use msg::Msg;
pub use session::Session;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("server rejected the connection: {reason:?}")]
    Rejected { reason: hs::RejectReason, retry_after_ms: u32 },
    #[error("authentication failed: wrong password or key, or not the expected server")]
    AuthFailed,
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("remote error ({code:?}): {message}")]
    Remote { code: msg::ErrorCode, message: String },
}

pub type Result<T> = std::result::Result<T, Error>;
