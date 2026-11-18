pub mod fletcher;
pub mod nvlist;
pub mod record;
pub mod token;
pub mod validate;
pub mod writer;

pub use validate::{Expect, Summary, Validator};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StreamError {
    #[error("send stream rejected: {0}")]
    Invalid(String),
    #[error("send stream checksum mismatch at offset {0}")]
    Checksum(u64),
}

pub(crate) fn invalid<T>(msg: impl Into<String>) -> Result<T, StreamError> {
    Err(StreamError::Invalid(msg.into()))
}
