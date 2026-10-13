use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// AEAD authentication failed: wrong key, tampered, or spliced data.
    Crypto,
    /// Corrupt or truncated file structure.
    Corrupt(String),
    InvalidKey,
    /// Key violates the hex-key contract.
    InvalidHexKey,
    Closed,
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Crypto => write!(f, "aead authentication failed"),
            Error::Corrupt(m) => write!(f, "corrupt store: {m}"),
            Error::InvalidKey => write!(f, "key must be 32 bytes"),
            Error::InvalidHexKey => write!(f, "key must be ascii hex"),
            Error::Closed => write!(f, "database closed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
