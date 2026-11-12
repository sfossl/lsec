use core::fmt;
use std::io::Error as IoError;

use crate::crypto::CryptoError;

#[derive(Debug)]
pub enum VaultError {
    InvalidMagicHeader,
    HeaderTooShort,
    UnsupportedCipherSuite(u8),
    UnsupportedKdf(u8),
    InvalidKdfParameters,
    CorruptedData,
    NoMatchingSlot,
    AllSlotsOccupied,
    SlotIndexOutOfBounds(usize),
    CannotRemoveLastSlot,
    SlotNotActive(usize),
    Crypto(CryptoError),
    Io(IoError),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagicHeader => write!(f, "invalid vault magic header or format mismatch"),
            Self::HeaderTooShort => write!(f, "vault header is too short"),
            Self::UnsupportedCipherSuite(id) => write!(f, "unsupported cipher suite id: {}", id),
            Self::UnsupportedKdf(id) => write!(f, "unsupported kdf algorithm id: {}", id),
            Self::InvalidKdfParameters => {
                write!(f, "vault kdf parameters out of acceptable bounds")
            }
            Self::CorruptedData => write!(f, "vault payload is corrupted or corrupted length"),
            Self::NoMatchingSlot => {
                write!(f, "no active vault slot matched the provided credential")
            }
            Self::AllSlotsOccupied => write!(f, "all vault container slots are occupied"),
            Self::SlotIndexOutOfBounds(idx) => write!(f, "slot index {} is out of bounds", idx),
            Self::CannotRemoveLastSlot => write!(f, "cannot remove the last active vault slot"),
            Self::SlotNotActive(idx) => write!(f, "slot {} is not active", idx),
            Self::Crypto(err) => write!(f, "vault cryptographic failure: {}", err),
            Self::Io(err) => write!(f, "vault filesystem io failure: {}", err),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<CryptoError> for VaultError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

impl From<IoError> for VaultError {
    fn from(err: IoError) -> Self {
        Self::Io(err)
    }
}
