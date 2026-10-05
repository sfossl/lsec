use core::fmt;
use crate::memguard::MemguardError;

#[derive(Debug)]
pub enum CryptoError {
    KdfError(String),
    RngError,
    EncryptionFailed,
    DecryptionFailed,
    InvalidKeyLength(usize),
    InvalidCiphertextLength,
    Memguard(MemguardError),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KdfError(msg) => write!(f, "kdf error: {}", msg),
            Self::RngError => write!(f, "system entropy generation failed"),
            Self::EncryptionFailed => write!(f, "authenticated encryption failed"),
            Self::DecryptionFailed => write!(f, "decryption or authentication tag verification failed"),
            Self::InvalidKeyLength(len) => write!(f, "invalid key length of {} bytes, expected 32", len),
            Self::InvalidCiphertextLength => write!(f, "ciphertext length is too short to contain nonce and tag"),
            Self::Memguard(err) => write!(f, "memguard error: {}", err),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<MemguardError> for CryptoError {
    fn from(err: MemguardError) -> Self {
        Self::Memguard(err)
    }
}

