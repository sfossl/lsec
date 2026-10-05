use core::fmt;
use crate::memguard::MemguardError;

#[derive(Debug)]
pub enum TotpError {
    InvalidStepSeconds,
    InvalidDigits(u32),
    EmptySecret,
    InvalidBase32,
    InvalidKeyLength,
    SystemTimeBeforeEpoch,
    Memguard(MemguardError),
}

impl fmt::Display for TotpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStepSeconds => write!(f, "step interval must be greater than zero"),
            Self::InvalidDigits(d) => write!(f, "unsupported totp code length: {} digits (expected 6 to 8)", d),
            Self::EmptySecret => write!(f, "totp secret seed cannot be empty"),
            Self::InvalidBase32 => write!(f, "invalid base32 secret encoding"),
            Self::InvalidKeyLength => write!(f, "hmac key initialization failed"),
            Self::SystemTimeBeforeEpoch => write!(f, "current system time is before unix epoch"),
            Self::Memguard(err) => write!(f, "memguard error: {}", err),
        }
    }
}

impl std::error::Error for TotpError {}

impl From<MemguardError> for TotpError {
    fn from(err: MemguardError) -> Self {
        Self::Memguard(err)
    }
}

