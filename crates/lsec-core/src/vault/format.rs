use super::error::VaultError;
use crate::config::{
    DEFAULT_SALT_LEN_BYTES, MAX_ARGON2_ITERATIONS, MAX_ARGON2_MEMORY_KIB, MAX_ARGON2_PARALLELISM,
    MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_PARALLELISM, SecurityConfig,
    VAULT_MAGIC_HEADER,
};

pub const HEADER_SIZE: usize = 6 + 1 + 1 + DEFAULT_SALT_LEN_BYTES + 4 + 4 + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherSuite {
    ChaCha20Poly1305 = 0x01,
    Aes256Gcm = 0x02,
}

impl TryFrom<u8> for CipherSuite {
    type Error = VaultError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x01 => Ok(Self::ChaCha20Poly1305),
            0x02 => Ok(Self::Aes256Gcm),
            other => Err(VaultError::UnsupportedCipherSuite(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KdfAlgorithm {
    Argon2id = 0x01,
}

impl TryFrom<u8> for KdfAlgorithm {
    type Error = VaultError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x01 => Ok(Self::Argon2id),
            other => Err(VaultError::UnsupportedKdf(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub cipher: CipherSuite,
    pub kdf: KdfAlgorithm,
    pub salt: [u8; DEFAULT_SALT_LEN_BYTES],
    pub argon2_memory_kib: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
}

impl VaultHeader {
    pub fn new(cipher: CipherSuite, salt: [u8; DEFAULT_SALT_LEN_BYTES], config: &SecurityConfig) -> Self {
        Self {
            cipher,
            kdf: KdfAlgorithm::Argon2id,
            salt,
            argon2_memory_kib: config.argon2_memory_kib,
            argon2_iterations: config.argon2_iterations,
            argon2_parallelism: config.argon2_parallelism,
        }
    }

    pub fn serialize(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..6].copy_from_slice(&VAULT_MAGIC_HEADER);
        buf[6] = self.cipher as u8;
        buf[7] = self.kdf as u8;
        buf[8..24].copy_from_slice(&self.salt);
        buf[24..28].copy_from_slice(&self.argon2_memory_kib.to_be_bytes());
        buf[28..32].copy_from_slice(&self.argon2_iterations.to_be_bytes());
        buf[32..36].copy_from_slice(&self.argon2_parallelism.to_be_bytes());
        buf
    }

    pub fn deserialize(input: &[u8]) -> Result<(Self, &[u8]), VaultError> {
        if input.len() < HEADER_SIZE {
            return Err(VaultError::HeaderTooShort);
        }

        if input[0..6] != VAULT_MAGIC_HEADER {
            return Err(VaultError::InvalidMagicHeader);
        }

        let cipher = CipherSuite::try_from(input[6])?;
        let kdf = KdfAlgorithm::try_from(input[7])?;

        let mut salt = [0u8; DEFAULT_SALT_LEN_BYTES];
        salt.copy_from_slice(&input[8..24]);

        let argon2_memory_kib = u32::from_be_bytes([input[24], input[25], input[26], input[27]]);
        let argon2_iterations = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
        let argon2_parallelism = u32::from_be_bytes([input[32], input[33], input[34], input[35]]);

        if !(MIN_ARGON2_MEMORY_KIB..=MAX_ARGON2_MEMORY_KIB).contains(&argon2_memory_kib)
            || !(MIN_ARGON2_ITERATIONS..=MAX_ARGON2_ITERATIONS).contains(&argon2_iterations)
            || !(MIN_ARGON2_PARALLELISM..=MAX_ARGON2_PARALLELISM).contains(&argon2_parallelism)
        {
            return Err(VaultError::InvalidKdfParameters);
        }

        let header = Self {
            cipher,
            kdf,
            salt,
            argon2_memory_kib,
            argon2_iterations,
            argon2_parallelism,
        };

        Ok((header, &input[HEADER_SIZE..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecurityConfig;

    #[test]
    fn test_header_roundtrip() {
        let salt = [42u8; 16];
        let header = VaultHeader::new(CipherSuite::ChaCha20Poly1305, salt, &SecurityConfig::default());
        let serialized = header.serialize();
        assert_eq!(serialized.len(), HEADER_SIZE);

        let (parsed, remaining) = VaultHeader::deserialize(&serialized).expect("deserialize ok");
        assert_eq!(parsed, header);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_reject_invalid_magic() {
        let salt = [1u8; 16];
        let mut serialized = VaultHeader::new(CipherSuite::ChaCha20Poly1305, salt, &SecurityConfig::default()).serialize();
        serialized[0] = b'X';

        let res = VaultHeader::deserialize(&serialized);
        assert!(matches!(res, Err(VaultError::InvalidMagicHeader)));
    }

    #[test]
    fn test_reject_too_short() {
        let short_data = [0u8; 20];
        let res = VaultHeader::deserialize(&short_data);
        assert!(matches!(res, Err(VaultError::HeaderTooShort)));
    }

    #[test]
    fn test_reject_unsupported_cipher() {
        let salt = [1u8; 16];
        let mut serialized = VaultHeader::new(CipherSuite::ChaCha20Poly1305, salt, &SecurityConfig::default()).serialize();
        serialized[6] = 0xFF;

        let res = VaultHeader::deserialize(&serialized);
        assert!(matches!(res, Err(VaultError::UnsupportedCipherSuite(0xFF))));
    }

    #[test]
    fn test_reject_unsupported_kdf() {
        let salt = [1u8; 16];
        let mut serialized = VaultHeader::new(CipherSuite::ChaCha20Poly1305, salt, &SecurityConfig::default()).serialize();
        serialized[7] = 0xAA;

        let res = VaultHeader::deserialize(&serialized);
        assert!(matches!(res, Err(VaultError::UnsupportedKdf(0xAA))));
    }

    #[test]
    fn test_reject_out_of_bounds_kdf_params() {
        let salt = [1u8; 16];
        let mut serialized = VaultHeader::new(CipherSuite::ChaCha20Poly1305, salt, &SecurityConfig::default()).serialize();
        // set memory kib to 0
        serialized[24..28].copy_from_slice(&0u32.to_be_bytes());
        let res = VaultHeader::deserialize(&serialized);
        assert!(matches!(res, Err(VaultError::InvalidKdfParameters)));

        // set iterations to 0
        let mut serialized2 = VaultHeader::new(CipherSuite::ChaCha20Poly1305, salt, &SecurityConfig::default()).serialize();
        serialized2[28..32].copy_from_slice(&0u32.to_be_bytes());
        let res2 = VaultHeader::deserialize(&serialized2);
        assert!(matches!(res2, Err(VaultError::InvalidKdfParameters)));

        // set iterations excessively high
        let mut serialized3 = VaultHeader::new(CipherSuite::ChaCha20Poly1305, salt, &SecurityConfig::default()).serialize();
        serialized3[28..32].copy_from_slice(&10_000u32.to_be_bytes());
        let res3 = VaultHeader::deserialize(&serialized3);
        assert!(matches!(res3, Err(VaultError::InvalidKdfParameters)));
    }
}

