use argon2::{Algorithm, Argon2, Params, Version};

use super::error::CryptoError;
use crate::config::{DEFAULT_KEY_LEN_BYTES, DEFAULT_SALT_LEN_BYTES, SecurityConfig};
use crate::memguard::ProtectedBuffer;

pub fn generate_salt() -> Result<[u8; DEFAULT_SALT_LEN_BYTES], CryptoError> {
    let mut salt = [0u8; DEFAULT_SALT_LEN_BYTES];
    getrandom::getrandom(&mut salt).map_err(|_| CryptoError::RngError)?;
    Ok(salt)
}

pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<ProtectedBuffer, CryptoError> {
    derive_key_argon2id(passphrase, salt, &SecurityConfig::default())
}

pub fn derive_key_argon2id(
    passphrase: &[u8],
    salt: &[u8],
    config: &SecurityConfig,
) -> Result<ProtectedBuffer, CryptoError> {
    let params = Params::new(
        config.argon2_memory_kib,
        config.argon2_iterations,
        config.argon2_parallelism,
        Some(DEFAULT_KEY_LEN_BYTES),
    )
    .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key_buffer = ProtectedBuffer::zeroed(DEFAULT_KEY_LEN_BYTES)?;
    argon2
        .hash_password_into(passphrase, salt, key_buffer.as_mut_slice())
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    Ok(key_buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt_randomness() {
        let salt1 = generate_salt().expect("salt 1 ok");
        let salt2 = generate_salt().expect("salt 2 ok");
        assert_ne!(salt1, salt2);
        assert_eq!(salt1.len(), DEFAULT_SALT_LEN_BYTES);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let fast_config = SecurityConfig::builder()
            .argon2_memory_kib(1024)
            .argon2_iterations(1)
            .argon2_parallelism(1)
            .build();

        let pass = b"secure-master-password";
        let salt = b"constant-salt-16";

        let key1 = derive_key_argon2id(pass, salt, &fast_config).expect("kdf 1 ok");
        let key2 = derive_key_argon2id(pass, salt, &fast_config).expect("kdf 2 ok");

        assert_eq!(key1.len(), DEFAULT_KEY_LEN_BYTES);
        assert_eq!(&key1[..], &key2[..]);
    }

    #[test]
    fn test_different_inputs_produce_different_keys() {
        let fast_config = SecurityConfig::builder()
            .argon2_memory_kib(1024)
            .argon2_iterations(1)
            .argon2_parallelism(1)
            .build();

        let salt = b"constant-salt-16";
        let key1 = derive_key_argon2id(b"password-a", salt, &fast_config).expect("ok");
        let key2 = derive_key_argon2id(b"password-b", salt, &fast_config).expect("ok");

        assert_ne!(&key1[..], &key2[..]);
    }
}

