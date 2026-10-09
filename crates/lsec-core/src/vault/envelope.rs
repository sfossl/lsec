use super::error::VaultError;
use super::format::{CipherSuite, VaultHeader, HEADER_SIZE};
use crate::config::SecurityConfig;
use crate::crypto::{
    decrypt_aes256_gcm, decrypt_chacha20, derive_key_argon2id, encrypt_aes256_gcm,
    encrypt_chacha20, generate_salt,
};
use crate::memguard::ProtectedBuffer;

pub fn seal(
    plaintext: &[u8],
    passphrase: &[u8],
    config: &SecurityConfig,
    cipher: CipherSuite,
) -> Result<Vec<u8>, VaultError> {
    let salt = generate_salt()?;
    let header = VaultHeader::new(cipher, salt, config);
    let serialized_header = header.serialize();

    let derived_key = derive_key_argon2id(passphrase, &salt, config)?;

    let ciphertext = match cipher {
        CipherSuite::ChaCha20Poly1305 => {
            encrypt_chacha20(&derived_key, plaintext, &serialized_header)?
        }
        CipherSuite::Aes256Gcm => {
            encrypt_aes256_gcm(&derived_key, plaintext, &serialized_header)?
        }
    };

    let mut vault_package = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    vault_package.extend_from_slice(&serialized_header);
    vault_package.extend_from_slice(&ciphertext);
    Ok(vault_package)
}

pub fn seal_default(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, VaultError> {
    seal(
        plaintext,
        passphrase,
        &SecurityConfig::default(),
        CipherSuite::ChaCha20Poly1305,
    )
}

pub fn unseal(vault_bytes: &[u8], passphrase: &[u8]) -> Result<ProtectedBuffer, VaultError> {
    let (header, ciphertext) = VaultHeader::deserialize(vault_bytes)?;
    let serialized_header = &vault_bytes[..HEADER_SIZE];

    let kdf_config = SecurityConfig::builder()
        .argon2_memory_kib(header.argon2_memory_kib)
        .argon2_iterations(header.argon2_iterations)
        .argon2_parallelism(header.argon2_parallelism)
        .build();

    let derived_key = derive_key_argon2id(passphrase, &header.salt, &kdf_config)?;

    let plaintext = match header.cipher {
        CipherSuite::ChaCha20Poly1305 => {
            decrypt_chacha20(&derived_key, ciphertext, serialized_header)?
        }
        CipherSuite::Aes256Gcm => {
            decrypt_aes256_gcm(&derived_key, ciphertext, serialized_header)?
        }
    };

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fast_config() -> SecurityConfig {
        SecurityConfig::builder()
            .argon2_memory_kib(1024)
            .argon2_iterations(1)
            .argon2_parallelism(1)
            .build()
    }

    #[test]
    fn test_seal_and_unseal_chacha20() {
        let config = test_fast_config();
        let secret = b"my-master-database-payload";
        let pass = b"correct-horse-battery-staple";

        let sealed = seal(secret, pass, &config, CipherSuite::ChaCha20Poly1305).expect("seal ok");
        assert_ne!(&sealed[HEADER_SIZE..], secret);

        let unsealed = unseal(&sealed, pass).expect("unseal ok");
        assert_eq!(&unsealed[..], secret);
    }

    #[test]
    fn test_seal_and_unseal_aes256_gcm() {
        let config = test_fast_config();
        let secret = b"sensitive-vault-record";
        let pass = b"complex-password-123";

        let sealed = seal(secret, pass, &config, CipherSuite::Aes256Gcm).expect("seal ok");
        let unsealed = unseal(&sealed, pass).expect("unseal ok");
        assert_eq!(&unsealed[..], secret);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let config = test_fast_config();
        let secret = b"confidential-data";
        let sealed = seal(secret, b"correct-password", &config, CipherSuite::ChaCha20Poly1305).expect("ok");

        let res = unseal(&sealed, b"wrong-password");
        assert!(matches!(res, Err(VaultError::Crypto(_))));
    }

    #[test]
    fn test_header_tamper_fails() {
        let config = test_fast_config();
        let secret = b"confidential-data";
        let mut sealed = seal(secret, b"correct-password", &config, CipherSuite::ChaCha20Poly1305).expect("ok");

        // tamper with salt in header
        sealed[8] ^= 0x01;

        let res = unseal(&sealed, b"correct-password");
        assert!(matches!(res, Err(VaultError::Crypto(_))));
    }

    #[test]
    fn test_ciphertext_tamper_fails() {
        let config = test_fast_config();
        let secret = b"confidential-data";
        let mut sealed = seal(secret, b"correct-password", &config, CipherSuite::ChaCha20Poly1305).expect("ok");

        let last_idx = sealed.len() - 1;
        sealed[last_idx] ^= 0x01;

        let res = unseal(&sealed, b"correct-password");
        assert!(matches!(res, Err(VaultError::Crypto(_))));
    }
}

