use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroize;

use super::error::CryptoError;
use crate::config::{DEFAULT_KEY_LEN_BYTES, DEFAULT_NONCE_LEN_BYTES, DEFAULT_TAG_LEN_BYTES};
use crate::memguard::ProtectedBuffer;

pub fn generate_nonce() -> Result<[u8; DEFAULT_NONCE_LEN_BYTES], CryptoError> {
    let mut nonce = [0u8; DEFAULT_NONCE_LEN_BYTES];
    getrandom::getrandom(&mut nonce).map_err(|_| CryptoError::RngError)?;
    Ok(nonce)
}

pub fn encrypt_chacha20(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != DEFAULT_KEY_LEN_BYTES {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    let nonce_bytes = generate_nonce()?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), payload)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(DEFAULT_NONCE_LEN_BYTES + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt_chacha20(
    key: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<ProtectedBuffer, CryptoError> {
    if key.len() != DEFAULT_KEY_LEN_BYTES {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    if ciphertext.len() < DEFAULT_NONCE_LEN_BYTES + DEFAULT_TAG_LEN_BYTES {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    let (nonce_slice, enc_body) = ciphertext.split_at(DEFAULT_NONCE_LEN_BYTES);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let payload = Payload { msg: enc_body, aad };

    let mut decrypted = cipher
        .decrypt(Nonce::from_slice(nonce_slice), payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let protected = ProtectedBuffer::new(&decrypted)?;
    decrypted.zeroize();
    Ok(protected)
}

pub fn encrypt_aes256_gcm(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != DEFAULT_KEY_LEN_BYTES {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    let nonce_bytes = generate_nonce()?;
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(AesNonce::from_slice(&nonce_bytes), payload)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(DEFAULT_NONCE_LEN_BYTES + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt_aes256_gcm(
    key: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<ProtectedBuffer, CryptoError> {
    if key.len() != DEFAULT_KEY_LEN_BYTES {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    if ciphertext.len() < DEFAULT_NONCE_LEN_BYTES + DEFAULT_TAG_LEN_BYTES {
        return Err(CryptoError::InvalidCiphertextLength);
    }

    let (nonce_slice, enc_body) = ciphertext.split_at(DEFAULT_NONCE_LEN_BYTES);
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
    let payload = Payload { msg: enc_body, aad };

    let mut decrypted = cipher
        .decrypt(AesNonce::from_slice(nonce_slice), payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let protected = ProtectedBuffer::new(&decrypted)?;
    decrypted.zeroize();
    Ok(protected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_roundtrip() {
        let key = [7u8; 32];
        let message = b"confidential-data-packet";
        let aad = b"authenticated-metadata";

        let encrypted = encrypt_chacha20(&key, message, aad).expect("enc ok");
        assert_ne!(&encrypted[..], message);

        let decrypted = decrypt_chacha20(&key, &encrypted, aad).expect("dec ok");
        assert_eq!(&decrypted[..], message);
    }

    #[test]
    fn test_chacha20_tamper_fails() {
        let key = [7u8; 32];
        let message = b"confidential-data-packet";
        let aad = b"authenticated-metadata";

        let mut encrypted = encrypt_chacha20(&key, message, aad).expect("enc ok");
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0x01;

        let res = decrypt_chacha20(&key, &encrypted, aad);
        assert!(matches!(res, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_chacha20_aad_mismatch_fails() {
        let key = [7u8; 32];
        let message = b"confidential-data-packet";

        let encrypted = encrypt_chacha20(&key, message, b"original-aad").expect("enc ok");
        let res = decrypt_chacha20(&key, &encrypted, b"tampered-aad");
        assert!(matches!(res, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = [9u8; 32];
        let message = b"aes-encrypted-vault-payload";
        let aad = b"context-header";

        let encrypted = encrypt_aes256_gcm(&key, message, aad).expect("enc ok");
        let decrypted = decrypt_aes256_gcm(&key, &encrypted, aad).expect("dec ok");
        assert_eq!(&decrypted[..], message);
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = [1u8; 16];
        let res = encrypt_chacha20(&short_key, b"data", b"");
        assert!(matches!(res, Err(CryptoError::InvalidKeyLength(16))));
    }

    #[test]
    fn test_truncated_ciphertext() {
        let key = [1u8; 32];
        let short_ct = [0u8; 10];
        let res = decrypt_chacha20(&key, &short_ct, b"");
        assert!(matches!(res, Err(CryptoError::InvalidCiphertextLength)));
    }

    #[test]
    fn test_nonce_uniqueness() {
        use std::collections::HashSet;

        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let nonce = generate_nonce().expect("nonce ok");
            assert!(seen.insert(nonce), "nonce collision detected");
        }
    }

    #[test]
    fn test_zero_length_plaintext() {
        let key = [3u8; 32];
        let empty = b"";
        let encrypted = encrypt_chacha20(&key, empty, b"").expect("enc ok");
        let decrypted = decrypt_chacha20(&key, &encrypted, b"").expect("dec ok");
        assert_eq!(&decrypted[..], empty);
    }

    #[test]
    fn test_large_payload_roundtrip() {
        let key = [5u8; 32];
        let payload = vec![0x42u8; 64 * 1024];
        let aad = b"64kib-payload-test";

        let encrypted = encrypt_chacha20(&key, &payload, aad).expect("enc ok");
        let decrypted = decrypt_chacha20(&key, &encrypted, aad).expect("dec ok");
        assert_eq!(&decrypted[..], &payload[..]);
    }

    #[test]
    fn test_aes256_gcm_tamper_fails() {
        let key = [9u8; 32];
        let message = b"sensitive-data";
        let mut encrypted = encrypt_aes256_gcm(&key, message, b"header").expect("enc ok");
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0x01;

        let res = decrypt_aes256_gcm(&key, &encrypted, b"header");
        assert!(matches!(res, Err(CryptoError::DecryptionFailed)));
    }
}
