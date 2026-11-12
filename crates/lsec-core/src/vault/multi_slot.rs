use super::error::VaultError;
use super::format::CipherSuite;
use crate::config::{
    SecurityConfig, DEFAULT_KEY_LEN_BYTES, DEFAULT_NONCE_LEN_BYTES, DEFAULT_SALT_LEN_BYTES,
    DEFAULT_TAG_LEN_BYTES, MAX_ARGON2_ITERATIONS, MAX_ARGON2_MEMORY_KIB, MAX_ARGON2_PARALLELISM,
    MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_PARALLELISM,
};
use crate::crypto::{
    decrypt_aes256_gcm, decrypt_chacha20, derive_key_argon2id, encrypt_aes256_gcm,
    encrypt_chacha20, generate_salt, CryptoError,
};
use crate::memguard::{ProtectedArray, ProtectedBuffer};

pub const MULTI_VAULT_MAGIC: [u8; 6] = [b'L', b'S', b'E', b'C', 0x02, 0x00];
pub const MAX_SLOTS: usize = 4;
pub const SLOT_STATUS_INACTIVE: u8 = 0x00;
pub const SLOT_STATUS_ACTIVE: u8 = 0x01;

pub const SLOT_METADATA_SIZE: usize = 1 + 1 + DEFAULT_SALT_LEN_BYTES + 4 + 4 + 4;
pub const WRAPPED_DEK_SIZE: usize =
    DEFAULT_NONCE_LEN_BYTES + DEFAULT_KEY_LEN_BYTES + DEFAULT_TAG_LEN_BYTES;
pub const SLOT_SIZE: usize = SLOT_METADATA_SIZE + WRAPPED_DEK_SIZE;
pub const HEADER_STATIC_SIZE: usize = 6 + 1;
pub const MULTI_HEADER_SIZE: usize = HEADER_STATIC_SIZE + (MAX_SLOTS * SLOT_SIZE);

pub struct MultiSlotVault;

impl MultiSlotVault {
    pub fn is_multi_slot(vault_bytes: &[u8]) -> bool {
        vault_bytes.len() >= MULTI_HEADER_SIZE && vault_bytes[0..6] == MULTI_VAULT_MAGIC
    }

    pub fn create(
        payload: &[u8],
        passphrase: &[u8],
        cipher: CipherSuite,
        config: &SecurityConfig,
    ) -> Result<Vec<u8>, VaultError> {
        let mut dek_bytes = [0u8; DEFAULT_KEY_LEN_BYTES];
        getrandom::getrandom(&mut dek_bytes).map_err(|_| CryptoError::RngError)?;
        let dek = ProtectedArray::<DEFAULT_KEY_LEN_BYTES>::new(dek_bytes);

        let mut container = vec![0u8; MULTI_HEADER_SIZE];
        container[0..6].copy_from_slice(&MULTI_VAULT_MAGIC);
        container[6] = cipher as u8;

        Self::write_slot(&mut container, 0, passphrase, cipher, config, &dek)?;

        let static_header = &container[0..HEADER_STATIC_SIZE];
        let payload_ciphertext = match cipher {
            CipherSuite::ChaCha20Poly1305 => encrypt_chacha20(&dek, payload, static_header)?,
            CipherSuite::Aes256Gcm => encrypt_aes256_gcm(&dek, payload, static_header)?,
        };

        container.extend_from_slice(&payload_ciphertext);
        Ok(container)
    }

    pub fn open(container: &[u8], passphrase: &[u8]) -> Result<ProtectedBuffer, VaultError> {
        if container.len() < MULTI_HEADER_SIZE + DEFAULT_NONCE_LEN_BYTES + DEFAULT_TAG_LEN_BYTES {
            return Err(VaultError::HeaderTooShort);
        }

        if container[0..6] != MULTI_VAULT_MAGIC {
            return Err(VaultError::InvalidMagicHeader);
        }

        let payload_cipher = CipherSuite::try_from(container[6])?;
        let dek = Self::unwrap_dek(container, passphrase)?;

        let static_header = &container[0..HEADER_STATIC_SIZE];
        let payload_ciphertext = &container[MULTI_HEADER_SIZE..];

        let decrypted = match payload_cipher {
            CipherSuite::ChaCha20Poly1305 => {
                decrypt_chacha20(&dek, payload_ciphertext, static_header)?
            }
            CipherSuite::Aes256Gcm => decrypt_aes256_gcm(&dek, payload_ciphertext, static_header)?,
        };

        Ok(decrypted)
    }

    pub fn add_slot(
        container: &mut [u8],
        existing_passphrase: &[u8],
        new_passphrase: &[u8],
        config: &SecurityConfig,
        new_cipher: CipherSuite,
    ) -> Result<usize, VaultError> {
        let dek = Self::unwrap_dek(container, existing_passphrase)?;

        let free_slot = (0..MAX_SLOTS)
            .find(|&i| {
                let offset = HEADER_STATIC_SIZE + (i * SLOT_SIZE);
                container[offset] == SLOT_STATUS_INACTIVE
            })
            .ok_or(VaultError::AllSlotsOccupied)?;

        Self::write_slot(
            container,
            free_slot,
            new_passphrase,
            new_cipher,
            config,
            &dek,
        )?;
        Ok(free_slot)
    }

    pub fn remove_slot(
        container: &mut [u8],
        existing_passphrase: &[u8],
        slot_index: usize,
    ) -> Result<(), VaultError> {
        if slot_index >= MAX_SLOTS {
            return Err(VaultError::SlotIndexOutOfBounds(slot_index));
        }

        let _dek = Self::unwrap_dek(container, existing_passphrase)?;

        let active_count = (0..MAX_SLOTS)
            .filter(|&i| {
                let offset = HEADER_STATIC_SIZE + (i * SLOT_SIZE);
                container[offset] == SLOT_STATUS_ACTIVE
            })
            .count();

        if active_count <= 1 {
            return Err(VaultError::CannotRemoveLastSlot);
        }

        let offset = HEADER_STATIC_SIZE + (slot_index * SLOT_SIZE);
        if container[offset] != SLOT_STATUS_ACTIVE {
            return Err(VaultError::SlotNotActive(slot_index));
        }

        container[offset..offset + SLOT_SIZE].fill(0);
        Ok(())
    }

    pub fn update_payload(
        container: &mut Vec<u8>,
        existing_passphrase: &[u8],
        new_payload: &[u8],
    ) -> Result<(), VaultError> {
        let dek = Self::unwrap_dek(container, existing_passphrase)?;
        let payload_cipher = CipherSuite::try_from(container[6])?;

        let static_header = &container[0..HEADER_STATIC_SIZE];
        let payload_ciphertext = match payload_cipher {
            CipherSuite::ChaCha20Poly1305 => encrypt_chacha20(&dek, new_payload, static_header)?,
            CipherSuite::Aes256Gcm => encrypt_aes256_gcm(&dek, new_payload, static_header)?,
        };

        container.truncate(MULTI_HEADER_SIZE);
        container.extend_from_slice(&payload_ciphertext);
        Ok(())
    }

    pub fn active_slots(container: &[u8]) -> Result<[bool; MAX_SLOTS], VaultError> {
        if container.len() < MULTI_HEADER_SIZE {
            return Err(VaultError::HeaderTooShort);
        }

        if container[0..6] != MULTI_VAULT_MAGIC {
            return Err(VaultError::InvalidMagicHeader);
        }

        let mut slots = [false; MAX_SLOTS];
        for (i, slot) in slots.iter_mut().enumerate() {
            let offset = HEADER_STATIC_SIZE + (i * SLOT_SIZE);
            *slot = container[offset] == SLOT_STATUS_ACTIVE;
        }
        Ok(slots)
    }

    fn unwrap_dek(
        container: &[u8],
        passphrase: &[u8],
    ) -> Result<ProtectedArray<DEFAULT_KEY_LEN_BYTES>, VaultError> {
        for i in 0..MAX_SLOTS {
            let offset = HEADER_STATIC_SIZE + (i * SLOT_SIZE);
            if container[offset] != SLOT_STATUS_ACTIVE {
                continue;
            }

            let slot_cipher = match CipherSuite::try_from(container[offset + 1]) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let mut salt = [0u8; DEFAULT_SALT_LEN_BYTES];
            salt.copy_from_slice(&container[offset + 2..offset + 18]);

            let memory_kib = u32::from_be_bytes([
                container[offset + 18],
                container[offset + 19],
                container[offset + 20],
                container[offset + 21],
            ]);
            let iterations = u32::from_be_bytes([
                container[offset + 22],
                container[offset + 23],
                container[offset + 24],
                container[offset + 25],
            ]);
            let parallelism = u32::from_be_bytes([
                container[offset + 26],
                container[offset + 27],
                container[offset + 28],
                container[offset + 29],
            ]);

            if !(MIN_ARGON2_MEMORY_KIB..=MAX_ARGON2_MEMORY_KIB).contains(&memory_kib)
                || !(MIN_ARGON2_ITERATIONS..=MAX_ARGON2_ITERATIONS).contains(&iterations)
                || !(MIN_ARGON2_PARALLELISM..=MAX_ARGON2_PARALLELISM).contains(&parallelism)
            {
                continue;
            }

            let kdf_config = SecurityConfig::builder()
                .argon2_memory_kib(memory_kib)
                .argon2_iterations(iterations)
                .argon2_parallelism(parallelism)
                .build();

            let kek = match derive_key_argon2id(passphrase, &salt, &kdf_config) {
                Ok(k) => k,
                Err(_) => continue,
            };

            let wrapped_dek = &container[offset + SLOT_METADATA_SIZE..offset + SLOT_SIZE];
            let aad = &container[offset..offset + SLOT_METADATA_SIZE];

            let unwrapped_res = match slot_cipher {
                CipherSuite::ChaCha20Poly1305 => decrypt_chacha20(&kek, wrapped_dek, aad),
                CipherSuite::Aes256Gcm => decrypt_aes256_gcm(&kek, wrapped_dek, aad),
            };

            if let Ok(unwrapped_buf) = unwrapped_res {
                if unwrapped_buf.len() == DEFAULT_KEY_LEN_BYTES {
                    let mut dek_arr = [0u8; DEFAULT_KEY_LEN_BYTES];
                    dek_arr.copy_from_slice(&unwrapped_buf);
                    return Ok(ProtectedArray::<DEFAULT_KEY_LEN_BYTES>::new(dek_arr));
                }
            }
        }

        Err(VaultError::NoMatchingSlot)
    }

    fn write_slot(
        container: &mut [u8],
        slot_index: usize,
        passphrase: &[u8],
        cipher: CipherSuite,
        config: &SecurityConfig,
        dek: &ProtectedArray<DEFAULT_KEY_LEN_BYTES>,
    ) -> Result<(), VaultError> {
        let offset = HEADER_STATIC_SIZE + (slot_index * SLOT_SIZE);
        let salt = generate_salt()?;
        let kek = derive_key_argon2id(passphrase, &salt, config)?;

        container[offset] = SLOT_STATUS_ACTIVE;
        container[offset + 1] = cipher as u8;
        container[offset + 2..offset + 18].copy_from_slice(&salt);
        container[offset + 18..offset + 22]
            .copy_from_slice(&config.argon2_memory_kib.to_be_bytes());
        container[offset + 22..offset + 26]
            .copy_from_slice(&config.argon2_iterations.to_be_bytes());
        container[offset + 26..offset + 30]
            .copy_from_slice(&config.argon2_parallelism.to_be_bytes());

        let aad = &container[offset..offset + SLOT_METADATA_SIZE];
        let wrapped_dek = match cipher {
            CipherSuite::ChaCha20Poly1305 => encrypt_chacha20(&kek, dek, aad)?,
            CipherSuite::Aes256Gcm => encrypt_aes256_gcm(&kek, dek, aad)?,
        };

        container[offset + SLOT_METADATA_SIZE..offset + SLOT_SIZE].copy_from_slice(&wrapped_dek);
        Ok(())
    }
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
    fn test_multi_slot_roundtrip_chacha20() {
        let payload = b"secret data payload";
        let passphrase = b"master-password";
        let config = test_fast_config();

        let vault =
            MultiSlotVault::create(payload, passphrase, CipherSuite::ChaCha20Poly1305, &config)
                .unwrap();

        assert!(MultiSlotVault::is_multi_slot(&vault));

        let decrypted = MultiSlotVault::open(&vault, passphrase).unwrap();
        assert_eq!(&decrypted[..], payload);
    }

    #[test]
    fn test_multi_slot_roundtrip_aes256_gcm() {
        let payload = b"aes-encrypted-vault";
        let passphrase = b"key-phrase";
        let config = test_fast_config();

        let vault =
            MultiSlotVault::create(payload, passphrase, CipherSuite::Aes256Gcm, &config).unwrap();
        let decrypted = MultiSlotVault::open(&vault, passphrase).unwrap();
        assert_eq!(&decrypted[..], payload);
    }

    #[test]
    fn test_multi_slot_wrong_passphrase_fails() {
        let payload = b"data";
        let passphrase = b"correct-password";
        let config = test_fast_config();

        let vault =
            MultiSlotVault::create(payload, passphrase, CipherSuite::ChaCha20Poly1305, &config)
                .unwrap();

        let err = MultiSlotVault::open(&vault, b"wrong-password").unwrap_err();
        assert!(matches!(err, VaultError::NoMatchingSlot));
    }

    #[test]
    fn test_add_and_unlock_multiple_slots() {
        let payload = b"shared secret";
        let pass_slot0 = b"passphrase-0";
        let pass_slot1 = b"passphrase-1";
        let pass_slot2 = b"passphrase-2";
        let config = test_fast_config();

        let mut vault =
            MultiSlotVault::create(payload, pass_slot0, CipherSuite::ChaCha20Poly1305, &config)
                .unwrap();

        let slot1_idx = MultiSlotVault::add_slot(
            &mut vault,
            pass_slot0,
            pass_slot1,
            &config,
            CipherSuite::ChaCha20Poly1305,
        )
        .unwrap();
        assert_eq!(slot1_idx, 1);

        let slot2_idx = MultiSlotVault::add_slot(
            &mut vault,
            pass_slot1,
            pass_slot2,
            &config,
            CipherSuite::Aes256Gcm,
        )
        .unwrap();
        assert_eq!(slot2_idx, 2);

        assert_eq!(
            &MultiSlotVault::open(&vault, pass_slot0).unwrap()[..],
            payload
        );
        assert_eq!(
            &MultiSlotVault::open(&vault, pass_slot1).unwrap()[..],
            payload
        );
        assert_eq!(
            &MultiSlotVault::open(&vault, pass_slot2).unwrap()[..],
            payload
        );

        let active = MultiSlotVault::active_slots(&vault).unwrap();
        assert_eq!(active, [true, true, true, false]);
    }

    #[test]
    fn test_remove_slot() {
        let payload = b"temporary slot data";
        let pass0 = b"owner";
        let pass1 = b"emergency";
        let config = test_fast_config();

        let mut vault =
            MultiSlotVault::create(payload, pass0, CipherSuite::ChaCha20Poly1305, &config).unwrap();
        MultiSlotVault::add_slot(
            &mut vault,
            pass0,
            pass1,
            &config,
            CipherSuite::ChaCha20Poly1305,
        )
        .unwrap();

        MultiSlotVault::remove_slot(&mut vault, pass0, 1).unwrap();

        assert_eq!(&MultiSlotVault::open(&vault, pass0).unwrap()[..], payload);
        assert!(matches!(
            MultiSlotVault::open(&vault, pass1).unwrap_err(),
            VaultError::NoMatchingSlot
        ));

        let err = MultiSlotVault::remove_slot(&mut vault, pass0, 0).unwrap_err();
        assert!(matches!(err, VaultError::CannotRemoveLastSlot));
    }

    #[test]
    fn test_all_slots_occupied() {
        let payload = b"four slots";
        let config = test_fast_config();
        let mut vault =
            MultiSlotVault::create(payload, b"pass0", CipherSuite::ChaCha20Poly1305, &config)
                .unwrap();

        MultiSlotVault::add_slot(
            &mut vault,
            b"pass0",
            b"pass1",
            &config,
            CipherSuite::ChaCha20Poly1305,
        )
        .unwrap();
        MultiSlotVault::add_slot(
            &mut vault,
            b"pass0",
            b"pass2",
            &config,
            CipherSuite::ChaCha20Poly1305,
        )
        .unwrap();
        MultiSlotVault::add_slot(
            &mut vault,
            b"pass0",
            b"pass3",
            &config,
            CipherSuite::ChaCha20Poly1305,
        )
        .unwrap();

        let err = MultiSlotVault::add_slot(
            &mut vault,
            b"pass0",
            b"pass4",
            &config,
            CipherSuite::ChaCha20Poly1305,
        )
        .unwrap_err();
        assert!(matches!(err, VaultError::AllSlotsOccupied));
    }

    #[test]
    fn test_fast_update_payload() {
        let initial = b"v1 data";
        let updated = b"v2 data modified without re-deriving argon2 on existing slots";
        let config = test_fast_config();

        let mut vault =
            MultiSlotVault::create(initial, b"key1", CipherSuite::ChaCha20Poly1305, &config)
                .unwrap();
        MultiSlotVault::add_slot(
            &mut vault,
            b"key1",
            b"key2",
            &config,
            CipherSuite::ChaCha20Poly1305,
        )
        .unwrap();

        MultiSlotVault::update_payload(&mut vault, b"key2", updated).unwrap();

        assert_eq!(&MultiSlotVault::open(&vault, b"key1").unwrap()[..], updated);
        assert_eq!(&MultiSlotVault::open(&vault, b"key2").unwrap()[..], updated);
    }

    #[test]
    fn test_tamper_payload_fails() {
        let payload = b"untampered payload";
        let config = test_fast_config();
        let mut vault =
            MultiSlotVault::create(payload, b"pass", CipherSuite::ChaCha20Poly1305, &config)
                .unwrap();

        let len = vault.len();
        vault[len - 1] ^= 0x01;

        let err = MultiSlotVault::open(&vault, b"pass").unwrap_err();
        assert!(matches!(err, VaultError::Crypto(_)));
    }
}
