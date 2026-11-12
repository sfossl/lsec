use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::catch_unwind;
use std::path::Path;
use std::slice;

use lsec_core::config::SecurityConfig;
use lsec_core::vault::{seal, seal_to_file, unseal, unseal_from_file, CipherSuite, VaultError};

use crate::error::{
    LSEC_ERR_CRYPTO_FAILED, LSEC_ERR_INVALID_PARAM, LSEC_ERR_IO_FAILED, LSEC_ERR_NULL_POINTER,
    LSEC_ERR_PANIC, LSEC_ERR_VAULT_CORRUPT, LSEC_OK,
};
use crate::memguard::LsecProtectedBuffer;

fn parse_cipher_suite(cipher_id: u8) -> Result<CipherSuite, i32> {
    match cipher_id {
        0 | 1 => Ok(CipherSuite::ChaCha20Poly1305),
        2 => Ok(CipherSuite::Aes256Gcm),
        _ => Err(LSEC_ERR_INVALID_PARAM),
    }
}

fn map_vault_error(err: VaultError) -> i32 {
    match err {
        VaultError::InvalidMagicHeader | VaultError::HeaderTooShort | VaultError::CorruptedData => {
            LSEC_ERR_VAULT_CORRUPT
        }
        VaultError::UnsupportedCipherSuite(_)
        | VaultError::UnsupportedKdf(_)
        | VaultError::InvalidKdfParameters
        | VaultError::AllSlotsOccupied
        | VaultError::SlotIndexOutOfBounds(_)
        | VaultError::CannotRemoveLastSlot
        | VaultError::SlotNotActive(_) => LSEC_ERR_INVALID_PARAM,
        VaultError::NoMatchingSlot | VaultError::Crypto(_) => LSEC_ERR_CRYPTO_FAILED,
        VaultError::Io(_) => LSEC_ERR_IO_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lsec_vault_seal(
    plaintext: *const u8,
    plaintext_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    cipher_id: u8,
    out_bytes: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = catch_unwind(|| {
        if out_bytes.is_null() || out_len.is_null() {
            return LSEC_ERR_NULL_POINTER;
        }

        let plain_slice = if plaintext_len == 0 {
            &[][..]
        } else {
            if plaintext.is_null() {
                return LSEC_ERR_NULL_POINTER;
            }
            unsafe { slice::from_raw_parts(plaintext, plaintext_len) }
        };

        if passphrase.is_null() && passphrase_len > 0 {
            return LSEC_ERR_NULL_POINTER;
        }
        let pass_slice = if passphrase_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(passphrase, passphrase_len) }
        };

        let cipher = match parse_cipher_suite(cipher_id) {
            Ok(c) => c,
            Err(code) => return code,
        };

        match seal(plain_slice, pass_slice, &SecurityConfig::default(), cipher) {
            Ok(sealed) => {
                let len = sealed.len();
                let mut boxed = sealed.into_boxed_slice();
                unsafe {
                    *out_bytes = boxed.as_mut_ptr();
                    *out_len = len;
                }
                let _ = Box::into_raw(boxed);
                LSEC_OK
            }
            Err(e) => map_vault_error(e),
        }
    });

    result.unwrap_or(LSEC_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn lsec_vault_unseal(
    vault_bytes: *const u8,
    vault_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out_plaintext: *mut *mut LsecProtectedBuffer,
) -> i32 {
    let result = catch_unwind(|| {
        if vault_bytes.is_null() || out_plaintext.is_null() {
            return LSEC_ERR_NULL_POINTER;
        }

        let v_slice = unsafe { slice::from_raw_parts(vault_bytes, vault_len) };
        let pass_slice = if passphrase_len == 0 {
            &[][..]
        } else {
            if passphrase.is_null() {
                return LSEC_ERR_NULL_POINTER;
            }
            unsafe { slice::from_raw_parts(passphrase, passphrase_len) }
        };

        match unseal(v_slice, pass_slice) {
            Ok(plain_buf) => {
                let boxed = Box::new(LsecProtectedBuffer(plain_buf));
                unsafe {
                    *out_plaintext = Box::into_raw(boxed);
                }
                LSEC_OK
            }
            Err(e) => map_vault_error(e),
        }
    });

    result.unwrap_or(LSEC_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn lsec_vault_seal_to_file(
    path: *const c_char,
    plaintext: *const u8,
    plaintext_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    cipher_id: u8,
) -> i32 {
    let result = catch_unwind(|| {
        if path.is_null() {
            return LSEC_ERR_NULL_POINTER;
        }

        let c_str = unsafe { CStr::from_ptr(path) };
        let path_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return LSEC_ERR_INVALID_PARAM,
        };

        let plain_slice = if plaintext_len == 0 {
            &[][..]
        } else {
            if plaintext.is_null() {
                return LSEC_ERR_NULL_POINTER;
            }
            unsafe { slice::from_raw_parts(plaintext, plaintext_len) }
        };

        let pass_slice = if passphrase_len == 0 {
            &[][..]
        } else {
            if passphrase.is_null() {
                return LSEC_ERR_NULL_POINTER;
            }
            unsafe { slice::from_raw_parts(passphrase, passphrase_len) }
        };

        let cipher = match parse_cipher_suite(cipher_id) {
            Ok(c) => c,
            Err(code) => return code,
        };

        match seal_to_file(
            Path::new(path_str),
            plain_slice,
            pass_slice,
            &SecurityConfig::default(),
            cipher,
        ) {
            Ok(()) => LSEC_OK,
            Err(e) => map_vault_error(e),
        }
    });

    result.unwrap_or(LSEC_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn lsec_vault_unseal_from_file(
    path: *const c_char,
    passphrase: *const u8,
    passphrase_len: usize,
    out_plaintext: *mut *mut LsecProtectedBuffer,
) -> i32 {
    let result = catch_unwind(|| {
        if path.is_null() || out_plaintext.is_null() {
            return LSEC_ERR_NULL_POINTER;
        }

        let c_str = unsafe { CStr::from_ptr(path) };
        let path_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return LSEC_ERR_INVALID_PARAM,
        };

        let pass_slice = if passphrase_len == 0 {
            &[][..]
        } else {
            if passphrase.is_null() {
                return LSEC_ERR_NULL_POINTER;
            }
            unsafe { slice::from_raw_parts(passphrase, passphrase_len) }
        };

        match unseal_from_file(Path::new(path_str), pass_slice) {
            Ok(plain_buf) => {
                let boxed = Box::new(LsecProtectedBuffer(plain_buf));
                unsafe {
                    *out_plaintext = Box::into_raw(boxed);
                }
                LSEC_OK
            }
            Err(e) => map_vault_error(e),
        }
    });

    result.unwrap_or(LSEC_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn lsec_vault_bytes_free(bytes: *mut u8, len: usize) {
    let _ = catch_unwind(|| {
        if !bytes.is_null() && len > 0 {
            unsafe {
                drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                    bytes, len,
                )));
            }
        }
    });
}
