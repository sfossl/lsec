use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::catch_unwind;
use std::path::Path;
use std::slice;

use lsec_core::config::SecurityConfig;
use lsec_core::vault::{
    seal, seal_to_file, unseal, unseal_from_file, CipherSuite, MultiSlotVault, VaultError,
};

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

unsafe fn to_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[][..])
    } else if ptr.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(ptr, len) })
    }
}

unsafe fn to_slice_mut<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        Some(&mut [][..])
    } else if ptr.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts_mut(ptr, len) })
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

        let plain_slice = match unsafe { to_slice(plaintext, plaintext_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
        };
        let pass_slice = match unsafe { to_slice(passphrase, passphrase_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
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
        if out_plaintext.is_null() {
            return LSEC_ERR_NULL_POINTER;
        }

        let v_slice = match unsafe { to_slice(vault_bytes, vault_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
        };
        let pass_slice = match unsafe { to_slice(passphrase, passphrase_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
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
pub unsafe extern "C" fn lsec_multi_vault_create(
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

        let plain_slice = match unsafe { to_slice(plaintext, plaintext_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
        };
        let pass_slice = match unsafe { to_slice(passphrase, passphrase_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
        };

        let cipher = match parse_cipher_suite(cipher_id) {
            Ok(c) => c,
            Err(code) => return code,
        };

        match MultiSlotVault::create(plain_slice, pass_slice, cipher, &SecurityConfig::default()) {
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
pub unsafe extern "C" fn lsec_multi_vault_open(
    container: *const u8,
    container_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out_plaintext: *mut *mut LsecProtectedBuffer,
) -> i32 {
    unsafe {
        lsec_vault_unseal(
            container,
            container_len,
            passphrase,
            passphrase_len,
            out_plaintext,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn lsec_multi_vault_add_slot(
    container: *mut u8,
    container_len: usize,
    existing_passphrase: *const u8,
    existing_passphrase_len: usize,
    new_passphrase: *const u8,
    new_passphrase_len: usize,
    new_cipher_id: u8,
    out_slot_index: *mut usize,
) -> i32 {
    let result = catch_unwind(|| {
        let c_slice = match unsafe { to_slice_mut(container, container_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
        };
        let exist_pass = match unsafe { to_slice(existing_passphrase, existing_passphrase_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
        };
        let new_pass = match unsafe { to_slice(new_passphrase, new_passphrase_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
        };

        let cipher = match parse_cipher_suite(new_cipher_id) {
            Ok(c) => c,
            Err(code) => return code,
        };

        match MultiSlotVault::add_slot(
            c_slice,
            exist_pass,
            new_pass,
            &SecurityConfig::default(),
            cipher,
        ) {
            Ok(slot_idx) => {
                if !out_slot_index.is_null() {
                    unsafe {
                        *out_slot_index = slot_idx;
                    }
                }
                LSEC_OK
            }
            Err(e) => map_vault_error(e),
        }
    });

    result.unwrap_or(LSEC_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn lsec_multi_vault_remove_slot(
    container: *mut u8,
    container_len: usize,
    existing_passphrase: *const u8,
    existing_passphrase_len: usize,
    slot_index: usize,
) -> i32 {
    let result = catch_unwind(|| {
        let c_slice = match unsafe { to_slice_mut(container, container_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
        };
        let exist_pass = match unsafe { to_slice(existing_passphrase, existing_passphrase_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
        };

        match MultiSlotVault::remove_slot(c_slice, exist_pass, slot_index) {
            Ok(()) => LSEC_OK,
            Err(e) => map_vault_error(e),
        }
    });

    result.unwrap_or(LSEC_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn lsec_multi_vault_update_payload(
    container: *const u8,
    container_len: usize,
    existing_passphrase: *const u8,
    existing_passphrase_len: usize,
    new_payload: *const u8,
    new_payload_len: usize,
    out_bytes: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = catch_unwind(|| {
        if out_bytes.is_null() || out_len.is_null() {
            return LSEC_ERR_NULL_POINTER;
        }

        let c_slice = match unsafe { to_slice(container, container_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
        };
        let exist_pass = match unsafe { to_slice(existing_passphrase, existing_passphrase_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
        };
        let new_plain = match unsafe { to_slice(new_payload, new_payload_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
        };

        let mut updated = c_slice.to_vec();
        match MultiSlotVault::update_payload(&mut updated, exist_pass, new_plain) {
            Ok(()) => {
                let len = updated.len();
                let mut boxed = updated.into_boxed_slice();
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
pub unsafe extern "C" fn lsec_multi_vault_active_slots(
    container: *const u8,
    container_len: usize,
    out_active_slots: *mut u8,
    out_active_slots_len: usize,
) -> i32 {
    let result = catch_unwind(|| {
        if out_active_slots.is_null() {
            return LSEC_ERR_NULL_POINTER;
        }
        if out_active_slots_len < 4 {
            return LSEC_ERR_INVALID_PARAM;
        }

        let c_slice = match unsafe { to_slice(container, container_len) } {
            Some(s) => s,
            None => return LSEC_ERR_NULL_POINTER,
        };
        match MultiSlotVault::active_slots(c_slice) {
            Ok(slots) => {
                let out_slice =
                    unsafe { slice::from_raw_parts_mut(out_active_slots, out_active_slots_len) };
                for (i, active) in slots.iter().enumerate() {
                    out_slice[i] = if *active { 1 } else { 0 };
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
