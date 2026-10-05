#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

use core::slice;
use std::alloc::{alloc, dealloc, Layout};
use std::panic::catch_unwind;

use lsec_core::config::SecurityConfig;
use lsec_core::memguard::ProtectedBuffer;
use lsec_core::totp::{decode_secret, generate_code, verify_code_at, TotpAlgorithm};
use lsec_core::vault::{seal, unseal, CipherSuite};
use zeroize::Zeroize;

pub struct LsecWasmBuffer(pub ProtectedBuffer);

#[no_mangle]
pub extern "C" fn lsec_wasm_is_ready() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn lsec_wasm_version_major() -> u32 {
    0
}

#[no_mangle]
pub extern "C" fn lsec_wasm_version_minor() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn lsec_wasm_version_patch() -> u32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_alloc(size: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }
    let layout = match Layout::from_size_align(size, 8) {
        Ok(l) => l,
        Err(_) => return core::ptr::null_mut(),
    };
    unsafe { alloc(layout) }
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_free(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    if let Ok(layout) = Layout::from_size_align(size, 8) {
        unsafe {
            dealloc(ptr, layout);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_wipe_and_free(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    let s = unsafe { slice::from_raw_parts_mut(ptr, size) };
    s.zeroize();
    unsafe {
        lsec_wasm_free(ptr, size);
    }
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_buffer_new(
    data: *const u8,
    len: usize,
) -> *mut LsecWasmBuffer {
    let result = catch_unwind(|| {
        let s = if len == 0 {
            &[][..]
        } else {
            if data.is_null() {
                return core::ptr::null_mut();
            }
            unsafe { slice::from_raw_parts(data, len) }
        };

        match ProtectedBuffer::new(s) {
            Ok(b) => Box::into_raw(Box::new(LsecWasmBuffer(b))),
            Err(_) => core::ptr::null_mut(),
        }
    });

    result.unwrap_or(core::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_buffer_free(buf: *mut LsecWasmBuffer) {
    let _ = catch_unwind(|| {
        if !buf.is_null() {
            unsafe {
                drop(Box::from_raw(buf));
            }
        }
    });
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_buffer_len(buf: *const LsecWasmBuffer) -> usize {
    if buf.is_null() {
        return 0;
    }
    unsafe { (*buf).0.len() }
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_buffer_data(buf: *const LsecWasmBuffer) -> *const u8 {
    if buf.is_null() {
        return core::ptr::null();
    }
    unsafe { (*buf).0.as_slice().as_ptr() }
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_buffer_wipe(buf: *mut LsecWasmBuffer) -> i32 {
    let result = catch_unwind(|| {
        if buf.is_null() {
            return -1;
        }
        unsafe {
            (*buf).0.wipe();
        }
        0
    });

    result.unwrap_or(-1)
}

fn parse_cipher(cipher_id: u8) -> Option<CipherSuite> {
    match cipher_id {
        0 | 1 => Some(CipherSuite::ChaCha20Poly1305),
        2 => Some(CipherSuite::Aes256Gcm),
        _ => None,
    }
}

fn parse_algo(algo_id: u8) -> Option<TotpAlgorithm> {
    match algo_id {
        0 => Some(TotpAlgorithm::Sha1),
        1 => Some(TotpAlgorithm::Sha256),
        2 => Some(TotpAlgorithm::Sha512),
        _ => None,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_vault_seal(
    plaintext: *const u8,
    plaintext_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    cipher_id: u8,
    out_len: *mut usize,
) -> *mut u8 {
    let result = catch_unwind(|| {
        if out_len.is_null() {
            return core::ptr::null_mut();
        }

        let plain_slice = if plaintext_len == 0 {
            &[][..]
        } else {
            if plaintext.is_null() {
                return core::ptr::null_mut();
            }
            unsafe { slice::from_raw_parts(plaintext, plaintext_len) }
        };

        if passphrase.is_null() && passphrase_len > 0 {
            return core::ptr::null_mut();
        }
        let pass_slice = if passphrase_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(passphrase, passphrase_len) }
        };

        let cipher = match parse_cipher(cipher_id) {
            Some(c) => c,
            None => return core::ptr::null_mut(),
        };

        match seal(plain_slice, pass_slice, &SecurityConfig::default(), cipher) {
            Ok(sealed) => {
                let len = sealed.len();
                let mut boxed = sealed.into_boxed_slice();
                let ptr = boxed.as_mut_ptr();
                unsafe {
                    *out_len = len;
                }
                let _ = Box::into_raw(boxed);
                ptr
            }
            Err(_) => core::ptr::null_mut(),
        }
    });

    result.unwrap_or(core::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_vault_unseal(
    vault_bytes: *const u8,
    vault_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
) -> *mut LsecWasmBuffer {
    let result = catch_unwind(|| {
        if vault_bytes.is_null() || vault_len == 0 {
            return core::ptr::null_mut();
        }

        let v_slice = unsafe { slice::from_raw_parts(vault_bytes, vault_len) };
        let pass_slice = if passphrase_len == 0 {
            &[][..]
        } else {
            if passphrase.is_null() {
                return core::ptr::null_mut();
            }
            unsafe { slice::from_raw_parts(passphrase, passphrase_len) }
        };

        match unseal(v_slice, pass_slice) {
            Ok(plain_buf) => Box::into_raw(Box::new(LsecWasmBuffer(plain_buf))),
            Err(_) => core::ptr::null_mut(),
        }
    });

    result.unwrap_or(core::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_vault_bytes_free(ptr: *mut u8, len: usize) {
    let _ = catch_unwind(|| {
        if !ptr.is_null() && len > 0 {
            unsafe {
                drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len)));
            }
        }
    });
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_totp_decode_base32(
    base32_ptr: *const u8,
    base32_len: usize,
) -> *mut LsecWasmBuffer {
    let result = catch_unwind(|| {
        if base32_ptr.is_null() || base32_len == 0 {
            return core::ptr::null_mut();
        }

        let bytes = unsafe { slice::from_raw_parts(base32_ptr, base32_len) };
        let s = match core::str::from_utf8(bytes) {
            Ok(val) => val,
            Err(_) => return core::ptr::null_mut(),
        };

        match decode_secret(s) {
            Ok(buf) => Box::into_raw(Box::new(LsecWasmBuffer(buf))),
            Err(_) => core::ptr::null_mut(),
        }
    });

    result.unwrap_or(core::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_totp_generate(
    secret: *const u8,
    secret_len: usize,
    timestamp: u64,
    step_seconds: u64,
    digits: u32,
    algorithm_id: u8,
    out_code: *mut u8,
    out_code_capacity: usize,
) -> i32 {
    let result = catch_unwind(|| {
        if secret.is_null() || out_code.is_null() {
            return -1;
        }

        if out_code_capacity < (digits as usize) {
            return -2;
        }

        let sec_slice = unsafe { slice::from_raw_parts(secret, secret_len) };
        let algo = match parse_algo(algorithm_id) {
            Some(a) => a,
            None => return -3,
        };

        match generate_code(sec_slice, timestamp, step_seconds, digits, algo) {
            Ok(code_str) => {
                let bytes = code_str.as_bytes();
                unsafe {
                    let out_slice = slice::from_raw_parts_mut(out_code, out_code_capacity);
                    out_slice[..bytes.len()].copy_from_slice(bytes);
                }
                0
            }
            Err(_) => -4,
        }
    });

    result.unwrap_or(-5)
}

#[no_mangle]
pub unsafe extern "C" fn lsec_wasm_totp_verify(
    secret: *const u8,
    secret_len: usize,
    candidate: *const u8,
    candidate_len: usize,
    timestamp: u64,
    step_seconds: u64,
    digits: u32,
    drift_steps: u8,
    algorithm_id: u8,
) -> i32 {
    let result = catch_unwind(|| {
        if secret.is_null() || candidate.is_null() {
            return -1;
        }

        let cand_bytes = unsafe { slice::from_raw_parts(candidate, candidate_len) };
        let cand_str = match core::str::from_utf8(cand_bytes) {
            Ok(s) => s,
            Err(_) => return -3,
        };

        let sec_slice = unsafe { slice::from_raw_parts(secret, secret_len) };
        let algo = match parse_algo(algorithm_id) {
            Some(a) => a,
            None => return -3,
        };

        let config = SecurityConfig::builder()
            .totp_step_seconds(step_seconds)
            .totp_digits(digits)
            .totp_drift_steps(drift_steps)
            .build();

        match verify_code_at(sec_slice, cand_str, timestamp, &config, algo) {
            Ok(valid) => if valid { 1 } else { 0 },
            Err(_) => -4,
        }
    });

    result.unwrap_or(-5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_ready() {
        assert_eq!(lsec_wasm_is_ready(), 1);
        assert_eq!(lsec_wasm_version_major(), 0);
        assert_eq!(lsec_wasm_version_minor(), 1);
        assert_eq!(lsec_wasm_version_patch(), 0);
    }

    #[test]
    fn test_wasm_alloc_and_wipe_free() {
        let size = 64;
        let ptr = unsafe { lsec_wasm_alloc(size) };
        assert!(!ptr.is_null());

        let s = unsafe { slice::from_raw_parts_mut(ptr, size) };
        s.fill(0xAA);
        assert_eq!(s[0], 0xAA);

        unsafe {
            lsec_wasm_wipe_and_free(ptr, size);
        }
    }

    #[test]
    fn test_wasm_buffer_lifecycle() {
        let secret = b"wasm-offline-secret-key";
        let handle = unsafe { lsec_wasm_buffer_new(secret.as_ptr(), secret.len()) };
        assert!(!handle.is_null());

        assert_eq!(unsafe { lsec_wasm_buffer_len(handle) }, secret.len());
        let data_ptr = unsafe { lsec_wasm_buffer_data(handle) };
        let slice = unsafe { std::slice::from_raw_parts(data_ptr, secret.len()) };
        assert_eq!(slice, secret);

        assert_eq!(unsafe { lsec_wasm_buffer_wipe(handle) }, 0);
        let wiped = unsafe { std::slice::from_raw_parts(data_ptr, secret.len()) };
        assert_eq!(wiped, &vec![0u8; secret.len()][..]);

        unsafe { lsec_wasm_buffer_free(handle) };
    }

    #[test]
    fn test_wasm_vault_seal_and_unseal() {
        let plain = b"pwa-client-encrypted-record";
        let pass = b"pwa-master-password";
        let mut sealed_len: usize = 0;

        let sealed_ptr = unsafe {
            lsec_wasm_vault_seal(
                plain.as_ptr(),
                plain.len(),
                pass.as_ptr(),
                pass.len(),
                1,
                &mut sealed_len,
            )
        };
        assert!(!sealed_ptr.is_null());
        assert!(sealed_len > plain.len());

        let unseal_handle = unsafe {
            lsec_wasm_vault_unseal(
                sealed_ptr,
                sealed_len,
                pass.as_ptr(),
                pass.len(),
            )
        };
        assert!(!unseal_handle.is_null());

        let unsealed_len = unsafe { lsec_wasm_buffer_len(unseal_handle) };
        let unsealed_ptr = unsafe { lsec_wasm_buffer_data(unseal_handle) };
        let unsealed = unsafe { std::slice::from_raw_parts(unsealed_ptr, unsealed_len) };
        assert_eq!(unsealed, plain);

        unsafe {
            lsec_wasm_vault_bytes_free(sealed_ptr, sealed_len);
            lsec_wasm_buffer_free(unseal_handle);
        }
    }

    #[test]
    fn test_wasm_totp_flow() {
        let seed_b32 = b"JBSWY3DPEHPK3PXP";
        let seed_handle = unsafe {
            lsec_wasm_totp_decode_base32(seed_b32.as_ptr(), seed_b32.len())
        };
        assert!(!seed_handle.is_null());

        let seed_ptr = unsafe { lsec_wasm_buffer_data(seed_handle) };
        let seed_len = unsafe { lsec_wasm_buffer_len(seed_handle) };

        let mut code_buf = [0u8; 6];
        let timestamp = 1234567890u64;

        let status = unsafe {
            lsec_wasm_totp_generate(
                seed_ptr,
                seed_len,
                timestamp,
                30,
                6,
                0,
                code_buf.as_mut_ptr(),
                code_buf.len(),
            )
        };
        assert_eq!(status, 0);

        let valid = unsafe {
            lsec_wasm_totp_verify(
                seed_ptr,
                seed_len,
                code_buf.as_ptr(),
                code_buf.len(),
                timestamp,
                30,
                6,
                1,
                0,
            )
        };
        assert_eq!(valid, 1);

        unsafe { lsec_wasm_buffer_free(seed_handle) };
    }
}
