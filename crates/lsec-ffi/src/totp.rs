use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::catch_unwind;
use std::slice;

use lsec_core::config::SecurityConfig;
use lsec_core::totp::{decode_secret, generate_code, verify_code_at, TotpAlgorithm, TotpError};

use crate::error::{
    LSEC_ERR_BUFFER_TOO_SMALL, LSEC_ERR_INVALID_PARAM, LSEC_ERR_NULL_POINTER, LSEC_ERR_PANIC,
    LSEC_ERR_TOTP_FAILED, LSEC_OK,
};
use crate::memguard::LsecProtectedBuffer;

fn parse_algorithm(algorithm_id: u8) -> Result<TotpAlgorithm, i32> {
    match algorithm_id {
        0 => Ok(TotpAlgorithm::Sha1),
        1 => Ok(TotpAlgorithm::Sha256),
        2 => Ok(TotpAlgorithm::Sha512),
        _ => Err(LSEC_ERR_INVALID_PARAM),
    }
}

fn map_totp_error(err: TotpError) -> i32 {
    match err {
        TotpError::InvalidStepSeconds
        | TotpError::InvalidDigits(_)
        | TotpError::EmptySecret
        | TotpError::InvalidBase32
        | TotpError::InvalidKeyLength
        | TotpError::SystemTimeBeforeEpoch => LSEC_ERR_TOTP_FAILED,
        TotpError::Memguard(_) => LSEC_ERR_TOTP_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lsec_totp_decode_base32(
    base32_str: *const c_char,
    out_buf: *mut *mut LsecProtectedBuffer,
) -> i32 {
    let result = catch_unwind(|| {
        if base32_str.is_null() || out_buf.is_null() {
            return LSEC_ERR_NULL_POINTER;
        }

        let c_str = unsafe { CStr::from_ptr(base32_str) };
        let encoded = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return LSEC_ERR_INVALID_PARAM,
        };

        match decode_secret(encoded) {
            Ok(buf) => {
                let boxed = Box::new(LsecProtectedBuffer(buf));
                unsafe {
                    *out_buf = Box::into_raw(boxed);
                }
                LSEC_OK
            }
            Err(e) => map_totp_error(e),
        }
    });

    result.unwrap_or(LSEC_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn lsec_totp_generate(
    secret: *const u8,
    secret_len: usize,
    timestamp: u64,
    step_seconds: u64,
    digits: u32,
    algorithm_id: u8,
    out_code: *mut c_char,
    out_code_capacity: usize,
) -> i32 {
    let result = catch_unwind(|| {
        if secret.is_null() || out_code.is_null() {
            return LSEC_ERR_NULL_POINTER;
        }

        if out_code_capacity < (digits as usize + 1) {
            return LSEC_ERR_BUFFER_TOO_SMALL;
        }

        let sec_slice = unsafe { slice::from_raw_parts(secret, secret_len) };
        let algo = match parse_algorithm(algorithm_id) {
            Ok(a) => a,
            Err(code) => return code,
        };

        match generate_code(sec_slice, timestamp, step_seconds, digits, algo) {
            Ok(code_str) => {
                let bytes = code_str.as_bytes();
                unsafe {
                    let out_slice =
                        slice::from_raw_parts_mut(out_code as *mut u8, out_code_capacity);
                    out_slice[..bytes.len()].copy_from_slice(bytes);
                    out_slice[bytes.len()] = 0;
                }
                LSEC_OK
            }
            Err(e) => map_totp_error(e),
        }
    });

    result.unwrap_or(LSEC_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn lsec_totp_verify(
    secret: *const u8,
    secret_len: usize,
    candidate_code: *const c_char,
    timestamp: u64,
    step_seconds: u64,
    digits: u32,
    drift_steps: u8,
    algorithm_id: u8,
    out_is_valid: *mut i32,
) -> i32 {
    let result = catch_unwind(|| {
        if secret.is_null() || candidate_code.is_null() || out_is_valid.is_null() {
            return LSEC_ERR_NULL_POINTER;
        }

        let c_str = unsafe { CStr::from_ptr(candidate_code) };
        let code_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return LSEC_ERR_INVALID_PARAM,
        };

        let sec_slice = unsafe { slice::from_raw_parts(secret, secret_len) };
        let algo = match parse_algorithm(algorithm_id) {
            Ok(a) => a,
            Err(code) => return code,
        };

        let config = SecurityConfig::builder()
            .totp_step_seconds(step_seconds)
            .totp_digits(digits)
            .totp_drift_steps(drift_steps)
            .build();

        match verify_code_at(sec_slice, code_str, timestamp, &config, algo) {
            Ok(valid) => {
                unsafe {
                    *out_is_valid = if valid { 1 } else { 0 };
                }
                LSEC_OK
            }
            Err(e) => map_totp_error(e),
        }
    });

    result.unwrap_or(LSEC_ERR_PANIC)
}
