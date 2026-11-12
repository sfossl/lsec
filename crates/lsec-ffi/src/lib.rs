#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

pub mod error;
pub mod memguard;
pub mod totp;
pub mod vault;

pub use error::*;
pub use memguard::*;
pub use totp::*;
pub use vault::*;

#[no_mangle]
pub extern "C" fn lsec_version_major() -> u32 {
    0
}

#[no_mangle]
pub extern "C" fn lsec_version_minor() -> u32 {
    2
}

#[no_mangle]
pub extern "C" fn lsec_version_patch() -> u32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn lsec_process_harden() -> i32 {
    let result = std::panic::catch_unwind(|| match lsec_core::process::harden_process() {
        Ok(()) => LSEC_OK,
        Err(_) => LSEC_ERR_IO_FAILED,
    });
    result.unwrap_or(LSEC_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn test_version_exports() {
        assert_eq!(lsec_version_major(), 0);
        assert_eq!(lsec_version_minor(), 2);
        assert_eq!(lsec_version_patch(), 0);
    }

    #[test]
    fn test_process_harden_c_abi() {
        let status = unsafe { lsec_process_harden() };
        assert_eq!(status, LSEC_OK);
    }

    #[test]
    fn test_buffer_c_lifecycle() {
        let secret = b"c-abi-secret-payload";
        let mut handle: *mut LsecProtectedBuffer = core::ptr::null_mut();

        let status = unsafe { lsec_buffer_new(secret.as_ptr(), secret.len(), &mut handle) };
        assert_eq!(status, LSEC_OK);
        assert!(!handle.is_null());

        let len = unsafe { lsec_buffer_len(handle) };
        assert_eq!(len, secret.len());

        let data_ptr = unsafe { lsec_buffer_data(handle) };
        let slice = unsafe { std::slice::from_raw_parts(data_ptr, len) };
        assert_eq!(slice, secret);

        let wipe_status = unsafe { lsec_buffer_wipe(handle) };
        assert_eq!(wipe_status, LSEC_OK);

        let wiped_slice = unsafe { std::slice::from_raw_parts(data_ptr, len) };
        assert_eq!(wiped_slice, &vec![0u8; secret.len()][..]);

        unsafe { lsec_buffer_free(handle) };
    }

    #[test]
    fn test_vault_c_seal_and_unseal() {
        let secret = b"vault-c-abi-test";
        let pass = b"passphrase";

        let mut out_bytes: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;

        let seal_status = unsafe {
            lsec_vault_seal(
                secret.as_ptr(),
                secret.len(),
                pass.as_ptr(),
                pass.len(),
                1, // ChaCha20Poly1305
                &mut out_bytes,
                &mut out_len,
            )
        };
        assert_eq!(seal_status, LSEC_OK);
        assert!(!out_bytes.is_null());
        assert!(out_len > secret.len());

        let mut unseal_handle: *mut LsecProtectedBuffer = core::ptr::null_mut();
        let unseal_status = unsafe {
            lsec_vault_unseal(
                out_bytes,
                out_len,
                pass.as_ptr(),
                pass.len(),
                &mut unseal_handle,
            )
        };
        assert_eq!(unseal_status, LSEC_OK);
        assert!(!unseal_handle.is_null());

        let unsealed_len = unsafe { lsec_buffer_len(unseal_handle) };
        let unsealed_ptr = unsafe { lsec_buffer_data(unseal_handle) };
        let unsealed_slice = unsafe { std::slice::from_raw_parts(unsealed_ptr, unsealed_len) };
        assert_eq!(unsealed_slice, secret);

        unsafe {
            lsec_vault_bytes_free(out_bytes, out_len);
            lsec_buffer_free(unseal_handle);
        }
    }

    #[test]
    fn test_totp_c_generate_and_verify() {
        let base32_seed = CString::new("JBSWY3DPEHPK3PXP").unwrap();
        let mut seed_handle: *mut LsecProtectedBuffer = core::ptr::null_mut();

        let dec_status = unsafe { lsec_totp_decode_base32(base32_seed.as_ptr(), &mut seed_handle) };
        assert_eq!(dec_status, LSEC_OK);
        assert!(!seed_handle.is_null());

        let seed_len = unsafe { lsec_buffer_len(seed_handle) };
        let seed_ptr = unsafe { lsec_buffer_data(seed_handle) };

        let mut code_buf = [0i8; 16];
        let timestamp = 1234567890u64;

        let gen_status = unsafe {
            lsec_totp_generate(
                seed_ptr,
                seed_len,
                timestamp,
                30,
                6,
                0, // Sha1
                code_buf.as_mut_ptr(),
                code_buf.len(),
            )
        };
        assert_eq!(gen_status, LSEC_OK);

        let code_cstr = unsafe { CStr::from_ptr(code_buf.as_ptr()) };
        let code_str = code_cstr.to_str().unwrap();
        assert_eq!(code_str.len(), 6);

        let mut is_valid: i32 = 0;
        let ver_status = unsafe {
            lsec_totp_verify(
                seed_ptr,
                seed_len,
                code_buf.as_ptr(),
                timestamp,
                30,
                6,
                1,
                0,
                &mut is_valid,
            )
        };
        assert_eq!(ver_status, LSEC_OK);
        assert_eq!(is_valid, 1);

        unsafe { lsec_buffer_free(seed_handle) };
    }

    #[test]
    fn test_multi_vault_c_abi() {
        let payload = b"c-abi multi-slot secret";
        let pass0 = b"primary-passphrase";
        let pass1 = b"secondary-credential";

        let mut out_bytes: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;

        let status = unsafe {
            lsec_multi_vault_create(
                payload.as_ptr(),
                payload.len(),
                pass0.as_ptr(),
                pass0.len(),
                1,
                &mut out_bytes,
                &mut out_len,
            )
        };
        assert_eq!(status, LSEC_OK);
        assert!(!out_bytes.is_null());
        assert!(out_len >= 367);

        let mut active_slots = [0u8; 4];
        let status = unsafe {
            lsec_multi_vault_active_slots(out_bytes, out_len, active_slots.as_mut_ptr(), 4)
        };
        assert_eq!(status, LSEC_OK);
        assert_eq!(active_slots, [1, 0, 0, 0]);

        let mut slot_idx: usize = 0;
        let status = unsafe {
            lsec_multi_vault_add_slot(
                out_bytes,
                out_len,
                pass0.as_ptr(),
                pass0.len(),
                pass1.as_ptr(),
                pass1.len(),
                2,
                &mut slot_idx,
            )
        };
        assert_eq!(status, LSEC_OK);
        assert_eq!(slot_idx, 1);

        let status = unsafe {
            lsec_multi_vault_active_slots(out_bytes, out_len, active_slots.as_mut_ptr(), 4)
        };
        assert_eq!(status, LSEC_OK);
        assert_eq!(active_slots, [1, 1, 0, 0]);

        let mut unseal_handle: *mut LsecProtectedBuffer = core::ptr::null_mut();
        let status = unsafe {
            lsec_multi_vault_open(
                out_bytes,
                out_len,
                pass1.as_ptr(),
                pass1.len(),
                &mut unseal_handle,
            )
        };
        assert_eq!(status, LSEC_OK);
        assert!(!unseal_handle.is_null());

        let len = unsafe { lsec_buffer_len(unseal_handle) };
        let ptr = unsafe { lsec_buffer_data(unseal_handle) };
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert_eq!(slice, payload);
        unsafe {
            lsec_buffer_free(unseal_handle);
        }

        let new_payload = b"updated payload data via sub-millisecond c-abi";
        let mut updated_bytes: *mut u8 = core::ptr::null_mut();
        let mut updated_len: usize = 0;

        let status = unsafe {
            lsec_multi_vault_update_payload(
                out_bytes,
                out_len,
                pass0.as_ptr(),
                pass0.len(),
                new_payload.as_ptr(),
                new_payload.len(),
                &mut updated_bytes,
                &mut updated_len,
            )
        };
        assert_eq!(status, LSEC_OK);
        assert!(!updated_bytes.is_null());

        let mut unseal_updated: *mut LsecProtectedBuffer = core::ptr::null_mut();
        let status = unsafe {
            lsec_vault_unseal(
                updated_bytes,
                updated_len,
                pass1.as_ptr(),
                pass1.len(),
                &mut unseal_updated,
            )
        };
        assert_eq!(status, LSEC_OK);
        let u_len = unsafe { lsec_buffer_len(unseal_updated) };
        let u_ptr = unsafe { lsec_buffer_data(unseal_updated) };
        let u_slice = unsafe { std::slice::from_raw_parts(u_ptr, u_len) };
        assert_eq!(u_slice, new_payload);

        unsafe {
            lsec_buffer_free(unseal_updated);
            lsec_vault_bytes_free(out_bytes, out_len);
            lsec_vault_bytes_free(updated_bytes, updated_len);
        }
    }

    #[test]
    fn test_null_pointer_safety() {
        assert_eq!(
            unsafe { lsec_buffer_new(core::ptr::null(), 10, core::ptr::null_mut()) },
            LSEC_ERR_NULL_POINTER
        );
        assert_eq!(
            unsafe {
                lsec_vault_seal(
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    1,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            },
            LSEC_ERR_NULL_POINTER
        );
        assert_eq!(
            unsafe { lsec_totp_decode_base32(core::ptr::null(), core::ptr::null_mut()) },
            LSEC_ERR_NULL_POINTER
        );
    }
}
