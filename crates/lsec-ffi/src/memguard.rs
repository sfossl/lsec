use std::panic::catch_unwind;
use std::slice;

use lsec_core::memguard::{MemguardError, ProtectedBuffer};

use crate::error::{
    LSEC_ERR_ALLOC_FAILED, LSEC_ERR_LOCK_FAILED, LSEC_ERR_NULL_POINTER, LSEC_ERR_PANIC, LSEC_OK,
};

pub struct LsecProtectedBuffer(pub ProtectedBuffer);

#[no_mangle]
pub unsafe extern "C" fn lsec_buffer_new(
    data: *const u8,
    len: usize,
    out_buf: *mut *mut LsecProtectedBuffer,
) -> i32 {
    let result = catch_unwind(|| {
        if out_buf.is_null() {
            return LSEC_ERR_NULL_POINTER;
        }

        let slice = if len == 0 {
            &[][..]
        } else {
            if data.is_null() {
                return LSEC_ERR_NULL_POINTER;
            }
            unsafe { slice::from_raw_parts(data, len) }
        };

        match ProtectedBuffer::new(slice) {
            Ok(buf) => {
                let boxed = Box::new(LsecProtectedBuffer(buf));
                unsafe {
                    *out_buf = Box::into_raw(boxed);
                }
                LSEC_OK
            }
            Err(MemguardError::ExceedsMaxAllocation(_)) | Err(MemguardError::AllocationFailed) => {
                LSEC_ERR_ALLOC_FAILED
            }
            Err(MemguardError::LockFailed(_)) => LSEC_ERR_LOCK_FAILED,
        }
    });

    result.unwrap_or(LSEC_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn lsec_buffer_zeroed(
    len: usize,
    out_buf: *mut *mut LsecProtectedBuffer,
) -> i32 {
    let result = catch_unwind(|| {
        if out_buf.is_null() {
            return LSEC_ERR_NULL_POINTER;
        }

        match ProtectedBuffer::zeroed(len) {
            Ok(buf) => {
                let boxed = Box::new(LsecProtectedBuffer(buf));
                unsafe {
                    *out_buf = Box::into_raw(boxed);
                }
                LSEC_OK
            }
            Err(MemguardError::ExceedsMaxAllocation(_)) | Err(MemguardError::AllocationFailed) => {
                LSEC_ERR_ALLOC_FAILED
            }
            Err(MemguardError::LockFailed(_)) => LSEC_ERR_LOCK_FAILED,
        }
    });

    result.unwrap_or(LSEC_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn lsec_buffer_len(buf: *const LsecProtectedBuffer) -> usize {
    if buf.is_null() {
        return 0;
    }
    unsafe { (*buf).0.len() }
}

#[no_mangle]
pub unsafe extern "C" fn lsec_buffer_data(buf: *const LsecProtectedBuffer) -> *const u8 {
    if buf.is_null() {
        return core::ptr::null();
    }
    unsafe { (*buf).0.as_slice().as_ptr() }
}

#[no_mangle]
pub unsafe extern "C" fn lsec_buffer_data_mut(buf: *mut LsecProtectedBuffer) -> *mut u8 {
    if buf.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { (*buf).0.as_mut_slice().as_mut_ptr() }
}

#[no_mangle]
pub unsafe extern "C" fn lsec_buffer_wipe(buf: *mut LsecProtectedBuffer) -> i32 {
    let result = catch_unwind(|| {
        if buf.is_null() {
            return LSEC_ERR_NULL_POINTER;
        }
        unsafe {
            (*buf).0.wipe();
        }
        LSEC_OK
    });

    result.unwrap_or(LSEC_ERR_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn lsec_buffer_free(buf: *mut LsecProtectedBuffer) {
    let _ = catch_unwind(|| {
        if !buf.is_null() {
            unsafe {
                drop(Box::from_raw(buf));
            }
        }
    });
}
