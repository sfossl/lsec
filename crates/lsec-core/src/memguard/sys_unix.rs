#![allow(dead_code)]

use core::ptr::NonNull;
use std::io::Error;

pub(crate) fn page_size() -> usize {
    let sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if sz > 0 {
        sz as usize
    } else {
        4096
    }
}

fn align_to_page(ptr: NonNull<u8>, len: usize) -> (usize, usize) {
    let sz = page_size();
    let addr = ptr.as_ptr() as usize;
    let page_start = addr & !(sz - 1);
    let page_end = (addr.saturating_add(len).saturating_add(sz - 1)) & !(sz - 1);
    (page_start, page_end.saturating_sub(page_start))
}

pub(crate) fn lock_memory(ptr: NonNull<u8>, len: usize) -> Result<(), Error> {
    if len == 0 {
        return Ok(());
    }

    let (addr, aligned_len) = align_to_page(ptr, len);
    let ret = unsafe { libc::mlock(addr as *const libc::c_void, aligned_len) };
    if ret == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

pub(crate) fn unlock_memory(ptr: NonNull<u8>, len: usize) -> Result<(), Error> {
    if len == 0 {
        return Ok(());
    }

    let (addr, aligned_len) = align_to_page(ptr, len);
    let ret = unsafe { libc::munlock(addr as *const libc::c_void, aligned_len) };
    if ret == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn mark_dont_dump(ptr: NonNull<u8>, len: usize) -> Result<(), Error> {
    if len == 0 {
        return Ok(());
    }

    let (addr, aligned_len) = align_to_page(ptr, len);
    let ret = unsafe { libc::madvise(addr as *mut libc::c_void, aligned_len, libc::MADV_DONTDUMP) };
    if ret == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn mark_dont_dump(_ptr: NonNull<u8>, _len: usize) -> Result<(), Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_and_unlock_page() {
        let mut buffer = vec![0u8; 8192];
        let ptr = NonNull::new(buffer.as_mut_ptr()).expect("non null pointer");

        let lock_res = lock_memory(ptr, buffer.len());
        if lock_res.is_ok() {
            let dump_res = mark_dont_dump(ptr, buffer.len());
            assert!(dump_res.is_ok());

            let unlock_res = unlock_memory(ptr, buffer.len());
            assert!(unlock_res.is_ok());
        }
    }

    #[test]
    fn test_zero_length_no_op() {
        let mut val = 42u8;
        let ptr = NonNull::new(&mut val as *mut u8).expect("non null");

        assert!(lock_memory(ptr, 0).is_ok());
        assert!(mark_dont_dump(ptr, 0).is_ok());
        assert!(unlock_memory(ptr, 0).is_ok());
    }

    #[test]
    fn test_page_alignment_calc() {
        let sz = page_size();
        let dummy = (sz * 2 + 15) as *mut u8;
        let ptr = NonNull::new(dummy).expect("non null");
        let (start, len) = align_to_page(ptr, 50);
        assert_eq!(start % sz, 0);
        assert_eq!(len % sz, 0);
        assert!(len >= 50);
    }
}
