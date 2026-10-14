use core::ptr::NonNull;
use std::io::Error;

// shortcut: hardcoded 4kb page size for x86_64 windows, query GetSystemInfo if arm64 page sizes differ
const DEFAULT_PAGE_SIZE: usize = 4096;

pub(crate) fn page_size() -> usize {
    DEFAULT_PAGE_SIZE
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
    let ret = unsafe {
        windows_sys::Win32::System::Memory::VirtualLock(
            addr as *const core::ffi::c_void,
            aligned_len,
        )
    };

    if ret != 0 {
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
    let ret = unsafe {
        windows_sys::Win32::System::Memory::VirtualUnlock(
            addr as *const core::ffi::c_void,
            aligned_len,
        )
    };

    if ret != 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

pub(crate) fn mark_dont_dump(_ptr: NonNull<u8>, _len: usize) -> Result<(), Error> {
    Ok(())
}

