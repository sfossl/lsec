use core::fmt;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use std::alloc::{alloc, dealloc, Layout};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::DEFAULT_MAX_LOCKED_MEMORY_BYTES;

#[cfg(unix)]
use super::sys_unix as sys;

#[cfg(windows)]
use super::sys_windows as sys;

#[cfg(not(any(unix, windows)))]
mod sys {
    use core::ptr::NonNull;
    use std::io::Error;

    pub(crate) fn page_size() -> usize {
        16
    }

    pub(crate) fn lock_memory(_ptr: NonNull<u8>, _len: usize) -> Result<(), Error> {
        Ok(())
    }

    pub(crate) fn unlock_memory(_ptr: NonNull<u8>, _len: usize) -> Result<(), Error> {
        Ok(())
    }

    pub(crate) fn mark_dont_dump(_ptr: NonNull<u8>, _len: usize) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Debug)]
pub enum MemguardError {
    ExceedsMaxAllocation(usize),
    AllocationFailed,
    LockFailed(std::io::Error),
}

impl fmt::Display for MemguardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceedsMaxAllocation(len) => {
                write!(f, "allocation of {} bytes exceeds limit", len)
            }
            Self::AllocationFailed => write!(f, "memory allocation failed"),
            Self::LockFailed(err) => write!(f, "failed to lock memory into ram: {}", err),
        }
    }
}

impl std::error::Error for MemguardError {}

pub struct ProtectedBuffer {
    ptr: NonNull<u8>,
    len: usize,
    layout: Layout,
}

// safety: protected buffer owns the underlying memory allocation exclusively
unsafe impl Send for ProtectedBuffer {}
unsafe impl Sync for ProtectedBuffer {}

impl ProtectedBuffer {
    pub fn new(data: &[u8]) -> Result<Self, MemguardError> {
        let mut buf = Self::zeroed(data.len())?;
        buf.as_mut_slice().copy_from_slice(data);
        Ok(buf)
    }

    pub fn zeroed(len: usize) -> Result<Self, MemguardError> {
        if len > DEFAULT_MAX_LOCKED_MEMORY_BYTES {
            return Err(MemguardError::ExceedsMaxAllocation(len));
        }

        if len == 0 {
            return Ok(Self {
                ptr: NonNull::dangling(),
                len: 0,
                layout: Layout::from_size_align(0, 1).unwrap(),
            });
        }

        let page_sz = sys::page_size();
        let alloc_size = len
            .checked_add(page_sz - 1)
            .map(|n| n & !(page_sz - 1))
            .ok_or(MemguardError::AllocationFailed)?;
        let layout = Layout::from_size_align(alloc_size, page_sz)
            .map_err(|_| MemguardError::AllocationFailed)?;

        let raw_ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(raw_ptr).ok_or(MemguardError::AllocationFailed)?;

        unsafe {
            core::ptr::write_bytes(ptr.as_ptr(), 0, alloc_size);
        }

        if let Err(e) = sys::lock_memory(ptr, alloc_size) {
            unsafe { dealloc(ptr.as_ptr(), layout) };
            return Err(MemguardError::LockFailed(e));
        }

        let _ = sys::mark_dont_dump(ptr, alloc_size);

        Ok(Self { ptr, len, layout })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.len == 0 {
            &mut []
        } else {
            unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
        }
    }

    pub fn wipe(&mut self) {
        if self.len > 0 {
            self.as_mut_slice().zeroize();
        }
    }
}

impl Zeroize for ProtectedBuffer {
    fn zeroize(&mut self) {
        self.wipe();
    }
}

impl ZeroizeOnDrop for ProtectedBuffer {}

impl Deref for ProtectedBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for ProtectedBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl fmt::Debug for ProtectedBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProtectedBuffer([REDACTED len={}])", self.len)
    }
}

impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        if self.len > 0 {
            self.wipe();
            let _ = sys::unlock_memory(self.ptr, self.layout.size());
            unsafe {
                dealloc(self.ptr.as_ptr(), self.layout);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_read_buffer() {
        let secret = b"super-confidential-secret-bytes";
        let buf = ProtectedBuffer::new(secret).expect("allocation ok");
        assert_eq!(buf.len(), secret.len());
        assert_eq!(&buf[..], secret);
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_zero_length_buffer() {
        let buf = ProtectedBuffer::new(&[]).expect("zero len ok");
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert_eq!(&buf[..], &[]);
    }

    #[test]
    fn test_exceeds_max_allocation() {
        let res = ProtectedBuffer::zeroed(DEFAULT_MAX_LOCKED_MEMORY_BYTES + 1);
        assert!(matches!(res, Err(MemguardError::ExceedsMaxAllocation(_))));
    }

    #[test]
    fn test_debug_redacted() {
        let secret = b"my-plain-password";
        let buf = ProtectedBuffer::new(secret).expect("ok");
        let debug_str = format!("{:?}", buf);
        assert!(!debug_str.contains("my-plain-password"));
        assert!(debug_str.contains("[REDACTED"));
    }

    #[test]
    fn test_wipe_clears_memory() {
        let secret = b"secret-passphrase-to-wipe";
        let mut buf = ProtectedBuffer::new(secret).expect("ok");
        assert_eq!(&buf[..], secret);
        buf.wipe();
        assert_eq!(&buf[..], &vec![0u8; secret.len()][..]);
    }

    #[test]
    fn test_zeroize_trait() {
        let secret = b"zeroize-trait-verification";
        let mut buf = ProtectedBuffer::new(secret).expect("ok");
        buf.zeroize();
        assert_eq!(&buf[..], &vec![0u8; secret.len()][..]);
    }

    #[test]
    fn test_send_across_thread() {
        let secret = b"thread-send-secret";
        let buf = ProtectedBuffer::new(secret).expect("ok");
        let handle = std::thread::spawn(move || {
            assert_eq!(&buf[..], secret);
        });
        handle.join().expect("thread join ok");
    }

    #[test]
    fn test_sync_shared_across_threads() {
        use std::sync::Arc;

        let secret = b"thread-sync-shared-secret";
        let buf = Arc::new(ProtectedBuffer::new(secret).expect("ok"));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let buf_clone = Arc::clone(&buf);
            handles.push(std::thread::spawn(move || {
                assert_eq!(&buf_clone[..], secret);
            }));
        }

        for handle in handles {
            handle.join().expect("join ok");
        }
    }

    #[test]
    fn test_concurrent_alloc_and_drop() {
        let mut handles = Vec::new();

        for i in 0..10 {
            handles.push(std::thread::spawn(move || {
                let data = vec![i as u8; 1024];
                let mut buf = ProtectedBuffer::new(&data).expect("ok");
                assert_eq!(&buf[..], &data[..]);
                buf.wipe();
            }));
        }

        for handle in handles {
            handle.join().expect("join ok");
        }
    }
}
