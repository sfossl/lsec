use core::fmt;
use std::io::Error as IoError;

#[derive(Debug)]
pub enum ProcessError {
    SyscallFailed(IoError),
    UnsupportedPlatform,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SyscallFailed(err) => write!(f, "process hardening syscall failed: {}", err),
            Self::UnsupportedPlatform => {
                write!(f, "process hardening is not supported on this platform")
            }
        }
    }
}

impl std::error::Error for ProcessError {}

impl From<IoError> for ProcessError {
    fn from(err: IoError) -> Self {
        Self::SyscallFailed(err)
    }
}

pub fn disable_dumpable() -> Result<(), ProcessError> {
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        if ret != 0 {
            return Err(ProcessError::SyscallFailed(IoError::last_os_error()));
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode(
                windows_sys::Win32::System::Diagnostics::Debug::SEM_NOGPFAULTERRORBOX,
            );
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(())
    }
}

pub fn deny_debugger() -> Result<(), ProcessError> {
    #[cfg(target_os = "macos")]
    {
        let ret = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, core::ptr::null_mut(), 0) };
        if ret != 0 {
            return Err(ProcessError::SyscallFailed(IoError::last_os_error()));
        }
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

pub fn harden_process() -> Result<(), ProcessError> {
    disable_dumpable()?;
    deny_debugger()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harden_process_success() {
        let res = harden_process();
        assert!(res.is_ok());

        #[cfg(target_os = "linux")]
        {
            let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
            assert_eq!(dumpable, 0);
        }
    }

    #[test]
    fn test_disable_dumpable_idempotent() {
        assert!(disable_dumpable().is_ok());
        assert!(disable_dumpable().is_ok());
    }
}
