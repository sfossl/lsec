#[cfg(unix)]
pub(crate) mod sys_unix;

#[cfg(windows)]
pub(crate) mod sys_windows;

pub mod buffer;

pub use buffer::{MemguardError, ProtectedBuffer};
