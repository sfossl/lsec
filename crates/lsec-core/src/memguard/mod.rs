#[cfg(unix)]
pub(crate) mod sys_unix;

#[cfg(windows)]
pub(crate) mod sys_windows;

pub mod array;
pub mod buffer;

pub use array::ProtectedArray;
pub use buffer::{MemguardError, ProtectedBuffer};
