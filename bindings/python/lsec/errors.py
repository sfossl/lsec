from __future__ import annotations

from typing import Iterable, Optional

LSEC_OK = 0
LSEC_ERR_NULL_POINTER = -1
LSEC_ERR_BUFFER_TOO_SMALL = -2
LSEC_ERR_INVALID_PARAM = -3
LSEC_ERR_ALLOC_FAILED = -4
LSEC_ERR_LOCK_FAILED = -5
LSEC_ERR_CRYPTO_FAILED = -6
LSEC_ERR_VAULT_CORRUPT = -7
LSEC_ERR_IO_FAILED = -8
LSEC_ERR_TOTP_FAILED = -9
LSEC_ERR_PANIC = -10


class LsecError(Exception):
    """Base class for every error raised by lsec."""

    code: Optional[int] = None
    default_message = "lsec: unknown internal error"

    def __init__(self, message: Optional[str] = None, code: Optional[int] = None) -> None:
        if code is not None:
            self.code = code
        super().__init__(message or self.default_message)


class LibraryNotFoundError(LsecError, OSError):
    default_message = "lsec: could not locate the lsec_ffi shared library"

    def __init__(self, message: Optional[str] = None, tried: Iterable[str] = ()) -> None:
        self.tried = list(tried)
        if message is None and self.tried:
            lines = "\n  ".join(self.tried)
            message = (
                f"{self.default_message}; tried:\n  {lines}\n"
                "build it with `cargo build -p lsec-ffi` or set LSEC_LIB_PATH"
            )
        super().__init__(message)


class NullPointerError(LsecError):
    code = LSEC_ERR_NULL_POINTER
    default_message = "lsec: null pointer passed to c-abi"


class BufferTooSmallError(LsecError):
    code = LSEC_ERR_BUFFER_TOO_SMALL
    default_message = "lsec: destination buffer too small"


class InvalidParameterError(LsecError, ValueError):
    code = LSEC_ERR_INVALID_PARAM
    default_message = "lsec: invalid parameter"


class AllocationError(LsecError, MemoryError):
    code = LSEC_ERR_ALLOC_FAILED
    default_message = "lsec: memory allocation failed"


class MemoryLockError(LsecError):
    code = LSEC_ERR_LOCK_FAILED
    default_message = "lsec: failed to lock memory pages into physical ram"


class CryptoError(LsecError):
    code = LSEC_ERR_CRYPTO_FAILED
    default_message = "lsec: cryptographic operation failed"


class VaultCorruptError(LsecError):
    code = LSEC_ERR_VAULT_CORRUPT
    default_message = "lsec: vault payload is corrupted or header is invalid"


class VaultIOError(LsecError, OSError):
    code = LSEC_ERR_IO_FAILED
    default_message = "lsec: filesystem io operation failed"


class TotpError(LsecError):
    code = LSEC_ERR_TOTP_FAILED
    default_message = "lsec: totp calculation or verification failed"


class PanicError(LsecError):
    code = LSEC_ERR_PANIC
    default_message = "lsec: unexpected panic caught across ffi boundary"


class UnknownError(LsecError):
    default_message = "lsec: unknown internal error"


_ERRORS_BY_CODE = {
    cls.code: cls
    for cls in (
        NullPointerError,
        BufferTooSmallError,
        InvalidParameterError,
        AllocationError,
        MemoryLockError,
        CryptoError,
        VaultCorruptError,
        VaultIOError,
        TotpError,
        PanicError,
    )
}


def error_for_code(status: int) -> LsecError:
    """Return the exception instance for a negative lsec status code."""
    cls = _ERRORS_BY_CODE.get(status)
    if cls is None:
        return UnknownError(f"lsec: unknown internal error (code {status})", code=status)
    return cls()


def check(status: int) -> None:
    """Raise the matching LsecError if ``status`` is not LSEC_OK."""
    if status != LSEC_OK:
        raise error_for_code(status)
