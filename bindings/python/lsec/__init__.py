from typing import Tuple

from ._loader import library_path, load_library
from .buffer import SecureBuffer
from .errors import (
    AllocationError,
    BufferTooSmallError,
    CryptoError,
    InvalidParameterError,
    LibraryNotFoundError,
    LsecError,
    MemoryLockError,
    NullPointerError,
    PanicError,
    TotpError,
    UnknownError,
    VaultCorruptError,
    VaultIOError,
)
from .totp import Totp, TotpAlgorithm
from .vault import CipherSuite, seal, seal_to_file, unseal, unseal_from_file
from . import totp, vault

__version__ = "0.1.0"

__all__ = [
    "AllocationError",
    "BufferTooSmallError",
    "CipherSuite",
    "CryptoError",
    "InvalidParameterError",
    "LibraryNotFoundError",
    "LsecError",
    "MemoryLockError",
    "NullPointerError",
    "PanicError",
    "SecureBuffer",
    "Totp",
    "TotpAlgorithm",
    "TotpError",
    "UnknownError",
    "VaultCorruptError",
    "VaultIOError",
    "library_path",
    "load_library",
    "seal",
    "seal_to_file",
    "totp",
    "unseal",
    "unseal_from_file",
    "vault",
    "version",
]


def version() -> Tuple[int, int, int]:
    """Version of the loaded native library as ``(major, minor, patch)``."""
    lib = load_library()
    return (lib.lsec_version_major(), lib.lsec_version_minor(), lib.lsec_version_patch())
