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
from .vault import CipherSuite, MultiSlotVault, seal, seal_to_file, unseal, unseal_from_file
from . import totp, vault

__version__ = "0.2.0"

__all__ = [
    "AllocationError",
    "BufferTooSmallError",
    "CipherSuite",
    "CryptoError",
    "InvalidParameterError",
    "LibraryNotFoundError",
    "LsecError",
    "MemoryLockError",
    "MultiSlotVault",
    "NullPointerError",
    "PanicError",
    "SecureBuffer",
    "Totp",
    "TotpAlgorithm",
    "TotpError",
    "UnknownError",
    "VaultCorruptError",
    "VaultIOError",
    "harden_process",
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


def harden_process() -> None:
    """Enforce anti-debugging and core-dump exclusion on the current process."""
    from .errors import check
    check(load_library().lsec_process_harden())


def version() -> Tuple[int, int, int]:
    """Version of the loaded native library as ``(major, minor, patch)``."""
    lib = load_library()
    return (lib.lsec_version_major(), lib.lsec_version_minor(), lib.lsec_version_patch())
