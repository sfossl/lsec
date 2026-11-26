from __future__ import annotations

import ctypes
import enum
import os
from typing import Union

from . import _ffi
from ._loader import load_library
from ._util import U8_MAX, c_string, uint
from .buffer import BytesLike, SecureBuffer, _borrow
from .errors import check


class CipherSuite(enum.IntEnum):
    CHACHA20_POLY1305 = _ffi.LSEC_CIPHER_CHACHA20_POLY1305
    AES256_GCM = _ffi.LSEC_CIPHER_AES256_GCM


StrPath = Union[str, "os.PathLike[str]"]


def _cipher_id(cipher: int) -> int:
    # unknown ids in range are left for the library to reject
    return uint(int(cipher), "cipher", U8_MAX)


def _encode_path(path: StrPath) -> bytes:
    return c_string(os.fsdecode(os.fspath(path)), "path")


def seal(
    plaintext: BytesLike, passphrase: BytesLike, cipher: int = CipherSuite.CHACHA20_POLY1305
) -> bytes:
    """Encrypt ``plaintext`` under ``passphrase`` (Argon2id + AEAD) and return the vault bytes.

    ``plaintext`` and ``passphrase`` may be SecureBuffer, bytes, bytearray,
    memoryview or str; a SecureBuffer is read in place without a python copy.
    """
    lib = load_library()
    cipher_id = _cipher_id(cipher)
    out_ptr = _ffi.BytePtr()
    out_len = ctypes.c_size_t(0)
    with _borrow(plaintext, "plaintext") as (plain_ptr, plain_len), _borrow(
        passphrase, "passphrase"
    ) as (pass_ptr, pass_len):
        check(
            lib.lsec_vault_seal(
                plain_ptr,
                plain_len,
                pass_ptr,
                pass_len,
                cipher_id,
                ctypes.byref(out_ptr),
                ctypes.byref(out_len),
            )
        )
    try:
        return ctypes.string_at(out_ptr, out_len.value)
    finally:
        lib.lsec_vault_bytes_free(out_ptr, out_len.value)


def unseal(vault_bytes: BytesLike, passphrase: BytesLike) -> SecureBuffer:
    """Decrypt vault bytes produced by :func:`seal` into a :class:`SecureBuffer`."""
    lib = load_library()
    handle = _ffi.BufferHandle()
    with _borrow(vault_bytes, "vault_bytes") as (vault_ptr, vault_len), _borrow(
        passphrase, "passphrase"
    ) as (pass_ptr, pass_len):
        check(lib.lsec_vault_unseal(vault_ptr, vault_len, pass_ptr, pass_len, ctypes.byref(handle)))
    return SecureBuffer(handle)


def seal_to_file(
    path: StrPath,
    plaintext: BytesLike,
    passphrase: BytesLike,
    cipher: int = CipherSuite.CHACHA20_POLY1305,
) -> None:
    """Seal ``plaintext`` and write it atomically to ``path`` (0600 on posix)."""
    lib = load_library()
    encoded_path = _encode_path(path)
    cipher_id = _cipher_id(cipher)
    with _borrow(plaintext, "plaintext") as (plain_ptr, plain_len), _borrow(
        passphrase, "passphrase"
    ) as (pass_ptr, pass_len):
        check(
            lib.lsec_vault_seal_to_file(encoded_path, plain_ptr, plain_len, pass_ptr, pass_len, cipher_id)
        )


def unseal_from_file(path: StrPath, passphrase: BytesLike) -> SecureBuffer:
    """Read and decrypt the vault at ``path`` into a :class:`SecureBuffer`."""
    lib = load_library()
    encoded_path = _encode_path(path)
    handle = _ffi.BufferHandle()
    with _borrow(passphrase, "passphrase") as (pass_ptr, pass_len):
        check(lib.lsec_vault_unseal_from_file(encoded_path, pass_ptr, pass_len, ctypes.byref(handle)))
    return SecureBuffer(handle)
