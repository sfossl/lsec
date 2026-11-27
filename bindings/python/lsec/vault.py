from __future__ import annotations

import contextlib
import ctypes
import enum
import os
from typing import Any, Iterator, Tuple, Union

from . import _ffi
from ._loader import load_library
from ._util import U8_MAX, c_string, uint
from .buffer import BytesLike, SecureBuffer, _borrow, _empty_ptr
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


def _take_bytes(lib: Any, out_ptr: Any, out_len: ctypes.c_size_t) -> bytes:
    try:
        return ctypes.string_at(out_ptr, out_len.value)
    finally:
        lib.lsec_vault_bytes_free(out_ptr, out_len.value)


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
    return _take_bytes(lib, out_ptr, out_len)


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


@contextlib.contextmanager
def _borrow_mut(data: Union[bytearray, memoryview], name: str = "container") -> Iterator[Tuple[Any, int]]:
    if not isinstance(data, (bytearray, memoryview)):
        raise TypeError(f"lsec: {name} must be a writable bytearray or memoryview, not {type(data).__name__}")
    view = memoryview(data)
    if view.readonly or not view.contiguous:
        raise TypeError(f"lsec: {name} must be a writable contiguous buffer")
    view = view.cast("B")
    if view.nbytes == 0:
        yield _empty_ptr(), 0
        return
    array = (ctypes.c_uint8 * view.nbytes).from_buffer(view)
    yield ctypes.cast(array, _ffi.BytePtr), view.nbytes


class MultiSlotVault:
    """Multi-slot encrypted vault supporting up to 4 independent passphrases."""

    @staticmethod
    def create(
        plaintext: BytesLike, passphrase: BytesLike, cipher: int = CipherSuite.CHACHA20_POLY1305
    ) -> bytes:
        lib = load_library()
        cipher_id = _cipher_id(cipher)
        out_ptr = _ffi.BytePtr()
        out_len = ctypes.c_size_t(0)
        with _borrow(plaintext, "plaintext") as (plain_ptr, plain_len), _borrow(
            passphrase, "passphrase"
        ) as (pass_ptr, pass_len):
            check(
                lib.lsec_multi_vault_create(
                    plain_ptr,
                    plain_len,
                    pass_ptr,
                    pass_len,
                    cipher_id,
                    ctypes.byref(out_ptr),
                    ctypes.byref(out_len),
                )
            )
        return _take_bytes(lib, out_ptr, out_len)

    @staticmethod
    def open(container: BytesLike, passphrase: BytesLike) -> SecureBuffer:
        lib = load_library()
        handle = _ffi.BufferHandle()
        with _borrow(container, "container") as (cont_ptr, cont_len), _borrow(
            passphrase, "passphrase"
        ) as (pass_ptr, pass_len):
            check(lib.lsec_multi_vault_open(cont_ptr, cont_len, pass_ptr, pass_len, ctypes.byref(handle)))
        return SecureBuffer(handle)

    @staticmethod
    def add_slot(
        container: Union[bytearray, memoryview],
        existing_passphrase: BytesLike,
        new_passphrase: BytesLike,
        cipher: int = CipherSuite.CHACHA20_POLY1305,
    ) -> int:
        lib = load_library()
        cipher_id = _cipher_id(cipher)
        slot_index = ctypes.c_size_t(0)
        with _borrow_mut(container) as (cont_ptr, cont_len), _borrow(
            existing_passphrase, "existing_passphrase"
        ) as (ex_ptr, ex_len), _borrow(new_passphrase, "new_passphrase") as (new_ptr, new_len):
            check(
                lib.lsec_multi_vault_add_slot(
                    cont_ptr,
                    cont_len,
                    ex_ptr,
                    ex_len,
                    new_ptr,
                    new_len,
                    cipher_id,
                    ctypes.byref(slot_index),
                )
            )
        return slot_index.value

    @staticmethod
    def remove_slot(
        container: Union[bytearray, memoryview], existing_passphrase: BytesLike, slot_index: int
    ) -> None:
        lib = load_library()
        slot_index = uint(slot_index, "slot_index", 3)
        with _borrow_mut(container) as (cont_ptr, cont_len), _borrow(
            existing_passphrase, "existing_passphrase"
        ) as (ex_ptr, ex_len):
            check(lib.lsec_multi_vault_remove_slot(cont_ptr, cont_len, ex_ptr, ex_len, slot_index))

    @staticmethod
    def update_payload(
        container: BytesLike, existing_passphrase: BytesLike, new_payload: BytesLike
    ) -> bytes:
        lib = load_library()
        out_ptr = _ffi.BytePtr()
        out_len = ctypes.c_size_t(0)
        with _borrow(container, "container") as (cont_ptr, cont_len), _borrow(
            existing_passphrase, "existing_passphrase"
        ) as (ex_ptr, ex_len), _borrow(new_payload, "new_payload") as (pay_ptr, pay_len):
            check(
                lib.lsec_multi_vault_update_payload(
                    cont_ptr,
                    cont_len,
                    ex_ptr,
                    ex_len,
                    pay_ptr,
                    pay_len,
                    ctypes.byref(out_ptr),
                    ctypes.byref(out_len),
                )
            )
        return _take_bytes(lib, out_ptr, out_len)

    @staticmethod
    def active_slots(container: BytesLike) -> Tuple[bool, bool, bool, bool]:
        lib = load_library()
        slots = (ctypes.c_uint8 * 4)()
        with _borrow(container, "container") as (cont_ptr, cont_len):
            check(lib.lsec_multi_vault_active_slots(cont_ptr, cont_len, slots, 4))
        return (bool(slots[0]), bool(slots[1]), bool(slots[2]), bool(slots[3]))
