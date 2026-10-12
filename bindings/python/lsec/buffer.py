from __future__ import annotations

import contextlib
import ctypes
import sys
import threading
import weakref
from typing import Any, Iterator, Optional, Tuple, Union

from . import _ffi
from ._loader import load_library
from ._util import uint
from .errors import InvalidParameterError, check

BytesLike = Union["SecureBuffer", bytes, bytearray, memoryview, str]

# stands in for empty inputs so the c side always receives a non-null pointer
_EMPTY = (ctypes.c_uint8 * 1)()


def _empty_ptr() -> Any:
    return ctypes.cast(_EMPTY, _ffi.BytePtr)


@contextlib.contextmanager
def _borrow(data: BytesLike, name: str = "data") -> Iterator[Tuple[Any, int]]:
    """Yield ``(pointer, length)`` for ``data``, without copying where possible.

    Accepts SecureBuffer, bytes, bytearray, memoryview and str (utf-8 encoded).
    The pointer is only valid inside the ``with`` block; a SecureBuffer cannot be
    freed while it is borrowed.
    """
    if isinstance(data, SecureBuffer):
        with data._use() as handle:
            lib = load_library()
            length = lib.lsec_buffer_len(handle)
            if length == 0:
                yield _empty_ptr(), 0
            else:
                yield lib.lsec_buffer_data_mut(handle), length
        return

    if isinstance(data, str):
        data = data.encode("utf-8")

    if isinstance(data, bytes):
        if not data:
            yield _empty_ptr(), 0
            return
        raw = ctypes.c_char_p(data)
        yield ctypes.cast(raw, _ffi.BytePtr), len(data)
        return

    if isinstance(data, (bytearray, memoryview)):
        view = memoryview(data)
        if not view.contiguous:
            raise TypeError(f"lsec: {name} must be a contiguous buffer")
        view = view.cast("B")
        if view.nbytes == 0:
            yield _empty_ptr(), 0
            return
        if view.readonly:
            copy = bytes(view)
            raw = ctypes.c_char_p(copy)
            yield ctypes.cast(raw, _ffi.BytePtr), len(copy)
            return
        array = (ctypes.c_uint8 * view.nbytes).from_buffer(view)
        yield ctypes.cast(array, _ffi.BytePtr), view.nbytes
        return

    raise TypeError(
        f"lsec: {name} must be bytes, bytearray, memoryview, str or SecureBuffer, "
        f"not {type(data).__name__}"
    )


def _zero_source(data: object) -> None:
    if isinstance(data, (bytearray, memoryview)):
        view = memoryview(data)
        if not view.readonly and view.contiguous and view.nbytes:
            view = view.cast("B")
            array = (ctypes.c_uint8 * view.nbytes).from_buffer(view)
            ctypes.memset(array, 0, view.nbytes)
            del array


class SecureBuffer:
    """Secret bytes held in page-locked memory owned by lsec.

    The memory is pinned to physical ram, excluded from core dumps where the os
    supports it, and zeroized when wiped or freed. Use it as a context manager so
    the secret is released deterministically::

        with SecureBuffer.from_bytes(bytearray(b"key"), wipe_source=True) as key:
            ...

    The buffer is safe to share between threads: freeing waits for native calls
    that are still reading it.
    """

    __slots__ = ("_handle", "_cond", "_active", "_array_ref", "_pending_free", "__weakref__")

    def __init__(self, _handle: Any) -> None:
        if not _handle:
            raise InvalidParameterError("lsec: invalid protected buffer handle")
        self._handle = _handle
        self._cond = threading.Condition()
        self._active = 0
        self._array_ref: Optional[weakref.ref] = None
        self._pending_free: Optional[weakref.finalize] = None

    @classmethod
    def from_bytes(cls, data: BytesLike, *, wipe_source: bool = False) -> SecureBuffer:
        """Copy ``data`` into a new locked buffer.

        With ``wipe_source=True`` a mutable source (bytearray / writable memoryview)
        is zeroed after the copy, so the only live copy is the locked one.
        """
        lib = load_library()
        handle = _ffi.BufferHandle()
        with _borrow(data) as (ptr, length):
            check(lib.lsec_buffer_new(ptr, length, ctypes.byref(handle)))
        if wipe_source:
            _zero_source(data)
        return cls(handle)

    @classmethod
    def zeroed(cls, length: int) -> SecureBuffer:
        """Allocate a locked buffer of ``length`` zero bytes, to fill via :meth:`write` or :meth:`view`."""
        length = uint(length, "length", sys.maxsize)
        lib = load_library()
        handle = _ffi.BufferHandle()
        check(lib.lsec_buffer_zeroed(length, ctypes.byref(handle)))
        return cls(handle)

    @contextlib.contextmanager
    def _use(self) -> Iterator[Any]:
        with self._cond:
            if self._handle is None:
                raise ValueError("lsec: buffer has already been freed")
            self._active += 1
            handle = self._handle
        try:
            yield handle
        finally:
            with self._cond:
                self._active -= 1
                if self._active == 0:
                    self._cond.notify_all()

    @property
    def closed(self) -> bool:
        return self._handle is None

    def __len__(self) -> int:
        with self._use() as handle:
            return load_library().lsec_buffer_len(handle)

    def view(self) -> memoryview:
        """Zero-copy, writable memoryview onto the locked memory.

        If the buffer is freed while views (or slices of them) are still alive,
        the memory is wiped immediately and released once the last view is gone,
        so a stale view reads zeros instead of freed memory. Use ``with buf.view() as v:``
        to drop it promptly. Copying out of it (``bytes(view)``) creates ordinary
        python memory that lsec cannot wipe.
        """
        with self._use() as handle:
            lib = load_library()
            length = lib.lsec_buffer_len(handle)
            if length == 0:
                return memoryview(bytearray())
            array = self._array_ref() if self._array_ref is not None else None
            if array is None:
                address = ctypes.addressof(lib.lsec_buffer_data_mut(handle).contents)
                array = (ctypes.c_uint8 * length).from_address(address)
                self._array_ref = weakref.ref(array)
            return memoryview(array).cast("B")

    def write(self, data: BytesLike, offset: int = 0) -> None:
        """Copy ``data`` into the buffer starting at ``offset``."""
        lib = load_library()
        with self._use() as handle, _borrow(data) as (ptr, size):
            length = lib.lsec_buffer_len(handle)
            if offset < 0 or offset + size > length:
                raise InvalidParameterError(
                    f"lsec: write of {size} bytes at offset {offset} exceeds buffer of {length} bytes"
                )
            if size:
                dest = ctypes.addressof(lib.lsec_buffer_data_mut(handle).contents) + offset
                ctypes.memmove(dest, ptr, size)

    def to_bytes(self) -> bytes:
        """Return an ordinary ``bytes`` copy.

        The copy lives in normal python memory: it is not locked and cannot be
        wiped. Prefer :meth:`view` or passing the SecureBuffer straight into lsec calls.
        """
        with self._use() as handle:
            lib = load_library()
            length = lib.lsec_buffer_len(handle)
            if length == 0:
                return b""
            return ctypes.string_at(lib.lsec_buffer_data(handle), length)

    def wipe(self) -> None:
        """Zeroize the contents in place; the buffer stays allocated."""
        with self._use() as handle:
            check(load_library().lsec_buffer_wipe(handle))

    def free(self) -> None:
        """Zeroize, unlock and release the memory. Safe to call more than once.

        Waits for in-flight native calls on this buffer to finish first. If views
        are still alive the contents are wiped now and the memory is released
        when the last view is dropped.
        """
        with self._cond:
            handle, self._handle = self._handle, None
            if handle is None:
                return
            while self._active:
                self._cond.wait()
            array = self._array_ref() if self._array_ref is not None else None
            self._array_ref = None

        lib = load_library()
        if array is None:
            lib.lsec_buffer_free(handle)
            return
        lib.lsec_buffer_wipe(handle)
        self._pending_free = weakref.finalize(array, lib.lsec_buffer_free, handle)

    close = free

    def __enter__(self) -> SecureBuffer:
        if self.closed:
            raise ValueError("lsec: buffer has already been freed")
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.free()

    def __del__(self) -> None:
        try:
            self.free()
        except Exception:
            pass

    def __repr__(self) -> str:
        if self.closed:
            return "<SecureBuffer freed>"
        return f"<SecureBuffer len={len(self)}>"

    def __reduce__(self) -> Any:
        raise TypeError("lsec: SecureBuffer cannot be pickled")
