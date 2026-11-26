from __future__ import annotations

from typing import Union

from .errors import InvalidParameterError

U8_MAX = 0xFF
U32_MAX = 0xFFFFFFFF
U64_MAX = 0xFFFFFFFFFFFFFFFF


def uint(value: int, name: str, maximum: int, minimum: int = 0) -> int:
    """Validate that ``value`` is an int (not bool) within ``minimum..maximum``."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidParameterError(f"lsec: {name} must be an int")
    if not minimum <= value <= maximum:
        raise InvalidParameterError(f"lsec: {name} must be between {minimum} and {maximum}")
    return value


def c_string(value: Union[str, bytes], name: str) -> bytes:
    """Encode ``value`` for a NUL-terminated c argument, rejecting embedded NULs."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, bytes):
        raise TypeError(f"lsec: {name} must be str or bytes")
    if b"\x00" in value:
        raise InvalidParameterError(f"lsec: {name} must not contain NUL bytes")
    return value
