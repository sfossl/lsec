from __future__ import annotations

import ctypes
import enum
import time
from typing import Optional, Union

from . import _ffi
from ._loader import load_library
from ._util import U8_MAX, U64_MAX, c_string, uint
from .buffer import BytesLike, SecureBuffer, _borrow
from .errors import InvalidParameterError, TotpError, check

DEFAULT_STEP_SECONDS = 30
DEFAULT_DIGITS = 6
DEFAULT_DRIFT_STEPS = 1

# mirrors MIN_TOTP_DIGITS / MAX_TOTP_DIGITS in lsec-core config.rs
MIN_DIGITS = 6
MAX_DIGITS = 8


class TotpAlgorithm(enum.IntEnum):
    SHA1 = _ffi.LSEC_TOTP_ALGO_SHA1
    SHA256 = _ffi.LSEC_TOTP_ALGO_SHA256
    SHA512 = _ffi.LSEC_TOTP_ALGO_SHA512


def _timestamp(timestamp: Optional[int]) -> int:
    if timestamp is None:
        return int(time.time())
    return uint(timestamp, "timestamp", U64_MAX)


def _digits(digits: int) -> int:
    if isinstance(digits, bool) or not isinstance(digits, int):
        raise InvalidParameterError("lsec: digits must be an int")
    if not MIN_DIGITS <= digits <= MAX_DIGITS:
        raise TotpError(f"lsec: digits must be between {MIN_DIGITS} and {MAX_DIGITS}, got {digits}")
    return digits


def _algorithm(algorithm: int) -> int:
    return uint(int(algorithm), "algorithm", U8_MAX)


def decode_base32(encoded: Union[str, bytes]) -> SecureBuffer:
    """Decode an RFC 4648 base32 TOTP seed straight into locked memory.

    Spaces, hyphens and ``=`` padding are ignored; case-insensitive.
    """
    lib = load_library()
    handle = _ffi.BufferHandle()
    check(lib.lsec_totp_decode_base32(c_string(encoded, "encoded"), ctypes.byref(handle)))
    return SecureBuffer(handle)


def generate(
    secret: BytesLike,
    *,
    timestamp: Optional[int] = None,
    step: int = DEFAULT_STEP_SECONDS,
    digits: int = DEFAULT_DIGITS,
    algorithm: int = TotpAlgorithm.SHA1,
) -> str:
    """Return the RFC 6238 code for the raw ``secret`` bytes at ``timestamp`` (default: now)."""
    lib = load_library()
    timestamp = _timestamp(timestamp)
    step = uint(step, "step", U64_MAX)
    digits = _digits(digits)
    algorithm = _algorithm(algorithm)

    out = ctypes.create_string_buffer(digits + 1)
    with _borrow(secret, "secret") as (sec_ptr, sec_len):
        check(lib.lsec_totp_generate(sec_ptr, sec_len, timestamp, step, digits, algorithm, out, len(out)))
    return out.value.decode("ascii")


def verify(
    secret: BytesLike,
    code: Union[str, bytes],
    *,
    timestamp: Optional[int] = None,
    step: int = DEFAULT_STEP_SECONDS,
    digits: int = DEFAULT_DIGITS,
    drift: int = DEFAULT_DRIFT_STEPS,
    algorithm: int = TotpAlgorithm.SHA1,
) -> bool:
    """Check ``code`` against the raw ``secret`` within ``drift`` steps either side of ``timestamp``.

    ``digits`` is the length the deployment expects and is never inferred from
    ``code``, so a shorter guess cannot weaken the check. A code of the wrong
    length simply fails. Comparison is constant-time.
    """
    lib = load_library()
    code_bytes = c_string(code, "code")
    timestamp = _timestamp(timestamp)
    step = uint(step, "step", U64_MAX)
    digits = _digits(digits)
    drift = uint(drift, "drift", U8_MAX)
    algorithm = _algorithm(algorithm)

    is_valid = ctypes.c_int32(0)
    with _borrow(secret, "secret") as (sec_ptr, sec_len):
        check(
            lib.lsec_totp_verify(
                sec_ptr,
                sec_len,
                code_bytes,
                timestamp,
                step,
                digits,
                drift,
                algorithm,
                ctypes.byref(is_valid),
            )
        )
    return is_valid.value == 1


class Totp:
    """A TOTP seed kept in locked memory, with its generation parameters.

    ``secret`` is a base32 string (as shown in authenticator QR codes) or a
    SecureBuffer holding the raw seed bytes::

        with Totp("JBSWY3DPEHPK3PXP") as otp:
            code = otp.now()
            assert otp.verify(code)
    """

    def __init__(
        self,
        secret: Union[str, SecureBuffer],
        *,
        step: int = DEFAULT_STEP_SECONDS,
        digits: int = DEFAULT_DIGITS,
        drift: int = DEFAULT_DRIFT_STEPS,
        algorithm: int = TotpAlgorithm.SHA1,
    ) -> None:
        if isinstance(secret, str):
            self._secret = decode_base32(secret)
        elif isinstance(secret, SecureBuffer):
            self._secret = secret
        else:
            raise TypeError(
                "lsec: secret must be a base32 str or a SecureBuffer; "
                "wrap raw seed bytes with SecureBuffer.from_bytes()"
            )
        self.step = step
        self.digits = _digits(digits)
        self.drift = drift
        self.algorithm = TotpAlgorithm(algorithm)

    def at(self, timestamp: Optional[int]) -> str:
        return generate(
            self._secret, timestamp=timestamp, step=self.step, digits=self.digits, algorithm=self.algorithm
        )

    def now(self) -> str:
        return self.at(None)

    def verify(self, code: Union[str, bytes], timestamp: Optional[int] = None) -> bool:
        return verify(
            self._secret,
            code,
            timestamp=timestamp,
            step=self.step,
            digits=self.digits,
            drift=self.drift,
            algorithm=self.algorithm,
        )

    def close(self) -> None:
        self._secret.free()

    def __enter__(self) -> Totp:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<Totp digits={self.digits} step={self.step} algorithm={self.algorithm.name}>"
