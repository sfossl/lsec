# lsec for Python

Python binding for `lsec` over the `lsec_ffi` C-ABI, written with the standard library's `ctypes`.
No C compiler, no build step and no third-party dependencies are required, only the prebuilt
`lsec_ffi` shared library.

## Installation

Build the native library and install the package:

```bash
cargo build -p lsec-ffi --release
pip install -e bindings/python
```

### Library discovery

The first match wins:

| Order | Location | Notes |
| :--- | :--- | :--- |
| 1 | `LSEC_LIB_PATH` | Path to the library file or to a directory containing it. When set, it is the only location searched. |
| 2 | `lsec/_lib/` | Copy bundled inside the package (for wheels). |
| 3 | `$CARGO_TARGET_DIR`, `target/release`, `target/debug` | Searched in the enclosing cargo workspace, for in-tree and editable installs. |
| 4 | System loader | `ctypes.util.find_library("lsec_ffi")`, then `PATH` / `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH`. |

File names: `lsec_ffi.dll` / `liblsec_ffi.dll` (Windows), `liblsec_ffi.so` (Linux), `liblsec_ffi.dylib` (macOS).
If nothing loads, `LibraryNotFoundError` lists every path tried. `lsec.library_path()` reports the copy in use.

## Usage

### Protected buffers

```python
from lsec import SecureBuffer

key = bytearray(b"master-key-material")
with SecureBuffer.from_bytes(key, wipe_source=True) as buf:  # key is zeroed after the copy
    view = buf.view()        # zero-copy memoryview onto locked memory
    buf.wipe()               # zeroize in place
# freed: zeroized, unlocked and released
```

If views (or slices of them) are still alive when the buffer is freed, the memory is wiped immediately
and released once the last view is dropped, so a stale view reads zeros, never freed memory. Use
`with buf.view() as v:` to drop views promptly. `free()` also waits for native calls on the buffer
running in other threads.

`to_bytes()` returns an ordinary Python copy that cannot be wiped. Prefer `view()`, or pass the
`SecureBuffer` straight into vault and TOTP calls, which read it in place.

### Vault encryption

```python
import lsec
from lsec import CipherSuite

blob = lsec.seal(b"db-password", b"passphrase", CipherSuite.AES256_GCM)
with lsec.unseal(blob, b"passphrase") as secret:
    use(secret.view())

lsec.seal_to_file("app.vault", b"db-password", b"passphrase")
with lsec.unseal_from_file("app.vault", b"passphrase") as secret:
    ...
```

### TOTP (RFC 6238)

```python
from lsec import Totp, TotpAlgorithm, totp

with Totp("JBSWY3DPEHPK3PXP", digits=6, drift=1) as otp:
    code = otp.now()
    assert otp.verify(code)

seed = totp.decode_base32("JBSWY3DPEHPK3PXP")       # SecureBuffer
code = totp.generate(seed, timestamp=1234567890, algorithm=TotpAlgorithm.SHA256)
ok = totp.verify(seed, code, timestamp=1234567890, drift=1, algorithm=TotpAlgorithm.SHA256)
```

`digits` (default 6) must be 6-8 and is never inferred from the submitted code, so a shorter guess
cannot weaken an 8-digit check. `verify` returns `False` for a wrong code, including one of the wrong
length. Plain `bytes` passed to `generate`/`verify` are the raw seed. `Totp` takes a base32 `str`, or a
`SecureBuffer` holding the raw seed.

## Errors

Every negative status code from the C-ABI is raised as a subclass of `lsec.LsecError`, which carries `.code`:

| Code | Exception | Also a |
| :--- | :--- | :--- |
| -1 | `NullPointerError` | |
| -2 | `BufferTooSmallError` | |
| -3 | `InvalidParameterError` | `ValueError` |
| -4 | `AllocationError` | `MemoryError` |
| -5 | `MemoryLockError` | |
| -6 | `CryptoError` (wrong passphrase, tampered vault) | |
| -7 | `VaultCorruptError` | |
| -8 | `VaultIOError` | `OSError` |
| -9 | `TotpError` | |
| -10 | `PanicError` | |
| other | `UnknownError` | |

`LibraryNotFoundError` (also an `OSError`) is raised when the native library cannot be loaded.

## Tests

```bash
cd bindings/python
python -m unittest discover -s tests -t .
```

Tests that need the native library are skipped when it cannot be found. Set `LSEC_REQUIRE_LIB=1` (for
example in CI) to make a missing library a hard failure. The suite also runs under `pytest`.
