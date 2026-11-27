## Overview

`bindings/python` provides a zero-dependency Python binding for the `lsec` local security engine over the `lsec_ffi` C-ABI using the standard library `ctypes` module. It exposes page-locked memory buffers, process dump suppression, envelope and multi-slot vault encryption, and RFC 6238 TOTP verification without a C compiler or third-party packages.

## Installation

Build the native shared library and install the Python package:

```bash
cargo build --release -p lsec-ffi
pip install -e bindings/python
```

## Prerequisites

The package loads `liblsec_ffi` at runtime (`liblsec_ffi.so` on Linux, `liblsec_ffi.dylib` on macOS, `lsec_ffi.dll` or `liblsec_ffi.dll` on Windows).

### Library Discovery

The loader selects the first match in order:

| Order | Location | Notes |
| :--- | :--- | :--- |
| 1 | `LSEC_LIB_PATH` | Path to the library file or its parent directory. Exclusive when set. |
| 2 | `lsec/_lib/` | Shared library bundled inside a wheel distribution. |
| 3 | `$CARGO_TARGET_DIR`, `target/release`, `target/debug` | Searched only when running from the repository checkout (`bindings/python/lsec`). Relative `CARGO_TARGET_DIR` resolves from the working directory. |
| 4 | System loader | `ctypes.util.find_library("lsec_ffi")`, then `PATH`, `LD_LIBRARY_PATH`, or `DYLD_LIBRARY_PATH`. |

If no library loads, `LibraryNotFoundError` lists every path tried. Call `lsec.library_path()` to inspect the active library path.

### Environment Variables

| Variable | Purpose | Scope |
| :--- | :--- | :--- |
| `LSEC_LIB_PATH` | Override shared library file or directory path | Runtime and tests |
| `CARGO_TARGET_DIR` | Custom Cargo target directory in checkout mode | Runtime and tests |
| `LSEC_REQUIRE_LIB` | Set to `1` to fail instead of skipping tests when library is missing | Test suite |

## Usage

### Protected Buffers

```python
from lsec import SecureBuffer

key = bytearray(b"master-key-material")
with SecureBuffer.from_bytes(key, wipe_source=True) as buf:
    with buf.view() as view:
        length = len(view)
    buf.wipe()
```

### Vault Encryption

```python
import lsec
from lsec import CipherSuite

blob = lsec.seal(b"db-password", b"passphrase", CipherSuite.AES256_GCM)
with lsec.unseal(blob, b"passphrase") as secret:
    with secret.view() as view:
        length = len(view)

lsec.seal_to_file("app.vault", b"db-password", b"passphrase")
with lsec.unseal_from_file("app.vault", b"passphrase") as secret:
    data = secret.to_bytes()
```

### Multi-Slot Vault and Process Hardening

```python
import lsec
from lsec import MultiSlotVault

lsec.harden_process()

container = bytearray(MultiSlotVault.create(b"payload", b"primary-pass"))
slot = MultiSlotVault.add_slot(container, b"primary-pass", b"recovery-pass")  # container must be bytearray
with MultiSlotVault.open(container, b"recovery-pass") as secret:
    length = len(secret)
MultiSlotVault.remove_slot(container, b"primary-pass", slot)  # container must be bytearray
```

### TOTP

```python
from lsec import Totp, TotpAlgorithm, totp

with Totp("JBSWY3DPEHPK3PXP", digits=6, drift=1) as otp:
    code = otp.now()
    assert otp.verify(code)

with totp.decode_base32("JBSWY3DPEHPK3PXP") as seed:
    code = totp.generate(seed, timestamp=1234567890, algorithm=TotpAlgorithm.SHA256)
    ok = totp.verify(seed, code, timestamp=1234567890, drift=1, algorithm=TotpAlgorithm.SHA256)
```

`digits` (default `6`) must be between `6` and `8` and is never inferred from the submitted code. `verify` returns `False` for any non-matching code, including wrong-length inputs. Raw `bytes` passed to `generate` or `verify` are treated as the raw seed; `Totp` accepts a Base32 `str` or a `SecureBuffer`.

## Memory Management

* **Context managers**: Use `with` blocks on `SecureBuffer` and `Totp` instances to zeroise, unlock, and release native memory deterministically.
* **Zero-copy views**: `buf.view()` returns a writable `memoryview` onto locked memory. If views or in-flight native calls are still active when `free()` or `close()` runs, the memory is zeroised immediately and unmapped once the last reference drops.
* **Plain copies**: `to_bytes()` allocates an unlocked Python `bytes` object that cannot be wiped. Prefer `view()` or pass `SecureBuffer` directly into vault and TOTP functions.

## Errors

Negative C-ABI status codes map to subclasses of `lsec.LsecError`, which exposes `.code`:

| Code | Exception | Base Class | Notes |
| :--- | :--- | :--- | :--- |
| `-1` | `NullPointerError` | `LsecError` | Null pointer passed to native call |
| `-2` | `BufferTooSmallError` | `LsecError` | Destination buffer too small |
| `-3` | `InvalidParameterError` | `LsecError`, `ValueError` | Invalid argument or out-of-range value |
| `-4` | `AllocationError` | `LsecError`, `MemoryError` | Memory allocation failure |
| `-5` | `MemoryLockError` | `LsecError` | OS memory lock failure (`mlock`/`VirtualLock`) |
| `-6` | `CryptoError` | `LsecError` | Authentication failure or wrong passphrase |
| `-7` | `VaultCorruptError` | `LsecError` | Malformed vault header or container |
| `-8` | `VaultIOError` | `LsecError`, `OSError` | Filesystem read or write failure |
| `-9` | `TotpError` | `LsecError` | Invalid Base32 seed or TOTP parameters |
| `-10` | `PanicError` | `LsecError` | Rust panic caught at FFI boundary |
| Other | `UnknownError` | `LsecError` | Unrecognised native status code |
| None | `LibraryNotFoundError` | `LsecError`, `OSError` | Native `liblsec_ffi` binary not found |

## Tests

```bash
cd bindings/python
python -m unittest discover -s tests -t .
```

Tests requiring the native library are skipped when it is absent unless `LSEC_REQUIRE_LIB=1` is set. The suite also runs under `pytest`.

## Connected Topics

| Topic | Relationship | Context |
| :--- | :--- | :--- |
| [C-ABI Shared Library](https://github.com/sfossl/lsec/tree/main/crates/lsec-ffi) | Native Dependency | C header and shared library compiled from Rust |
| [Python Integration Guide](https://github.com/sfossl/lsec/blob/main/.docs/python-integration.md) | Dedicated Documentation | Library discovery, view deferral and buffer safety |
| [API Reference](https://github.com/sfossl/lsec/blob/main/.docs/api-reference.md) | Function Index | Full API specification across all runtimes |
| [Repository Overview](https://github.com/sfossl/lsec) | Workspace Root | Architecture and multi-target ecosystem matrix |
