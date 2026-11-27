[Docs Overview](../README.md#documentation) / Python Integration

# Python Integration

`bindings/python` provides a zero-dependency Python package over the `lsec-ffi` C-ABI using standard-library `ctypes`.

### Documentation Guides
[Getting Started](getting-started.md) | [Memory Guard](memguard.md) | [Vault](vault.md) | [TOTP](totp.md) | [C Integration](c-integration.md) | [Go Integration](go-integration.md) | [WebAssembly](wasm-integration.md) | [Python Integration](python-integration.md) | [API Reference](api-reference.md)

## Installation

Build the native shared library and install the package:

```bash
cargo build --release -p lsec-ffi
pip install -e bindings/python
```

## Library Discovery

The loader searches locations in order and stops at the first match:

| Order | Location | Notes |
| :--- | :--- | :--- |
| 1 | `LSEC_LIB_PATH` | File or directory path. Exclusive when set. |
| 2 | `lsec/_lib/` | Bundled shared library inside wheel distributions. |
| 3 | `$CARGO_TARGET_DIR`, `target/release`, `target/debug` | Used only when running from the repository checkout. |
| 4 | System loader | `ctypes.util.find_library("lsec_ffi")`, then `PATH`, `LD_LIBRARY_PATH`, or `DYLD_LIBRARY_PATH`. |

## Lifecycle and Memory Safety

- **Deterministic cleanup**: Wrap `SecureBuffer` and `Totp` instances in `with` statements, or call `free()` / `close()` explicitly, rather than relying on garbage collection.
- **View deferral**: `buf.view()` exposes a zero-copy `memoryview` onto locked pages. Calling `free()` while a view or native call is active zeroises the contents immediately and defers unmapping until the last reference is released.
- **Mutable containers**: `MultiSlotVault.add_slot` and `MultiSlotVault.remove_slot` mutate containers in place and require a writable `bytearray` or contiguous `memoryview`. `MultiSlotVault.update_payload` returns a new `bytes` container.

## Minimal Working Example

```python
import lsec
from lsec import CipherSuite

lsec.harden_process()

sealed = lsec.seal(b"data", b"passphrase", CipherSuite.CHACHA20_POLY1305)
with lsec.unseal(sealed, b"passphrase") as buf:
    print(f"unsealed {len(buf)} bytes")
```

---

## Connected Topics

| Context | Destination | Description |
| :--- | :--- | :--- |
| **Previous** | [WebAssembly](wasm-integration.md) | Node.js and browser WebAssembly SDK |
| **Next** | [API Reference](api-reference.md) | Complete signatures, constants and error codes |
| **API Reference** | [API Reference: Python Bindings](api-reference.md#module-bindingspython-lsec-package) | Python classes, methods and exceptions |
| **Source Code** | [`__init__.py`](../bindings/python/lsec/__init__.py) | `ctypes` wrapper implementation |
