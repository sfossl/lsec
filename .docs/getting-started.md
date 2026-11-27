[Docs Overview](../README.md#documentation) / Getting Started

# Getting Started

`lsec` is a defense-in-depth local security engine providing page-locked memory, anti-dump guarantees, envelope vault encryption and replay-resistant TOTP verification.

### Documentation Guides
[Getting Started](getting-started.md) | [Memory Guard](memguard.md) | [Vault](vault.md) | [TOTP](totp.md) | [C Integration](c-integration.md) | [Go Integration](go-integration.md) | [WebAssembly](wasm-integration.md) | [Python Integration](python-integration.md) | [API Reference](api-reference.md)

## Installation

### Rust Projects

Add `lsec-core` to `Cargo.toml`:

```toml
[dependencies]
lsec-core = "0.2.0"
```

### Go Projects

Import the Go binding module:

```bash
go get github.com/sfossl/lsec/bindings/go
```

Build or link against the `liblsec_ffi` shared library.

### JavaScript and WebAssembly Projects

Import the package and initialize the Wasm runtime:

```javascript
import { init, Buffer, Vault, TOTP } from '@sfossl/lsec';

// initialize with platform entropy
await init();
```

### Python Projects

Build the shared library and install the `ctypes` binding (no compiler or third-party packages needed):

```bash
cargo build -p lsec-ffi --release
pip install -e bindings/python
```

```python
import lsec

blob = lsec.seal(b"confidential-offline-records", b"user-strong-passphrase")
with lsec.unseal(blob, b"user-strong-passphrase") as secret:  # page-locked SecureBuffer
    ...

with lsec.Totp("JBSWY3DPEHPK3PXP") as otp:
    assert otp.verify(otp.now())
```

The library is located automatically in the cargo `target/` directory or on the system search path;
set `LSEC_LIB_PATH` to point at a specific copy. See [bindings/python/README.md](../bindings/python/README.md).

---

## Quickstart

### 1. Protecting Secrets in Memory

Allocate page-aligned memory pinned to physical RAM:

```rust
use lsec_core::memguard::ProtectedBuffer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = ProtectedBuffer::new(b"value")?;

    assert_eq!(&secret[..], b"value");

    // memory is wiped and unlocked automatically on drop
    Ok(())
}
```

### 2. Encrypted Vault Containers

Seal payloads using authenticated ChaCha20-Poly1305 and owner-only `0600` file permissions:

```rust
use lsec_core::config::SecurityConfig;
use lsec_core::vault::{seal_to_file, unseal_from_file, CipherSuite};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = "app_data.vault";
    let data = b"data";
    let passphrase = b"passphrase";
    let config = SecurityConfig::default();

    seal_to_file(path, data, passphrase, &config, CipherSuite::ChaCha20Poly1305)?;

    let unsealed = unseal_from_file(path, passphrase)?;
    assert_eq!(&unsealed[..], data);
    Ok(())
}
```

### 3. Time-Based Authentication (TOTP)

Decode Base32 secrets and calculate passcodes in constant time:

```rust
use lsec_core::config::SecurityConfig;
use lsec_core::totp::{decode_secret, generate_current, verify_code_current, TotpAlgorithm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seed_buffer = decode_secret("JBSWY3DPEHPK3PXP")?;
    let config = SecurityConfig::default();

    let code = generate_current(&seed_buffer, &config, TotpAlgorithm::Sha1)?;
    let is_valid = verify_code_current(&seed_buffer, &code, &config, TotpAlgorithm::Sha1)?;
    assert!(is_valid);
    Ok(())
}
```

---

## Configuration

Security parameter limits can be customized using `SecurityConfigBuilder`:

```rust
use lsec_core::config::SecurityConfig;

let custom_config = SecurityConfig::builder()
    .argon2_memory_kib(32 * 1024)
    .argon2_iterations(4)
    .argon2_parallelism(2)
    .totp_step_seconds(30)
    .totp_digits(6)
    .totp_drift_steps(1)
    .build();
```

---

## Connected Topics

| Context | Destination | Description |
| :--- | :--- | :--- |
| **Previous** | [Docs Overview](../README.md#documentation) | Root architecture and package matrix |
| **Next** | [Memory Guard](memguard.md) | Page-locked memory and zeroization deep dive |
| **API Reference** | [API Reference](api-reference.md) | Parameter limits, structs and C-ABI codes |
| **Integrations** | [Go Integration](go-integration.md) | Using lsec from Go via CGo |
| **Integrations** | [Python Integration](python-integration.md) | Using lsec from Python via ctypes |
