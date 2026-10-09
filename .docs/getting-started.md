# Getting Started with lsec

## Installation

### Rust Projects

Add `lsec-core` to `Cargo.toml`:

```toml
[dependencies]
lsec-core = { git = "https://github.com/sfossl/lsec", tag = "v0.1.0" }
```

### Go Projects

Import the Go binding module:

```bash
go get github.com/sfossl/lsec/bindings/go
```

Build or link against `liblsec_ffi` shared library.

### JavaScript and WebAssembly Projects

Import the package and initialize the wasm runtime:

```javascript
import { init, Buffer, Vault, TOTP } from './bindings/js/index.js';

// initialize with platform entropy
await init();
```

---

## Quick Starts

### 1. Protecting Secrets in Memory

```rust
use lsec_core::memguard::ProtectedBuffer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // allocate locked memory pinned to physical ram
    let secret = ProtectedBuffer::new(b"sensitive-secret-bytes")?;

    // access payload immutably
    assert_eq!(&secret[..], b"sensitive-secret-bytes");

    // memory is wiped and unlocked automatically on drop
    Ok(())
}
```

### 2. Encrypted Vault Containers

```rust
use lsec_core::config::SecurityConfig;
use lsec_core::vault::{seal_to_file, unseal_from_file, CipherSuite};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = "app_data.vault";
    let data = b"confidential-offline-records";
    let passphrase = b"user-strong-passphrase";
    let config = SecurityConfig::default();

    // seal payload with authenticated chacha20-poly1305 and 0600 file mode
    seal_to_file(path, data, passphrase, &config, CipherSuite::ChaCha20Poly1305)?;

    // decrypt directly into page-locked buffer
    let unsealed = unseal_from_file(path, passphrase)?;
    assert_eq!(&unsealed[..], data);

    Ok(())
}
```

### 3. Time-Based Authentication (TOTP)

```rust
use lsec_core::config::SecurityConfig;
use lsec_core::totp::{decode_secret, generate_current, verify_code_current, TotpAlgorithm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // decode base32 secret into protected memory
    let seed_buffer = decode_secret("JBSWY3DPEHPK3PXP")?;
    let config = SecurityConfig::default();

    // generate 6-digit code for current epoch window
    let code = generate_current(&seed_buffer, &config, TotpAlgorithm::Sha1)?;

    // verify in constant-time with drift tolerance
    let is_valid = verify_code_current(&seed_buffer, &code, &config, TotpAlgorithm::Sha1)?;
    assert!(is_valid);

    Ok(())
}
```

---

## Centralized Configuration Override

All default cryptographic and operational limits can be customized using `SecurityConfigBuilder`:

```rust
use lsec_core::config::SecurityConfig;

let custom_config = SecurityConfig::builder()
    .argon2_memory_kib(32 * 1024) // 32 MiB
    .argon2_iterations(4)
    .argon2_parallelism(2)
    .totp_step_seconds(30)
    .totp_digits(6)
    .totp_drift_steps(1)
    .build();
```
