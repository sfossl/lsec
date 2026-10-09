Hardened local security primitives providing page-locked memory, anti-dump guarantees, envelope vault encryption and replay-resistant TOTP across native desktop, CLI and offline PWA environments.

## 1. Architecture Overview

`lsec` is organized as a modular Rust workspace exposing C-ABI and WebAssembly boundaries for language independence:

- `crates/lsec-core`: Pure Rust cryptographic primitives, page-locked memory (`memguard`), Argon2id key derivation, ChaCha20-Poly1305 and AES-256-GCM envelope vaults and RFC 6238 TOTP verification.
- `crates/lsec-ffi`: C-ABI shared library (`liblsec_ffi`) and C99 header (`include/lsec.h`) for native integration.
- `crates/lsec-wasm`: Zero-dependency WebAssembly interface exposing linear memory management and host entropy hooks for browsers and PWAs.
- `bindings/go`: Idiomatic Go client using C-ABI bindings.
- `bindings/js`: Zero-dependency JavaScript and TypeScript SDK for Node.js, browsers and offline web apps.

## 2. Feature and Package Matrix

| Crate / Module | Responsibility | System Dependencies |
| :--- | :--- | :--- |
| `crates/lsec-core` | Core cryptographic and memory isolation logic | OS libc (POSIX) / Windows Memory API |
| `crates/lsec-ffi` | Standard C-ABI exports and `lsec.h` generator | `lsec-core` |
| `crates/lsec-wasm` | WebAssembly interface for browsers and PWAs | `lsec-core` (linear memory) |
| `bindings/go` | Idiomatic Go package via C-ABI | `liblsec_ffi` shared library |
| `bindings/js` | JavaScript and TypeScript SDK with type definitions | `lsec_wasm.wasm` WebAssembly binary |

## 3. Minimal Working Examples

### Memory Protection (Rust)

```rust
use lsec_core::memguard::ProtectedBuffer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret_data = b"master-passphrase-material";
    let mut protected = ProtectedBuffer::new(secret_data)?;

    // access payload via deref
    assert_eq!(&protected[..], secret_data);

    // explicit zeroization
    protected.wipe();

    // memory automatically zeroized and unlocked on drop
    drop(protected);
    Ok(())
}
```

### Encrypted Vault Storage (Rust)

```rust
use lsec_core::config::SecurityConfig;
use lsec_core::vault::{seal_to_file, unseal_from_file, CipherSuite};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = "credentials.vault";
    let payload = b"database-encryption-key-material";
    let passphrase = b"user-master-password";
    let config = SecurityConfig::default();

    // atomic write with 0600 permissions
    seal_to_file(vault_path, payload, passphrase, &config, CipherSuite::ChaCha20Poly1305)?;

    // decrypt directly into page-locked ram
    let unsealed = unseal_from_file(vault_path, passphrase)?;
    assert_eq!(&unsealed[..], payload);

    Ok(())
}
```

### Time-Based Authentication (Rust)

```rust
use lsec_core::config::SecurityConfig;
use lsec_core::totp::{generate_current, verify_code_current, TotpAlgorithm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seed = b"12345678901234567890";
    let config = SecurityConfig::default();

    let code = generate_current(seed, &config, TotpAlgorithm::Sha1)?;
    let is_valid = verify_code_current(seed, &code, &config, TotpAlgorithm::Sha1)?;
    assert!(is_valid);

    Ok(())
}
```

## 4. Security Guarantees and Explicit Non-Goals

### Guarantees

| Property | Implementation Mechanism |
| :--- | :--- |
| Memory Dump Exclusion | Linux `MADV_DONTDUMP` prevents secret buffers from appearing in core dumps. |
| Swap File Prevention | `mlock` (POSIX) and `VirtualLock` (Windows) pin secrets to physical RAM. |
| Page-Aligned Isolation | Dedicated OS page alignment prevents memory unlocking races between buffers. |
| Deterministic Zeroization | Volatile memory writes and compiler fences prevent dead store elimination. |
| Atomic File Writes | Temporary file swap prevents partial or corrupted vault writes. |
| Strict Access Controls | Enforced `0600` POSIX file permissions and `0700` directory permissions. |

### Explicit Non-Goals

- Remote Transport: `lsec` does not manage network transport, TLS, or remote session protocols (handled by upper-level network layers).
- Root/Kernel Compromise: If an attacker possesses kernel-level access or root privileges (`ptrace` with `CAP_SYS_PTRACE`), user-space defense cannot guarantee isolation.
- Process Supervision: `lsec` does not manage background services or process daemonization.

## 5. Performance and Allocation Profile

| Operation | Characteristic | Allocations |
| :--- | :--- | :--- |
| Page-Locked Buffer Alloc | Direct page-aligned allocation and memory lock | 1 OS page mapping |
| Buffer Zeroize + Release | Volatile zeroization and unlock on drop | 0 heap allocations |
| Argon2id Key Derivation | Calibrated memory and time passes | Bounded KDF buffer |
| TOTP Code Generation | Stack-allocated HMAC and constant-time modular reduction | 0 heap allocations |
