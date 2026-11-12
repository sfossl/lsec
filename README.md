## Overview

`lsec` is a defense-in-depth local security engine providing page-locked memory, stack-allocated zeroizing arrays, process dump suppression, multi-slot envelope vault encryption and replay-resistant TOTP verification.

Most software relies on default heap memory and unauthenticated local file storage. This leaves sensitive material vulnerable to memory swapping, crash dumps and unauthenticated file tampering. `lsec` provides low-level memory isolation and cryptographic storage primitives to protect credentials, keys and tokens throughout their local lifecycle across desktop, CLI and offline WebAssembly environments.

## Installation

### Rust

Add `lsec-core` to `Cargo.toml`:

```toml
[dependencies]
lsec-core = "0.2.0"
```

### Go

Install the Go binding module:

```bash
go get github.com/sfossl/lsec/bindings/go
```

Build or link against the `liblsec_ffi` shared library.

### JavaScript and WebAssembly

Install the client package:

```bash
npm install @sfossl/lsec
```

## Architecture

`lsec` is organized as a modular Rust workspace exposing C-ABI and WebAssembly boundaries for native and web runtimes.

### Package Matrix

| Package / Module | Role | Dependencies |
| :--- | :--- | :--- |
| `crates/lsec-core` | Memory locking, Argon2id, AEAD ciphers and TOTP | libc (POSIX) / Windows Memory API |
| `crates/lsec-ffi` | Standard C99 symbols (`lsec.h`) and shared library | `lsec-core` |
| `crates/lsec-wasm` | WebAssembly interface for browsers and PWAs | `lsec-core` |
| `bindings/go` | Idiomatic Go client with garbage-collector-safe handles | `liblsec_ffi` |
| `bindings/js` | ESM TypeScript and JavaScript SDK | `lsec_wasm.wasm` |

## Capabilities

| Capability | Module | Mechanism |
| :--- | :--- | :--- |
| Memory Guard | `memguard` | OS page alignment, RAM pinning (`mlock`/`VirtualLock`), `ProtectedArray<N>` stack zeroization and `MADV_DONTDUMP`. |
| Multi-Slot Vault | `vault` | LUKS-style 4-slot container separating DEK from KEKs, sub-millisecond fast updates and multi-credential unlock. |
| Envelope Vault | `vault` | Argon2id key derivation, ChaCha20-Poly1305 / AES-256-GCM AEAD, binary headers and atomic file replace. |
| Process Hardening | `process` | OS-level anti-dump guarantees (`PR_SET_DUMPABLE`), error box suppression and anti-debugging controls. |
| Two-Factor Auth | `totp` | RFC 6238 time-step calculation, RFC 4648 strict Base32 decoding and constant-time drift verification. |

### Usage Examples

#### Stack-Allocated Memory Array (Rust)

```rust
use lsec_core::memguard::ProtectedArray;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 32-byte key buffer on stack with zero heap allocation
    let mut key = ProtectedArray::<32>::new([0x42; 32]);
    assert_eq!(key.len(), 32);

    // drops with volatile memory wipe and compiler fence
    Ok(())
}
```

#### Multi-Slot Vault Storage (Rust)

```rust
use lsec_core::config::SecurityConfig;
use lsec_core::vault::{CipherSuite, MultiSlotVault};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::default();
    let payload = b"secret credentials";

    // create multi-slot vault with master password
    let mut vault = MultiSlotVault::create(
        payload,
        b"master-passphrase",
        CipherSuite::ChaCha20Poly1305,
        &config,
    )?;

    // add secondary recovery key without re-encrypting payload
    MultiSlotVault::add_slot(
        &mut vault,
        b"master-passphrase",
        b"recovery-key",
        &config,
        CipherSuite::Aes256Gcm,
    )?;

    // re-encrypts payload in <0.1ms with zero Argon2id recomputation
    MultiSlotVault::update_payload(&mut vault, b"recovery-key", b"updated secret credentials")?;

    let opened = MultiSlotVault::open(&vault, b"master-passphrase")?;
    assert_eq!(&opened[..], b"updated secret credentials");
    Ok(())
}
```

#### Page-Locked Memory Buffer (Rust)

```rust
use lsec_core::memguard::ProtectedBuffer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = b"value";
    let mut buffer = ProtectedBuffer::new(data)?;

    assert_eq!(&buffer[..], data);

    buffer.wipe();
    Ok(())
}
```

#### Envelope Vault Storage (Rust)

```rust
use lsec_core::config::SecurityConfig;
use lsec_core::vault::{seal_to_file, unseal_from_file, CipherSuite};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = "file.vault";
    let payload = b"data";
    let passphrase = b"passphrase";
    let config = SecurityConfig::default();

    seal_to_file(path, payload, passphrase, &config, CipherSuite::ChaCha20Poly1305)?;

    let unsealed = unseal_from_file(path, passphrase)?;
    assert_eq!(&unsealed[..], payload);
    Ok(())
}
```

#### Time-Based Authentication (Rust)

```rust
use lsec_core::config::SecurityConfig;
use lsec_core::totp::{generate_current, verify_code_current, TotpAlgorithm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = b"12345678901234567890";
    let config = SecurityConfig::default();

    let code = generate_current(secret, &config, TotpAlgorithm::Sha1)?;
    let is_valid = verify_code_current(secret, &code, &config, TotpAlgorithm::Sha1)?;
    assert!(is_valid);
    Ok(())
}
```

#### Envelope Vault (Go)

```go
package main

import (
	"bytes"
	"fmt"

	"github.com/sfossl/lsec/bindings/go"
)

func main() {
	payload := []byte("data")
	passphrase := []byte("passphrase")

	ciphertext, err := lsec.Seal(payload, passphrase, lsec.CipherChaCha20Poly1305)
	if err != nil {
		panic(err)
	}

	buf, err := lsec.Unseal(ciphertext, passphrase)
	if err != nil {
		panic(err)
	}
	defer buf.Free()

	if !bytes.Equal(buf.Bytes(), payload) {
		panic("mismatch")
	}
	fmt.Println("ok")
}
```

#### WebAssembly & Node.js (JavaScript)

```javascript
import { init, Vault } from '@sfossl/lsec';

await init();

const data = new TextEncoder().encode("data");
const passphrase = new TextEncoder().encode("passphrase");

const encrypted = Vault.seal(data, passphrase);
const decrypted = Vault.unseal(encrypted, passphrase);

console.log(decrypted.bytes);
decrypted.free();
```

## Ecosystem

The `lsec` project consists of the following official components:

- `lsec-core`: Pure Rust crate containing core cryptography and memory guard routines.
- `lsec-ffi`: C-ABI crate producing `liblsec_ffi` and `include/lsec.h`.
- `lsec-wasm`: WebAssembly compilation target.
- `bindings/go`: Go module wrapping the native C-ABI.
- `bindings/js`: Node.js and browser SDK loading the WebAssembly module.

## Properties

### Security Guarantees

| Property | Mechanism |
| :--- | :--- |
| Memory Dump Exclusion | Linux `MADV_DONTDUMP` excludes secret buffers from core dumps. |
| Swap File Prevention | `mlock` (POSIX) and `VirtualLock` (Windows) pin allocations to physical RAM. |
| Page-Aligned Isolation | Page-boundary alignment prevents cross-buffer unlocking races. |
| Deterministic Zeroization | Volatile writes and compiler fences prevent dead-store elimination on wipe. |
| Atomic File Writes | Temporary file swap ensures atomic replacement with `0600` permissions. |
| DoS Parameter Bounds | Hard upper bounds on Argon2id iterations, memory and lanes during envelope deserialization. |

### Performance Profile

| Operation | Characteristic | Allocations |
| :--- | :--- | :--- |
| Page-Locked Allocation | Direct page alignment and memory pin | 1 OS page mapping |
| Buffer Zeroization | Volatile memory wipe and unlock on drop | 0 heap allocations |
| Argon2id Key Derivation | Calibrated passes and memory lanes | Bounded KDF buffer |
| TOTP Code Generation | Stack-allocated HMAC and constant-time reduction | 0 heap allocations |

## Limitations

- **Container Memory Limits**: In unprivileged Docker containers or restricted environments, the operating system `RLIMIT_MEMLOCK` defaults to 64 KB. Calling `ProtectedBuffer::new` will fail unless granted `CAP_IPC_LOCK` or a higher memory lock limit (`ulimit -l`). For fixed-size keys and seeds, use `ProtectedArray<N>` instead to avoid OS page locking limits.
- **Single-Buffer Size Ceiling**: Memory buffers are bounded by `DEFAULT_MAX_LOCKED_MEMORY_BYTES` (16 MiB) to avoid exhausting physical host RAM. Large multi-gigabyte streams must be processed in chunks.
- **Not a Network Transport Protocol**: `lsec` does not manage TLS or transport encryption. Network data must be encrypted using standard network protocols.
- **Root and Kernel Boundaries**: User-space memory locking cannot protect secrets against attackers with root privileges or kernel-level memory access (`CAP_SYS_PTRACE`).

## Roadmap

- Streaming vault interface for files exceeding the 16 MiB single-buffer threshold.
- Dynamic page size queries via `GetSystemInfo` on Windows ARM64 platforms.
- Native Python and Swift bindings over the C-ABI.

## Documentation

| Guide | Description |
| :--- | :--- |
| [Getting Started](.docs/getting-started.md) | Package installation, quickstarts and configuration overrides |
| [Memory Guard](.docs/memguard.md) | Page-aligned memory, RAM pinning, anti-dump and deterministic zeroization |
| [Vault Storage](.docs/vault.md) | Binary envelope header format, Argon2id KDF bounds and atomic file replace |
| [TOTP Authentication](.docs/totp.md) | RFC 6238 counter logic, strict RFC 4648 Base32 padding and constant-time verification |
| [C Integration](.docs/c-integration.md) | Header exports, compiler flags and memory management rules |
| [Go Integration](.docs/go-integration.md) | CGo setup, runtime finalizers and pointer dereference safety |
| [WebAssembly Integration](.docs/wasm-integration.md) | Node.js loader, browser streaming instantiation and linear memory rules |
| [API Reference](.docs/api-reference.md) | Full specification of exported modules, constants, structs and C-ABI return codes |

## References

- [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238): TOTP: Time-Based One-Time Password Algorithm.
- [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648): The Base16, Base32 and Base64 Data Encodings.
- [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439): ChaCha20 and Poly1305 for IETF Protocols.
- [RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106): Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work.
