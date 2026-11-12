[Docs Overview](../README.md#documentation) / Vault

# Vault

The `vault` module provides self-describing encrypted binary envelope containers and atomic filesystem storage with strict permissions.

### Documentation Guides
[Getting Started](getting-started.md) | [Memory Guard](memguard.md) | [Vault](vault.md) | [TOTP](totp.md) | [C Integration](c-integration.md) | [Go Integration](go-integration.md) | [WebAssembly](wasm-integration.md) | [API Reference](api-reference.md)

## Binary Envelope Format

Every sealed vault container begins with a self-describing 36-byte header:

| Offset | Size | Field | Description |
| :--- | :--- | :--- | :--- |
| `0..6` | 6 bytes | Magic Bytes | Constant identifier `LSEC\x01\x00` |
| `6..7` | 1 byte | Cipher ID | `0x01` (ChaCha20-Poly1305), `0x02` (AES-256-GCM) |
| `7..8` | 1 byte | KDF ID | `0x01` (Argon2id) |
| `8..12` | 4 bytes | KDF Memory | Memory cost in KiB (little-endian) |
| `12..16` | 4 bytes | KDF Iterations | Time cost passes (little-endian) |
| `16..20` | 4 bytes | KDF Lanes | Parallelism lane count (little-endian) |
| `20..32` | 12 bytes | Salt | CSPRNG salt material |
| `32..36` | 4 bytes | Header CRC32 | Little-endian checksum covering bytes `0..32` |
| `36..48` | 12 bytes | Nonce | AEAD nonce prefix |
| `48..` | N bytes | Ciphertext + Tag | Authenticated ciphertext and 16-byte Poly1305 / GCM tag |

## Atomic Filesystem Operations

When writing to disk, `seal_to_file` guarantees atomic replacement:
1. Writes payload to a temporary file (`<path>.tmp.<pid>`).
2. Enforces owner-only `0o600` permissions on POSIX filesystems.
3. Performs an atomic filesystem rename over the target path.
4. Cleans up temporary artifacts if any error occurs.

```rust
use lsec_core::config::SecurityConfig;
use lsec_core::vault::{seal_to_file, unseal_from_file, CipherSuite};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = "credentials.vault";
    let data = b"data";
    let passphrase = b"passphrase";
    let config = SecurityConfig::default();

    seal_to_file(path, data, passphrase, &config, CipherSuite::ChaCha20Poly1305)?;

    let unsealed = unseal_from_file(path, passphrase)?;
    assert_eq!(&unsealed[..], data);
    Ok(())
}
```

## Multi-Slot Container Architecture

`MultiSlotVault` separates payload encryption from credential derivation:
* **Data Encryption Key (DEK)**: A random 256-bit symmetric key encrypts the payload directly.
* **Key Slots**: 4 fixed 90-byte slots wrap the DEK under independent credentials and KDF configurations.
* **Instant Updates**: `update_payload` re-encrypts only the payload using the active DEK, executing in sub-millisecond latency without re-running Argon2id.
* **Credential Diversity**: Adding secondary passphrases or recovery keys operates without re-encrypting the underlying payload.

### Multi-Slot Header Layout

| Offset | Size | Field | Description |
| :--- | :--- | :--- | :--- |
| `0..6` | 6 bytes | Magic Header | Constant identifier `LSEC\x02\x00` |
| `6..7` | 1 byte | Payload Cipher | `0x01` (ChaCha20-Poly1305), `0x02` (AES-256-GCM) |
| `7..97` | 90 bytes | Slot 0 | Status, cipher, salt, Argon2 parameters and wrapped DEK |
| `97..187` | 90 bytes | Slot 1 | Status, cipher, salt, Argon2 parameters and wrapped DEK |
| `187..277` | 90 bytes | Slot 2 | Status, cipher, salt, Argon2 parameters and wrapped DEK |
| `277..367` | 90 bytes | Slot 3 | Status, cipher, salt, Argon2 parameters and wrapped DEK |
| `367..` | N bytes | Payload Ciphertext | Nonce, payload ciphertext and 16-byte authentication tag |

### Multi-Slot Usage

```rust
use lsec_core::config::SecurityConfig;
use lsec_core::vault::{CipherSuite, MultiSlotVault};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::default();
    let payload = b"payload data";

    // create container with slot 0
    let mut vault = MultiSlotVault::create(
        payload,
        b"primary-passphrase",
        CipherSuite::ChaCha20Poly1305,
        &config,
    )?;

    // add recovery credential to slot 1
    MultiSlotVault::add_slot(
        &mut vault,
        b"primary-passphrase",
        b"recovery-credential",
        &config,
        CipherSuite::ChaCha20Poly1305,
    )?;

    // fast update: zero argon2id recomputation
    MultiSlotVault::update_payload(
        &mut vault,
        b"primary-passphrase",
        b"updated payload data",
    )?;

    // open container with either credential
    let opened = MultiSlotVault::open(&vault, b"recovery-credential")?;
    assert_eq!(&opened[..], b"updated payload data");
    Ok(())
}
```

---

## Connected Topics

| Context | Destination | Description |
| :--- | :--- | :--- |
| **Previous** | [Memory Guard](memguard.md) | Physical RAM pinning and protected buffers |
| **Next** | [TOTP](totp.md) | Time-based authentication and Base32 decoding |
| **API Reference** | [API Reference: vault](api-reference.md#module-lsec-corevault) | Header structs, constants and error codes |
| **Integrations** | [WebAssembly](wasm-integration.md) | Decrypting vaults inside browsers and PWAs |
