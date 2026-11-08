[Docs Overview](../README.md#documentation) / TOTP

# TOTP

The `totp` module implements RFC 6238 time-based authentication and strict RFC 4648 Base32 secret decoding.

### Documentation Guides
[Getting Started](getting-started.md) | [Memory Guard](memguard.md) | [Vault](vault.md) | [TOTP](totp.md) | [C Integration](c-integration.md) | [Go Integration](go-integration.md) | [WebAssembly](wasm-integration.md) | [API Reference](api-reference.md)

## Algorithms & Features

- **Supported Hashes**: HMAC-SHA1 (RFC standard default), HMAC-SHA256 and HMAC-SHA512.
- **Strict Base32 Decoding**: Rejects non-zero residual padding bits per RFC 4648 Section 3.5, preventing token-aliasing attacks.
- **Constant-Time Verification**: Verifies candidate passcodes using constant-time string comparisons to prevent timing side-channels.
- **Drift Tolerance**: Configurable time-step window tolerance (+/- N steps).

## Minimal Working Example

```rust
use lsec_core::config::SecurityConfig;
use lsec_core::totp::{decode_secret, generate_current, verify_code_current, TotpAlgorithm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // decode secret into buffer
    let secret_buffer = decode_secret("JBSWY3DPEHPK3PXP")?;
    let config = SecurityConfig::default();

    // generate current code
    let code = generate_current(&secret_buffer, &config, TotpAlgorithm::Sha1)?;
    println!("code: {}", code);

    // verify code in constant time
    let is_valid = verify_code_current(&secret_buffer, &code, &config, TotpAlgorithm::Sha1)?;
    assert!(is_valid);
    Ok(())
}
```

---

## Connected Topics

| Context | Destination | Description |
| :--- | :--- | :--- |
| **Previous** | [Vault](vault.md) | Binary envelope containers and file storage |
| **Next** | [C Integration](c-integration.md) | Integrating lsec with C and C++ |
| **API Reference** | [API Reference: totp](api-reference.md#module-lsec-coretotp) | Function signatures and `TotpError` variants |
| **Integrations** | [Go Integration](go-integration.md) | Verifying TOTP codes in Go backends |
