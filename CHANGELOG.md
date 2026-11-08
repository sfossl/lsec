# Changelog

## v0.1.0 - (2026-11-08)

- Core cryptographic engine in Rust (`crates/lsec-core`) with memory protection (`MemGuard`), zeroization and mlock protection.
- Secure local vault storage using ChaCha20-Poly1305 authenticated encryption and Argon2id key derivation.
- RFC 6238 compliant TOTP engine with configurable time steps, digit lengths and SHA digest algorithms.
- C-ABI dynamic library interface (`crates/lsec-ffi`) with native headers (`lsec.h`) for low-level systems integration.
- Standalone WebAssembly engine (`crates/lsec-wasm`) for browser and edge runtime execution.
- Idiomatic Go SDK bindings (`bindings/go`) with pure Cgo wrappers for backend integration.
- Modular TypeScript and Node.js SDK (`bindings/js`) published as `@sfossl/lsec` on npm.
- Comprehensive technical documentation and integration guides in `.docs/`.
