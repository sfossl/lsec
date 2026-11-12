# Changelog

## [0.2.0] - Unreleased

### Added

- Multi-slot vault container architecture (`MultiSlotVault` in `lsec-core::vault`) with independent DEK unwrapping, fixed 4-slot array and sub-millisecond payload updates.
- Transparent backward compatibility in `unseal()` supporting both single-envelope (`v0.1`) and multi-slot (`v0.2`) containers.
- Multi-slot error variants in `VaultError` (`NoMatchingSlot`, `AllSlotsOccupied`, `SlotIndexOutOfBounds`, `CannotRemoveLastSlot`, `SlotNotActive`).
- Stack-allocated zeroizing memory type `ProtectedArray<const N: usize>` in `lsec-core::memguard`.
- `MemguardError::LengthMismatch` variant for fixed-size slice validation.

## [0.1.0] - (2026-11-08)

- Core cryptographic engine in Rust (`crates/lsec-core`) with memory protection (`MemGuard`), zeroization and mlock protection.
- Secure local vault storage using ChaCha20-Poly1305 authenticated encryption and Argon2id key derivation.
- RFC 6238 compliant TOTP engine with configurable time steps, digit lengths and SHA digest algorithms.
- C-ABI dynamic library interface (`crates/lsec-ffi`) with native headers (`lsec.h`) for low-level systems integration.
- Standalone WebAssembly engine (`crates/lsec-wasm`) for browser and edge runtime execution.
- Idiomatic Go SDK bindings (`bindings/go`) with pure Cgo wrappers for backend integration.
- Modular TypeScript and Node.js SDK (`bindings/js`) published as `@sfossl/lsec` on npm.
- Comprehensive technical documentation and integration guides in `.docs/`.
