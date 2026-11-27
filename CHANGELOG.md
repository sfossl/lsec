# Changelog

## [v0.3.0] - 2026-11-27

### Added

- Zero-dependency Python bindings (`bindings/python`) over `lsec_ffi` `ctypes`, exposing `SecureBuffer`, `seal`/`unseal`, `seal_to_file`/`unseal_from_file`, `MultiSlotVault`, `harden_process()`, and `Totp`.
- Dedicated Python integration guide (`.docs/python-integration.md`) and updated binding documentation.
- `Buffer.Write()` method in `bindings/go` exposing `lsec_buffer_data_mut`.
- Python test execution in CI (on `main` and `dev`) and multi-platform PyPI wheel release workflow (`.github/workflows/release-python.yml`).

### Updated

- Package versions and exported native version functions aligned to `0.3.0` across Rust workspace crates, `lsec-ffi`, `lsec-wasm`, `@sfossl/lsec`, `bindings/go`, and `bindings/python`.
- `bindings/js` now caches concurrent `init()` calls, rejects invalid cipher or TOTP algorithm values, enforces `Uint8Array` containers for in-place `MultiSlotVault` mutations, and reports descriptive TOTP error messages.
- Documentation aligned to British English and third-person imperative register across `README.md`, `.docs/`, and binding READMEs.

### Fixed

- Plaintext heap zeroisation on `ProtectedBuffer::new` failure in `lsec-core` AEAD decryption, Base32 secret zeroisation on decode errors, empty Base32 output rejection, and stack DEK zeroisation in `MultiSlotVault`.
- TOTP timestamp/step overflow and `InvalidDigits` error propagation in `verify_code_at`, KDF parameter bounds validation in `MultiSlotVault::write_slot`, and truncated multi-slot error reporting in `unseal`.
- Panic safety (`catch_unwind`) on `lsec-ffi` and `lsec-wasm` accessor/allocator exports, `lsec_totp_generate` capacity overflow check, and uniform Wasm allocator `Layout` alignment.
- Thread-safe `Buffer` mutex locking and `C.int` bounds checks in `bindings/go`, plus empty-slice/empty-buffer handling across Go and JS bindings and Wasm secret wiping via `lsec_wasm_wipe_and_free`.

## [0.2.0] - (2026-11-12)

### Added

- Opt-in process-level hardening module (`lsec-core::process`) providing `harden_process()`, `disable_dumpable()` and `deny_debugger()`.
- C-ABI exported function `lsec_process_harden()` in `lsec-ffi` and `ProcessHarden()` in `bindings/go`.
- Multi-slot vault container architecture (`MultiSlotVault` in `lsec-core::vault`) with independent DEK unwrapping, fixed 4-slot array and sub-millisecond payload updates.
- C-ABI functions for multi-slot vault management in `lsec-ffi` (`lsec_multi_vault_*`).
- WebAssembly multi-slot container exports in `lsec-wasm` (`lsec_wasm_multi_vault_*`).
- Idiomatic Go SDK functions for multi-slot vaults (`MultiVaultCreate`, `MultiVaultOpen`, `MultiVaultAddSlot`, `MultiVaultRemoveSlot`, `MultiVaultUpdatePayload`, `MultiVaultActiveSlots`).
- JavaScript/TypeScript `MultiSlotVault` class with full browser, Node.js and offline runtime support.
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
