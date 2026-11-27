## Overview

`lsec-wasm` is the freestanding WebAssembly compilation target for the `lsec` defence-in-depth security engine. It exposes zero-dependency cryptographic operations, vault encryption and TOTP verification directly in linear WebAssembly memory for browser, progressive web app and edge runtime execution.

## Exported Functions

| Symbol | Signature | Role |
| :--- | :--- | :--- |
| `lsec_wasm_is_ready` | `() -> u32` | Returns readiness status |
| `lsec_wasm_version_major` | `() -> u32` | Returns major ABI version |
| `lsec_wasm_version_minor` | `() -> u32` | Returns minor ABI version |
| `lsec_wasm_version_patch` | `() -> u32` | Returns patch ABI version |
| `lsec_wasm_alloc` | `(size: usize) -> *mut u8` | Allocates memory in WebAssembly linear heap |
| `lsec_wasm_free` | `(ptr: *mut u8, size: usize)` | Deallocates memory in WebAssembly linear heap |
| `lsec_wasm_wipe_and_free` | `(ptr: *mut u8, size: usize)` | Zeroises and deallocates memory |
| `lsec_wasm_buffer_new` | `(data: *const u8, len: usize) -> *mut LsecWasmBuffer` | Creates a protected buffer handle |
| `lsec_wasm_buffer_free` | `(buf: *mut LsecWasmBuffer)` | Zeroises and frees a protected buffer handle |
| `lsec_wasm_buffer_len` | `(buf: *const LsecWasmBuffer) -> usize` | Returns protected buffer byte length |
| `lsec_wasm_buffer_data` | `(buf: *const LsecWasmBuffer) -> *const u8` | Returns pointer to protected buffer bytes |
| `lsec_wasm_buffer_wipe` | `(buf: *mut LsecWasmBuffer) -> i32` | Zeroises protected buffer contents in place |
| `lsec_wasm_vault_seal` | `(plaintext, plaintext_len, passphrase, passphrase_len, cipher_id, out_len) -> *mut u8` | Encrypts payload into serialised envelope |
| `lsec_wasm_vault_unseal` | `(vault_bytes, vault_len, passphrase, passphrase_len) -> *mut LsecWasmBuffer` | Authenticates and decrypts single or multi-slot envelope |
| `lsec_wasm_multi_vault_create` | `(plaintext, plaintext_len, passphrase, passphrase_len, cipher_id, out_len) -> *mut u8` | Creates multi-slot container with slot 0 |
| `lsec_wasm_multi_vault_open` | `(container, container_len, passphrase, passphrase_len) -> *mut LsecWasmBuffer` | Unwraps DEK and decrypts payload into memory |
| `lsec_wasm_multi_vault_add_slot` | `(container, container_len, existing_passphrase, existing_passphrase_len, new_passphrase, new_passphrase_len, new_cipher_id) -> i32` | Adds new credential slot to container |
| `lsec_wasm_multi_vault_remove_slot` | `(container, container_len, existing_passphrase, existing_passphrase_len, slot_index) -> i32` | Zeroises targeted slot |
| `lsec_wasm_multi_vault_update_payload` | `(container, container_len, existing_passphrase, existing_passphrase_len, new_payload, new_payload_len, out_len) -> *mut u8` | Updates payload reusing existing DEK |
| `lsec_wasm_multi_vault_active_slots` | `(container, container_len, out_slots) -> i32` | Reads active status for all 4 slots |
| `lsec_wasm_vault_bytes_free` | `(ptr: *mut u8, len: usize)` | Frees sealed vault byte allocations |
| `lsec_wasm_totp_decode_base32` | `(base32_ptr, base32_len) -> *mut LsecWasmBuffer` | Decodes Base32 secret into protected buffer |
| `lsec_wasm_totp_generate` | `(secret, secret_len, timestamp, step_seconds, digits, algorithm_id, out_code, out_code_capacity) -> i32` | Generates RFC 6238 token code |
| `lsec_wasm_totp_verify` | `(secret, secret_len, candidate, candidate_len, timestamp, step_seconds, digits, drift_steps, algorithm_id) -> i32` | Performs constant-time TOTP verification |

## Installation

Compile the crate to the freestanding `wasm32-unknown-unknown` target:

```bash
cargo build --release --target wasm32-unknown-unknown -p lsec-wasm
```

The compiled binary is placed at:
`target/wasm32-unknown-unknown/release/lsec_wasm.wasm`

## Client SDK

For Node.js, Deno, Bun and browser runtimes, use the high-level JavaScript and TypeScript SDK in `bindings/js` published as `@sfossl/lsec` on npm.

## Connected Topics

| Topic | Relationship | Context |
| :--- | :--- | :--- |
| [Core Engine](https://github.com/sfossl/lsec/tree/main/crates/lsec-core) | Underlying Rust Crate | Rust cryptographic and vault implementations |
| [JavaScript SDK](https://github.com/sfossl/lsec/tree/main/bindings/js) | TypeScript Wrapper | High-level client SDK for browser and Node.js |
| [WebAssembly Guide](https://github.com/sfossl/lsec/blob/main/.docs/wasm-integration.md) | Dedicated Documentation | Streaming instantiation and memory lifecycle |
| [API Reference](https://github.com/sfossl/lsec/blob/main/.docs/api-reference.md) | Function Index | Low-level WebAssembly memory and return codes |
| [Repository Overview](https://github.com/sfossl/lsec) | Workspace Root | Architecture and multi-target ecosystem matrix |
