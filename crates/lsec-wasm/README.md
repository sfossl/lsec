## Overview

`lsec-wasm` is the freestanding WebAssembly compilation target for the `lsec` defense-in-depth security engine. It exposes zero-dependency cryptographic operations, vault encryption and TOTP verification directly in linear WebAssembly memory for browser, progressive web app and edge runtime execution.

## Exported Functions

| Symbol | Signature | Role |
| :--- | :--- | :--- |
| `lsec_wasm_alloc` | `(size: u32) -> u32` | Allocates memory in WebAssembly linear heap |
| `lsec_wasm_free` | `(ptr: u32, size: u32)` | Zeroizes and deallocates memory |
| `lsec_wasm_vault_seal` | `(data_ptr, data_len, pass_ptr, pass_len, cipher) -> u32` | Encrypts payload into serialized envelope |
| `lsec_wasm_vault_unseal` | `(cipher_ptr, cipher_len, pass_ptr, pass_len) -> u32` | Authenticates and decrypts single or multi-slot envelope |
| `lsec_wasm_multi_vault_create` | `(data_ptr, data_len, pass_ptr, pass_len, cipher, out_len) -> u32` | Creates multi-slot container with slot 0 |
| `lsec_wasm_multi_vault_open` | `(c_ptr, c_len, pass_ptr, pass_len) -> u32` | Unwraps DEK and decrypts payload into memory |
| `lsec_wasm_multi_vault_add_slot` | `(c_ptr, c_len, exist_pass, exist_len, new_pass, new_len, cipher) -> i32` | Adds new credential slot to container |
| `lsec_wasm_multi_vault_remove_slot` | `(c_ptr, c_len, exist_pass, exist_len, slot_idx) -> i32` | Zeroizes targeted slot |
| `lsec_wasm_multi_vault_update_payload` | `(c_ptr, c_len, exist_pass, exist_len, plain_ptr, plain_len, out_len) -> u32` | Fast payload update reusing existing DEK |
| `lsec_wasm_multi_vault_active_slots` | `(c_ptr, c_len, out_slots_ptr) -> i32` | Reads active status for all 4 slots |
| `lsec_wasm_totp_generate` | `(secret_ptr, secret_len, step, digits, algo, time) -> u32` | Generates RFC 6238 token code |
| `lsec_wasm_totp_verify` | `(secret_ptr, secret_len, step, digits, algo, token, time, skew) -> i32` | Constant-time TOTP verification |

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
