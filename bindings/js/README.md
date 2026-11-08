## Overview

`@sfossl/lsec` is the official JavaScript and TypeScript SDK for the `lsec` defense-in-depth security engine. It runs on top of freestanding WebAssembly with zero external dependencies, providing local vault encryption, memory protection buffers and RFC 6238 TOTP verification across Node.js, browsers and modern edge runtimes.

## Installation

```bash
npm install @sfossl/lsec
```

## Capabilities Matrix

| Module | Purpose | Runtime Support |
| :--- | :--- | :--- |
| `Buffer` | Protected memory allocation with manual zeroization | Node.js, Browsers, PWAs, Edge |
| `Vault` | Envelope encryption with Argon2id and ChaCha20-Poly1305 | Node.js, Browsers, PWAs, Edge |
| `Totp` | RFC 6238 token code generation and timing-safe verify | Node.js, Browsers, PWAs, Edge |

## Usage

### Node.js

In Node.js environments, `init()` automatically loads the embedded WebAssembly binary:

```javascript
import { init, Vault, Totp } from '@sfossl/lsec';

// initialize wasm engine
await init();

const data = new TextEncoder().encode("data");
const passphrase = new TextEncoder().encode("passphrase");

// seal payload with authenticated encryption
const sealed = Vault.seal(data, passphrase);

// decrypt into protected buffer
const unsealed = Vault.unseal(sealed, passphrase);
console.log("decrypted bytes:", unsealed.bytes.length);

// zeroize and free memory
unsealed.free();
```

### Browser and Bundlers

In browsers, PWAs and bundlers (Vite, Webpack, Rollup), pass a fetched `Response`, `ArrayBuffer` or URL to `init()`:

```javascript
import { init, Vault } from '@sfossl/lsec';

const wasmResponse = await fetch('/assets/lsec_wasm.wasm');
await init(wasmResponse);
```

## Memory Management

Because WebAssembly executes within a dedicated linear memory space without host garbage collection:

* Every `Buffer` instance allocates memory inside the WebAssembly heap.
* Call `buf.free()` or `buf.wipe()` when done with sensitive material to ensure immediate memory zeroization.

## Connected Topics

| Topic | Relationship | Context |
| :--- | :--- | :--- |
| [WebAssembly Engine](https://github.com/sfossl/lsec/tree/main/crates/lsec-wasm) | Underlying Engine | Rust crate compiling directly to WebAssembly |
| [WebAssembly Guide](https://github.com/sfossl/lsec/blob/main/.docs/wasm-integration.md) | Dedicated Documentation | Streaming instantiation and linear memory rules |
| [npm Package](https://www.npmjs.com/package/@sfossl/lsec) | Registry Distribution | Published package releases and versions |
| [API Reference](https://github.com/sfossl/lsec/blob/main/.docs/api-reference.md) | Function Index | Complete JavaScript and TypeScript symbol specifications |
| [Repository Overview](https://github.com/sfossl/lsec) | Workspace Root | Architecture and multi-target ecosystem matrix |
