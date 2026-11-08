[Docs Overview](../README.md#documentation) / WebAssembly Integration

# WebAssembly Integration

`bindings/js` provides a zero-dependency TypeScript and JavaScript SDK running on top of `lsec-wasm`.

### Documentation Guides
[Getting Started](getting-started.md) | [Memory Guard](memguard.md) | [Vault](vault.md) | [TOTP](totp.md) | [C Integration](c-integration.md) | [Go Integration](go-integration.md) | [WebAssembly](wasm-integration.md) | [API Reference](api-reference.md)

## Building the Wasm Target

Compile `lsec-wasm` to WebAssembly:

```bash
cargo build --release --target wasm32-unknown-unknown -p lsec-wasm
```

The compiled binary will be placed at:
`target/wasm32-unknown-unknown/release/lsec_wasm.wasm`

## Node.js Usage

In Node.js, `init()` automatically discovers the compiled binary in `target/` if no source argument is provided:

```javascript
import { init, Vault, Buffer } from './bindings/js/index.js';

await init();

const data = new TextEncoder().encode("data");
const passphrase = new TextEncoder().encode("passphrase");

const sealed = Vault.seal(data, passphrase);
const unsealed = Vault.unseal(sealed, passphrase);

console.log(unsealed.bytes);
unsealed.free();
```

## Browser & PWA Usage

In modern browser environments or bundlers (Vite, Webpack, Rollup), pass the fetched Wasm response or byte buffer to `init()`:

```javascript
import { init, Vault } from '@sfossl/lsec';

// streaming instantiation
const wasmResponse = await fetch('/assets/lsec_wasm.wasm');
await init(wasmResponse);

const encrypted = Vault.seal(
  new TextEncoder().encode("data"),
  new TextEncoder().encode("passphrase")
);
```

## Memory Management

Because WebAssembly runs in linear memory without automatic host garbage collection:
1. Every `Buffer` instance allocates memory in the Wasm heap.
2. Call `buffer.free()` or `buffer.wipe()` when done with sensitive material to zero out bytes and avoid linear memory fragmentation.

---

## Connected Topics

| Context | Destination | Description |
| :--- | :--- | :--- |
| **Previous** | [Go Integration](go-integration.md) | CGo package and runtime safety |
| **Next** | [API Reference](api-reference.md) | Complete signatures, constants and error codes |
| **API Reference** | [API Reference: JS SDK](api-reference.md#module-bindingsjs) | JavaScript class definitions and static helpers |
| **Source Code** | [`index.js`](../bindings/js/index.js) | ESM loader and buffer classes |
