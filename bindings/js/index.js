let wasmExports = null;

function ensureInitialized() {
  if (!wasmExports) {
    throw new Error('lsec: wasm module not initialized. Call await init() first.');
  }
}

function toBytes(input) {
  if (typeof input === 'string') {
    return new TextEncoder().encode(input);
  }
  if (input instanceof Uint8Array) {
    return input;
  }
  if (input instanceof Buffer) {
    return input.bytes();
  }
  throw new TypeError('lsec: expected string, Uint8Array, or lsec.Buffer');
}

function copyToWasm(bytes) {
  if (bytes.length === 0) {
    return 0;
  }
  const ptr = wasmExports.lsec_wasm_alloc(bytes.length);
  if (ptr === 0) {
    throw new Error('lsec: failed to allocate wasm memory');
  }
  new Uint8Array(wasmExports.memory.buffer, ptr, bytes.length).set(bytes);
  return ptr;
}

function copyFromWasm(ptr, len) {
  if (ptr === 0 || len === 0) {
    return new Uint8Array(0);
  }
  return new Uint8Array(wasmExports.memory.buffer, ptr, len).slice();
}

export async function init(wasmSource) {
  if (wasmExports) {
    return;
  }

  let randomFill = null;
  if (typeof globalThis.crypto?.getRandomValues === 'function') {
    randomFill = (view) => {
      globalThis.crypto.getRandomValues(view);
    };
  } else if (typeof globalThis.process !== 'undefined' && globalThis.process.versions?.node) {
    try {
      const nodeCrypto = await import('node:crypto');
      randomFill = (view) => {
        nodeCrypto.randomFillSync(view);
      };
    } catch {
      randomFill = null;
    }
  }

  const imports = {
    env: {
      lsec_host_random: (ptr, len) => {
        if (ptr === 0 || len === 0) return 0;
        const view = new Uint8Array(wasmExports.memory.buffer, ptr, len);
        if (randomFill) {
          randomFill(view);
          return 0;
        }
        return -1;
      }
    }
  };

  let moduleBytes = wasmSource;

  if (!moduleBytes) {
    // node.js local file resolution fallback
    if (typeof globalThis.process !== 'undefined' && globalThis.process.versions?.node) {
      const fs = await import('node:fs');
      const path = await import('node:path');
      const url = await import('node:url');
      const filename = url.fileURLToPath(import.meta.url);
      const dirname = path.dirname(filename);
      const releasePath = path.resolve(dirname, '../../target/wasm32-unknown-unknown/release/lsec_wasm.wasm');
      const debugPath = path.resolve(dirname, '../../target/wasm32-unknown-unknown/debug/lsec_wasm.wasm');
      if (fs.existsSync(releasePath)) {
        moduleBytes = fs.readFileSync(releasePath);
      } else if (fs.existsSync(debugPath)) {
        moduleBytes = fs.readFileSync(debugPath);
      }
    }
  }

  if (!moduleBytes) {
    throw new Error('lsec: wasm source not provided and could not locate default binary');
  }

  let instance;
  if (moduleBytes instanceof WebAssembly.Module) {
    instance = await WebAssembly.instantiate(moduleBytes, imports);
  } else if (moduleBytes instanceof ArrayBuffer || ArrayBuffer.isView(moduleBytes)) {
    const res = await WebAssembly.instantiate(moduleBytes, imports);
    instance = res.instance;
  } else if (typeof Response !== 'undefined' && moduleBytes instanceof Response) {
    const res = await WebAssembly.instantiateStreaming(moduleBytes, imports);
    instance = res.instance;
  } else {
    const res = await WebAssembly.instantiate(moduleBytes, imports);
    instance = res.instance;
  }

  wasmExports = instance.exports;
}

export class Buffer {
  #handle = null;
  #length = 0;

  constructor(handle, length) {
    if (!handle || handle === 0) {
      throw new Error('lsec: invalid buffer handle');
    }
    this.#handle = handle;
    this.#length = length;
  }

  static from(input) {
    ensureInitialized();
    const bytes = toBytes(input);
    const ptr = copyToWasm(bytes);
    try {
      const handle = wasmExports.lsec_wasm_buffer_new(ptr, bytes.length);
      if (!handle || handle === 0) {
        throw new Error('lsec: failed to create protected buffer');
      }
      return new Buffer(handle, bytes.length);
    } finally {
      if (ptr !== 0) {
        wasmExports.lsec_wasm_free(ptr, bytes.length);
      }
    }
  }

  static alloc(length) {
    ensureInitialized();
    const zeroBytes = new Uint8Array(length);
    return Buffer.from(zeroBytes);
  }

  get length() {
    return this.#length;
  }

  bytes() {
    this.#assertNotFreed();
    const dataPtr = wasmExports.lsec_wasm_buffer_data(this.#handle);
    const len = wasmExports.lsec_wasm_buffer_len(this.#handle);
    return copyFromWasm(dataPtr, len);
  }

  text() {
    return new TextDecoder().decode(this.bytes());
  }

  wipe() {
    this.#assertNotFreed();
    const status = wasmExports.lsec_wasm_buffer_wipe(this.#handle);
    if (status !== 0) {
      throw new Error('lsec: buffer wipe failed');
    }
  }

  free() {
    if (this.#handle && this.#handle !== 0) {
      wasmExports.lsec_wasm_buffer_free(this.#handle);
      this.#handle = null;
      this.#length = 0;
    }
  }

  get rawHandle() {
    this.#assertNotFreed();
    return this.#handle;
  }

  #assertNotFreed() {
    if (!this.#handle || this.#handle === 0) {
      throw new Error('lsec: buffer has already been freed');
    }
  }
}

export class Vault {
  static seal(plaintext, passphrase, cipher = 'chacha20-poly1305') {
    ensureInitialized();
    const plainBytes = toBytes(plaintext);
    const passBytes = toBytes(passphrase);

    const cipherId = cipher === 'aes-256-gcm' ? 2 : 1;

    const plainPtr = copyToWasm(plainBytes);
    const passPtr = copyToWasm(passBytes);
    const outLenPtr = wasmExports.lsec_wasm_alloc(4);

    try {
      const sealedPtr = wasmExports.lsec_wasm_vault_seal(
        plainPtr,
        plainBytes.length,
        passPtr,
        passBytes.length,
        cipherId,
        outLenPtr
      );

      if (!sealedPtr || sealedPtr === 0) {
        throw new Error('lsec: vault seal operation failed');
      }

      const lenView = new DataView(wasmExports.memory.buffer, outLenPtr, 4);
      const sealedLen = lenView.getUint32(0, true);

      const result = copyFromWasm(sealedPtr, sealedLen);
      wasmExports.lsec_wasm_vault_bytes_free(sealedPtr, sealedLen);
      return result;
    } finally {
      if (plainPtr !== 0) wasmExports.lsec_wasm_free(plainPtr, plainBytes.length);
      if (passPtr !== 0) wasmExports.lsec_wasm_free(passPtr, passBytes.length);
      if (outLenPtr !== 0) wasmExports.lsec_wasm_free(outLenPtr, 4);
    }
  }

  static unseal(vaultBytes, passphrase) {
    ensureInitialized();
    const vBytes = toBytes(vaultBytes);
    const passBytes = toBytes(passphrase);

    const vaultPtr = copyToWasm(vBytes);
    const passPtr = copyToWasm(passBytes);

    try {
      const handle = wasmExports.lsec_wasm_vault_unseal(
        vaultPtr,
        vBytes.length,
        passPtr,
        passBytes.length
      );

      if (!handle || handle === 0) {
        throw new Error('lsec: vault unseal failed or authentication tag mismatch');
      }

      const len = wasmExports.lsec_wasm_buffer_len(handle);
      return new Buffer(handle, len);
    } finally {
      if (vaultPtr !== 0) wasmExports.lsec_wasm_free(vaultPtr, vBytes.length);
      if (passPtr !== 0) wasmExports.lsec_wasm_free(passPtr, passBytes.length);
    }
  }
}

export class TOTP {
  static decodeBase32(base32Secret) {
    ensureInitialized();
    const bytes = new TextEncoder().encode(base32Secret.trim());
    const ptr = copyToWasm(bytes);

    try {
      const handle = wasmExports.lsec_wasm_totp_decode_base32(ptr, bytes.length);
      if (!handle || handle === 0) {
        throw new Error('lsec: invalid base32 secret encoding');
      }
      const len = wasmExports.lsec_wasm_buffer_len(handle);
      return new Buffer(handle, len);
    } finally {
      if (ptr !== 0) wasmExports.lsec_wasm_free(ptr, bytes.length);
    }
  }

  static generate(secret, options = {}) {
    ensureInitialized();
    const secBytes = toBytes(secret);
    const timestamp = BigInt(options.timestamp ?? Math.floor(Date.now() / 1000));
    const stepSeconds = BigInt(options.stepSeconds ?? 30);
    const digits = options.digits ?? 6;

    let algoId = 0;
    if (options.algorithm === 'sha256') algoId = 1;
    if (options.algorithm === 'sha512') algoId = 2;

    const secPtr = copyToWasm(secBytes);
    const codePtr = wasmExports.lsec_wasm_alloc(digits + 1);

    try {
      const status = wasmExports.lsec_wasm_totp_generate(
        secPtr,
        secBytes.length,
        timestamp,
        stepSeconds,
        digits,
        algoId,
        codePtr,
        digits + 1
      );

      if (status !== 0) {
        throw new Error(`lsec: totp generation failed with code ${status}`);
      }

      const codeBytes = copyFromWasm(codePtr, digits);
      return new TextDecoder().decode(codeBytes);
    } finally {
      if (secPtr !== 0) wasmExports.lsec_wasm_free(secPtr, secBytes.length);
      if (codePtr !== 0) wasmExports.lsec_wasm_free(codePtr, digits + 1);
    }
  }

  static verify(secret, candidateCode, options = {}) {
    ensureInitialized();
    const secBytes = toBytes(secret);
    const candBytes = new TextEncoder().encode(candidateCode.trim());
    const timestamp = BigInt(options.timestamp ?? Math.floor(Date.now() / 1000));
    const stepSeconds = BigInt(options.stepSeconds ?? 30);
    const digits = options.digits ?? candidateCode.trim().length;
    const driftSteps = options.driftSteps ?? 1;

    let algoId = 0;
    if (options.algorithm === 'sha256') algoId = 1;
    if (options.algorithm === 'sha512') algoId = 2;

    const secPtr = copyToWasm(secBytes);
    const candPtr = copyToWasm(candBytes);

    try {
      const result = wasmExports.lsec_wasm_totp_verify(
        secPtr,
        secBytes.length,
        candPtr,
        candBytes.length,
        timestamp,
        stepSeconds,
        digits,
        driftSteps,
        algoId
      );

      if (result < 0) {
        throw new Error(`lsec: totp verification error with code ${result}`);
      }

      return result === 1;
    } finally {
      if (secPtr !== 0) wasmExports.lsec_wasm_free(secPtr, secBytes.length);
      if (candPtr !== 0) wasmExports.lsec_wasm_free(candPtr, candBytes.length);
    }
  }
}

export function version() {
  ensureInitialized();
  return {
    major: wasmExports.lsec_wasm_version_major(),
    minor: wasmExports.lsec_wasm_version_minor(),
    patch: wasmExports.lsec_wasm_version_patch()
  };
}
