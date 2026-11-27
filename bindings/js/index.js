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
  throw new TypeError('lsec: expected string, Uint8Array or lsec.Buffer');
}

function allocWasm(size) {
  const ptr = wasmExports.lsec_wasm_alloc(size);
  if (ptr === 0) {
    throw new Error('lsec: failed to allocate wasm memory');
  }
  return ptr;
}

function copyToWasm(bytes) {
  const allocSize = bytes.length === 0 ? 1 : bytes.length;
  const ptr = allocWasm(allocSize);
  if (bytes.length > 0) {
    new Uint8Array(wasmExports.memory.buffer, ptr, bytes.length).set(bytes);
  }
  return ptr;
}

function copyFromWasm(ptr, len) {
  if (ptr === 0 || len === 0) {
    return new Uint8Array(0);
  }
  return new Uint8Array(wasmExports.memory.buffer, ptr, len).slice();
}

function parseCipher(cipher) {
  if (cipher === 'chacha20-poly1305' || cipher === 1) {
    return 1;
  }
  if (cipher === 'aes-256-gcm' || cipher === 'aes256-gcm' || cipher === 2) {
    return 2;
  }
  throw new TypeError(`lsec: unknown cipher suite: ${cipher}`);
}

function parseAlgo(algo) {
  if (algo === undefined || algo === 'sha1' || algo === 0) {
    return 0;
  }
  if (algo === 'sha256' || algo === 1) {
    return 1;
  }
  if (algo === 'sha512' || algo === 2) {
    return 2;
  }
  throw new TypeError(`lsec: unknown totp algorithm: ${algo}`);
}

function readVaultBytes(outLenPtr, ptr) {
  const len = new DataView(wasmExports.memory.buffer, outLenPtr, 4).getUint32(0, true);
  const result = copyFromWasm(ptr, len);
  wasmExports.lsec_wasm_vault_bytes_free(ptr, len);
  return result;
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
    if (typeof globalThis.process !== 'undefined' && globalThis.process.versions?.node) {
      const fs = await import('node:fs');
      const path = await import('node:path');
      const url = await import('node:url');
      const filename = url.fileURLToPath(import.meta.url);
      const dirname = path.dirname(filename);
      const releasePath = path.resolve(dirname, '../../target/wasm32-unknown-unknown/release/lsec_wasm.wasm');
      const debugPath = path.resolve(dirname, '../../target/wasm32-unknown-unknown/debug/lsec_wasm.wasm');
      const localWasmPath = path.resolve(dirname, './lsec_wasm.wasm');
      if (fs.existsSync(localWasmPath)) {
        moduleBytes = fs.readFileSync(localWasmPath);
      } else if (fs.existsSync(releasePath)) {
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
      wasmExports.lsec_wasm_wipe_and_free(ptr, bytes.length || 1);
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
    const cipherId = parseCipher(cipher);

    const plainPtr = copyToWasm(plainBytes);
    const passPtr = copyToWasm(passBytes);
    const outLenPtr = allocWasm(4);

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

      return readVaultBytes(outLenPtr, sealedPtr);
    } finally {
      wasmExports.lsec_wasm_wipe_and_free(plainPtr, plainBytes.length || 1);
      wasmExports.lsec_wasm_wipe_and_free(passPtr, passBytes.length || 1);
      wasmExports.lsec_wasm_free(outLenPtr, 4);
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
      wasmExports.lsec_wasm_wipe_and_free(vaultPtr, vBytes.length || 1);
      wasmExports.lsec_wasm_wipe_and_free(passPtr, passBytes.length || 1);
    }
  }
}

export class MultiSlotVault {
  static create(payload, passphrase, cipher = 'chacha20-poly1305') {
    ensureInitialized();
    const plainBytes = toBytes(payload);
    const passBytes = toBytes(passphrase);
    const cipherId = parseCipher(cipher);

    const plainPtr = copyToWasm(plainBytes);
    const passPtr = copyToWasm(passBytes);
    const outLenPtr = allocWasm(4);

    try {
      const sealedPtr = wasmExports.lsec_wasm_multi_vault_create(
        plainPtr,
        plainBytes.length,
        passPtr,
        passBytes.length,
        cipherId,
        outLenPtr
      );

      if (!sealedPtr || sealedPtr === 0) {
        throw new Error('lsec: multi-slot vault creation failed');
      }

      return readVaultBytes(outLenPtr, sealedPtr);
    } finally {
      wasmExports.lsec_wasm_wipe_and_free(plainPtr, plainBytes.length || 1);
      wasmExports.lsec_wasm_wipe_and_free(passPtr, passBytes.length || 1);
      wasmExports.lsec_wasm_free(outLenPtr, 4);
    }
  }

  static open(container, passphrase) {
    return Vault.unseal(container, passphrase);
  }

  static addSlot(container, existingPassphrase, newPassphrase, cipher = 'chacha20-poly1305') {
    ensureInitialized();
    if (!(container instanceof Uint8Array)) {
      throw new TypeError('lsec: container must be a Uint8Array');
    }
    const existBytes = toBytes(existingPassphrase);
    const newBytes = toBytes(newPassphrase);
    const cipherId = parseCipher(cipher);

    const cPtr = copyToWasm(container);
    const existPtr = copyToWasm(existBytes);
    const newPtr = copyToWasm(newBytes);

    try {
      const slotIdx = wasmExports.lsec_wasm_multi_vault_add_slot(
        cPtr,
        container.length,
        existPtr,
        existBytes.length,
        newPtr,
        newBytes.length,
        cipherId
      );

      if (slotIdx < 0) {
        throw new Error('lsec: failed to add slot to multi-slot vault');
      }

      const updated = copyFromWasm(cPtr, container.length);
      container.set(updated);
      return slotIdx;
    } finally {
      wasmExports.lsec_wasm_wipe_and_free(cPtr, container.length || 1);
      wasmExports.lsec_wasm_wipe_and_free(existPtr, existBytes.length || 1);
      wasmExports.lsec_wasm_wipe_and_free(newPtr, newBytes.length || 1);
    }
  }

  static removeSlot(container, existingPassphrase, slotIndex) {
    ensureInitialized();
    if (!(container instanceof Uint8Array)) {
      throw new TypeError('lsec: container must be a Uint8Array');
    }
    const existBytes = toBytes(existingPassphrase);

    const cPtr = copyToWasm(container);
    const existPtr = copyToWasm(existBytes);

    try {
      const status = wasmExports.lsec_wasm_multi_vault_remove_slot(
        cPtr,
        container.length,
        existPtr,
        existBytes.length,
        slotIndex
      );

      if (status !== 0) {
        throw new Error(`lsec: failed to remove slot ${slotIndex}`);
      }

      const updated = copyFromWasm(cPtr, container.length);
      container.set(updated);
    } finally {
      wasmExports.lsec_wasm_wipe_and_free(cPtr, container.length || 1);
      wasmExports.lsec_wasm_wipe_and_free(existPtr, existBytes.length || 1);
    }
  }

  static updatePayload(container, existingPassphrase, newPayload) {
    ensureInitialized();
    const cBytes = toBytes(container);
    const existBytes = toBytes(existingPassphrase);
    const plainBytes = toBytes(newPayload);

    const cPtr = copyToWasm(cBytes);
    const existPtr = copyToWasm(existBytes);
    const plainPtr = copyToWasm(plainBytes);
    const outLenPtr = allocWasm(4);

    try {
      const sealedPtr = wasmExports.lsec_wasm_multi_vault_update_payload(
        cPtr,
        cBytes.length,
        existPtr,
        existBytes.length,
        plainPtr,
        plainBytes.length,
        outLenPtr
      );

      if (!sealedPtr || sealedPtr === 0) {
        throw new Error('lsec: fast payload update failed');
      }

      return readVaultBytes(outLenPtr, sealedPtr);
    } finally {
      wasmExports.lsec_wasm_wipe_and_free(cPtr, cBytes.length || 1);
      wasmExports.lsec_wasm_wipe_and_free(existPtr, existBytes.length || 1);
      wasmExports.lsec_wasm_wipe_and_free(plainPtr, plainBytes.length || 1);
      wasmExports.lsec_wasm_free(outLenPtr, 4);
    }
  }

  static activeSlots(container) {
    ensureInitialized();
    const cBytes = toBytes(container);
    const cPtr = copyToWasm(cBytes);
    const outPtr = allocWasm(4);

    try {
      const status = wasmExports.lsec_wasm_multi_vault_active_slots(cPtr, cBytes.length, outPtr);
      if (status !== 0) {
        throw new Error('lsec: failed to read active slots');
      }

      const slotsBytes = copyFromWasm(outPtr, 4);
      return [
        slotsBytes[0] === 1,
        slotsBytes[1] === 1,
        slotsBytes[2] === 1,
        slotsBytes[3] === 1
      ];
    } finally {
      wasmExports.lsec_wasm_wipe_and_free(cPtr, cBytes.length || 1);
      wasmExports.lsec_wasm_free(outPtr, 4);
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
      wasmExports.lsec_wasm_wipe_and_free(ptr, bytes.length || 1);
    }
  }

  static generate(secret, options = {}) {
    ensureInitialized();
    const secBytes = toBytes(secret);
    const timestamp = BigInt(options.timestamp ?? Math.floor(Date.now() / 1000));
    const stepSeconds = BigInt(options.stepSeconds ?? 30);
    const digits = options.digits ?? 6;
    const algoId = parseAlgo(options.algorithm);

    const secPtr = copyToWasm(secBytes);
    const codePtr = allocWasm(digits + 1);

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
      wasmExports.lsec_wasm_wipe_and_free(secPtr, secBytes.length || 1);
      wasmExports.lsec_wasm_wipe_and_free(codePtr, digits + 1);
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
    const algoId = parseAlgo(options.algorithm);

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
      wasmExports.lsec_wasm_wipe_and_free(secPtr, secBytes.length || 1);
      wasmExports.lsec_wasm_wipe_and_free(candPtr, candBytes.length || 1);
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

export { TOTP as Totp };
