import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const wasmPath = path.resolve(__dirname, '../../../target/wasm32-unknown-unknown/debug/lsec_wasm.wasm');

const wasmBytes = fs.readFileSync(wasmPath);

let wasmInstance = null;

const imports = {
  env: {
    lsec_host_random: (ptr, len) => {
      const mem = wasmInstance.exports.memory.buffer;
      const view = new Uint8Array(mem, ptr, len);
      crypto.getRandomValues(view);
      return 0;
    }
  }
};

const { instance } = await WebAssembly.instantiate(wasmBytes, imports);
wasmInstance = instance;
const exports = instance.exports;

console.log('wasm: instantiated successfully');

// version and readiness
assert.strictEqual(exports.lsec_wasm_is_ready(), 1);
assert.strictEqual(exports.lsec_wasm_version_major(), 0);
assert.strictEqual(exports.lsec_wasm_version_minor(), 1);
assert.strictEqual(exports.lsec_wasm_version_patch(), 0);
console.log('wasm: readiness and version tests passed');

// helper functions
function writeBytes(bytes) {
  const ptr = exports.lsec_wasm_alloc(bytes.length);
  assert.notStrictEqual(ptr, 0);
  const mem = new Uint8Array(exports.memory.buffer, ptr, bytes.length);
  mem.set(bytes);
  return ptr;
}

function readBytes(ptr, len) {
  const mem = new Uint8Array(exports.memory.buffer, ptr, len);
  return new Uint8Array(mem);
}

// memory lifecycle
{
  const size = 32;
  const ptr = exports.lsec_wasm_alloc(size);
  assert.notStrictEqual(ptr, 0);
  const view = new Uint8Array(exports.memory.buffer, ptr, size);
  view.fill(0x55);
  assert.strictEqual(view[0], 0x55);
  exports.lsec_wasm_wipe_and_free(ptr, size);
  console.log('wasm: linear memory alloc and wipe_and_free passed');
}

// protected buffer lifecycle
{
  const secret = new TextEncoder().encode('offline-pwa-secret-seed');
  const secretPtr = writeBytes(secret);

  const handle = exports.lsec_wasm_buffer_new(secretPtr, secret.length);
  assert.notStrictEqual(handle, 0);

  const len = exports.lsec_wasm_buffer_len(handle);
  assert.strictEqual(len, secret.length);

  const dataPtr = exports.lsec_wasm_buffer_data(handle);
  const readBack = readBytes(dataPtr, len);
  assert.deepStrictEqual(readBack, secret);

  const wipeStatus = exports.lsec_wasm_buffer_wipe(handle);
  assert.strictEqual(wipeStatus, 0);

  const wiped = readBytes(dataPtr, len);
  assert.deepStrictEqual(wiped, new Uint8Array(len));

  exports.lsec_wasm_buffer_free(handle);
  exports.lsec_wasm_free(secretPtr, secret.length);
  console.log('wasm: protected buffer lifecycle passed');
}

// vault seal and unseal (PWA offline database encryption)
{
  const plaintext = new TextEncoder().encode('offline-local-account-credentials');
  const passphrase = new TextEncoder().encode('super-strong-user-passphrase');

  const plainPtr = writeBytes(plaintext);
  const passPtr = writeBytes(passphrase);
  const outLenPtr = exports.lsec_wasm_alloc(4);

  const sealedPtr = exports.lsec_wasm_vault_seal(
    plainPtr,
    plaintext.length,
    passPtr,
    passphrase.length,
    1, // ChaCha20Poly1305
    outLenPtr
  );
  assert.notStrictEqual(sealedPtr, 0);

  const sealedLenView = new DataView(exports.memory.buffer, outLenPtr, 4);
  const sealedLen = sealedLenView.getUint32(0, true);
  assert.ok(sealedLen > plaintext.length);

  const unsealHandle = exports.lsec_wasm_vault_unseal(
    sealedPtr,
    sealedLen,
    passPtr,
    passphrase.length
  );
  assert.notStrictEqual(unsealHandle, 0);

  const unsealedLen = exports.lsec_wasm_buffer_len(unsealHandle);
  assert.strictEqual(unsealedLen, plaintext.length);

  const unsealedPtr = exports.lsec_wasm_buffer_data(unsealHandle);
  const unsealedBytes = readBytes(unsealedPtr, unsealedLen);
  assert.deepStrictEqual(unsealedBytes, plaintext);

  exports.lsec_wasm_vault_bytes_free(sealedPtr, sealedLen);
  exports.lsec_wasm_buffer_free(unsealHandle);
  exports.lsec_wasm_free(plainPtr, plaintext.length);
  exports.lsec_wasm_free(passPtr, passphrase.length);
  exports.lsec_wasm_free(outLenPtr, 4);
  console.log('wasm: vault seal and unseal roundtrip passed');
}

// totp flow
{
  const base32Seed = new TextEncoder().encode('JBSWY3DPEHPK3PXP');
  const b32Ptr = writeBytes(base32Seed);

  const seedHandle = exports.lsec_wasm_totp_decode_base32(b32Ptr, base32Seed.length);
  assert.notStrictEqual(seedHandle, 0);

  const seedPtr = exports.lsec_wasm_buffer_data(seedHandle);
  const seedLen = exports.lsec_wasm_buffer_len(seedHandle);

  const codeOutPtr = exports.lsec_wasm_alloc(8);
  const timestamp = 1234567890n;

  const genStatus = exports.lsec_wasm_totp_generate(
    seedPtr,
    seedLen,
    timestamp,
    30n,
    6,
    0, // Sha1
    codeOutPtr,
    8
  );
  assert.strictEqual(genStatus, 0);

  const codeBytes = readBytes(codeOutPtr, 6);
  const codeStr = new TextDecoder().decode(codeBytes);
  assert.strictEqual(codeStr.length, 6);
  console.log('wasm: generated totp code:', codeStr);

  const valid = exports.lsec_wasm_totp_verify(
    seedPtr,
    seedLen,
    codeOutPtr,
    6,
    timestamp,
    30n,
    6,
    1, // 1 step drift
    0  // Sha1
  );
  assert.strictEqual(valid, 1);

  exports.lsec_wasm_buffer_free(seedHandle);
  exports.lsec_wasm_free(b32Ptr, base32Seed.length);
  exports.lsec_wasm_free(codeOutPtr, 8);
  console.log('wasm: totp decode, generate, verify passed');
}

console.log('all wasm integration tests passed successfully.');

