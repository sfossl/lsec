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

assert.strictEqual(exports.lsec_wasm_is_ready(), 1);
assert.strictEqual(exports.lsec_wasm_version_major(), 0);
assert.strictEqual(exports.lsec_wasm_version_minor(), 3);
assert.strictEqual(exports.lsec_wasm_version_patch(), 0);
console.log('wasm: readiness and version tests passed');

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
  exports.lsec_wasm_wipe_and_free(secretPtr, secret.length);
  console.log('wasm: protected buffer lifecycle passed');
}

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
    1,
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
  exports.lsec_wasm_wipe_and_free(plainPtr, plaintext.length);
  exports.lsec_wasm_wipe_and_free(passPtr, passphrase.length);
  exports.lsec_wasm_free(outLenPtr, 4);
  console.log('wasm: vault seal and unseal roundtrip passed');
}

{
  const payload = new TextEncoder().encode('wasm-multi-vault-payload');
  const pass0 = new TextEncoder().encode('wasm-primary-passphrase');
  const pass1 = new TextEncoder().encode('wasm-recovery-passphrase');
  const updatedPayload = new TextEncoder().encode('wasm-updated-multi-vault-payload');

  const payloadPtr = writeBytes(payload);
  const pass0Ptr = writeBytes(pass0);
  const pass1Ptr = writeBytes(pass1);
  const updatedPayloadPtr = writeBytes(updatedPayload);
  const outLenPtr = exports.lsec_wasm_alloc(4);
  const slotsPtr = exports.lsec_wasm_alloc(4);

  const containerPtr = exports.lsec_wasm_multi_vault_create(
    payloadPtr,
    payload.length,
    pass0Ptr,
    pass0.length,
    1,
    outLenPtr
  );
  assert.notStrictEqual(containerPtr, 0);

  const containerLen = new DataView(exports.memory.buffer, outLenPtr, 4).getUint32(0, true);
  assert.ok(containerLen >= 367);

  assert.strictEqual(exports.lsec_wasm_multi_vault_active_slots(containerPtr, containerLen, slotsPtr), 0);
  assert.deepStrictEqual(readBytes(slotsPtr, 4), new Uint8Array([1, 0, 0, 0]));

  const slotIdx = exports.lsec_wasm_multi_vault_add_slot(
    containerPtr,
    containerLen,
    pass0Ptr,
    pass0.length,
    pass1Ptr,
    pass1.length,
    2
  );
  assert.strictEqual(slotIdx, 1);

  const openHandle = exports.lsec_wasm_multi_vault_open(
    containerPtr,
    containerLen,
    pass1Ptr,
    pass1.length
  );
  assert.notStrictEqual(openHandle, 0);
  const openLen = exports.lsec_wasm_buffer_len(openHandle);
  assert.deepStrictEqual(readBytes(exports.lsec_wasm_buffer_data(openHandle), openLen), payload);
  exports.lsec_wasm_buffer_free(openHandle);

  const updatedPtr = exports.lsec_wasm_multi_vault_update_payload(
    containerPtr,
    containerLen,
    pass0Ptr,
    pass0.length,
    updatedPayloadPtr,
    updatedPayload.length,
    outLenPtr
  );
  assert.notStrictEqual(updatedPtr, 0);
  const updatedLen = new DataView(exports.memory.buffer, outLenPtr, 4).getUint32(0, true);

  assert.strictEqual(
    exports.lsec_wasm_multi_vault_remove_slot(updatedPtr, updatedLen, pass0Ptr, pass0.length, 1),
    0
  );
  assert.strictEqual(
    exports.lsec_wasm_multi_vault_open(updatedPtr, updatedLen, pass1Ptr, pass1.length),
    0
  );

  exports.lsec_wasm_vault_bytes_free(containerPtr, containerLen);
  exports.lsec_wasm_vault_bytes_free(updatedPtr, updatedLen);
  exports.lsec_wasm_wipe_and_free(payloadPtr, payload.length);
  exports.lsec_wasm_wipe_and_free(pass0Ptr, pass0.length);
  exports.lsec_wasm_wipe_and_free(pass1Ptr, pass1.length);
  exports.lsec_wasm_wipe_and_free(updatedPayloadPtr, updatedPayload.length);
  exports.lsec_wasm_free(outLenPtr, 4);
  exports.lsec_wasm_free(slotsPtr, 4);
  console.log('wasm: multi-vault lifecycle passed');
}

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
    0,
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
    1,
    0
  );
  assert.strictEqual(valid, 1);

  exports.lsec_wasm_buffer_free(seedHandle);
  exports.lsec_wasm_wipe_and_free(b32Ptr, base32Seed.length);
  exports.lsec_wasm_wipe_and_free(codeOutPtr, 8);
  console.log('wasm: totp decode, generate, verify passed');
}

console.log('all wasm integration tests passed successfully.');
