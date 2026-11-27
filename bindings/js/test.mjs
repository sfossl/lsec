import assert from 'node:assert';
import { init, version, Buffer, Vault, MultiSlotVault, TOTP, Totp } from './index.js';

await init();

const v = version();
assert.strictEqual(v.major, 0);
assert.strictEqual(v.minor, 3);
assert.strictEqual(v.patch, 0);
assert.strictEqual(Totp, TOTP);

{
  const text = 'lsec-in-memory-js-buffer-test';
  const buf = Buffer.from(text);
  assert.strictEqual(buf.length, text.length);
  assert.strictEqual(buf.text(), text);

  const bytes = buf.bytes();
  assert.strictEqual(bytes.length, text.length);

  buf.wipe();
  assert.deepStrictEqual(buf.bytes(), new Uint8Array(text.length));

  buf.free();
  assert.throws(() => buf.bytes(), /already been freed/);
}

{
  const plaintext = 'confidential-offline-client-session';
  const passphrase = 'js-vault-password-456';

  const sealed = Vault.seal(plaintext, passphrase, 'chacha20-poly1305');
  assert.ok(sealed instanceof Uint8Array);
  assert.ok(sealed.length > plaintext.length);

  const unsealed = Vault.unseal(sealed, passphrase);
  assert.strictEqual(unsealed.text(), plaintext);
  unsealed.free();

  assert.throws(() => {
    Vault.unseal(sealed, 'wrong-password');
  }, /unseal failed/);
}

{
  const plaintext = 'confidential-aes-session';
  const passphrase = 'aes-vault-password-789';

  const sealed = Vault.seal(plaintext, passphrase, 'aes-256-gcm');
  assert.ok(sealed.length > plaintext.length);

  const unsealed = Vault.unseal(sealed, passphrase);
  assert.strictEqual(unsealed.text(), plaintext);
  unsealed.free();
}

{
  assert.throws(() => {
    Vault.seal('data', 'passphrase', 'unknown-cipher');
  }, TypeError);

  assert.throws(() => {
    MultiSlotVault.create('data', 'passphrase', 'unknown-cipher');
  }, TypeError);

  assert.throws(() => {
    TOTP.generate('12345678901234567890', { algorithm: 'md5' });
  }, TypeError);

  assert.throws(() => {
    TOTP.verify('12345678901234567890', '123456', { algorithm: 'md5' });
  }, TypeError);
}

{
  const emptyBuf = Buffer.from(new Uint8Array(0));
  assert.strictEqual(emptyBuf.length, 0);
  assert.deepStrictEqual(emptyBuf.bytes(), new Uint8Array(0));
  emptyBuf.free();

  const sealedEmpty = Vault.seal(new Uint8Array(0), 'passphrase');
  const unsealedEmpty = Vault.unseal(sealedEmpty, 'passphrase');
  assert.strictEqual(unsealedEmpty.length, 0);
  unsealedEmpty.free();

  const emptyContainer = MultiSlotVault.create(new Uint8Array(0), 'passphrase');
  const openedEmpty = MultiSlotVault.open(emptyContainer, 'passphrase');
  assert.strictEqual(openedEmpty.length, 0);
  openedEmpty.free();
}

{
  const b32 = 'JBSWY3DPEE======';
  const decoded = TOTP.decodeBase32(b32);
  assert.strictEqual(decoded.text(), 'Hello!');
  assert.deepStrictEqual(decoded.bytes(), new TextEncoder().encode('Hello!'));
  decoded.free();
}

{
  const rfcSha1Seed = '12345678901234567890';
  const code = TOTP.generate(rfcSha1Seed, {
    timestamp: 59,
    stepSeconds: 30,
    digits: 6,
    algorithm: 'sha1'
  });
  assert.strictEqual(code, '287082');

  const valid = TOTP.verify(rfcSha1Seed, '287082', {
    timestamp: 59,
    stepSeconds: 30,
    digits: 6,
    algorithm: 'sha1'
  });
  assert.strictEqual(valid, true);

  const invalid = TOTP.verify(rfcSha1Seed, '000000', {
    timestamp: 59,
    stepSeconds: 30,
    digits: 6,
    algorithm: 'sha1'
  });
  assert.strictEqual(invalid, false);

  const rfcSha512Seed = '1234567890123456789012345678901234567890123456789012345678901234';
  const codeSha512 = TOTP.generate(rfcSha512Seed, {
    timestamp: 1234567890,
    stepSeconds: 30,
    digits: 8,
    algorithm: 'sha512'
  });
  assert.strictEqual(codeSha512, '93441116');

  const validSha512 = TOTP.verify(rfcSha512Seed, '93441116', {
    timestamp: 1234567890,
    stepSeconds: 30,
    digits: 8,
    algorithm: 'sha512'
  });
  assert.strictEqual(validSha512, true);
}

{
  const seed = 'test-drift-seed-bytes';
  const t0 = 1000000;
  const currentCode = TOTP.generate(seed, { timestamp: t0, stepSeconds: 30, digits: 6 });

  const driftOk = TOTP.verify(seed, currentCode, {
    timestamp: t0 + 30,
    stepSeconds: 30,
    digits: 6,
    driftSteps: 1
  });
  assert.strictEqual(driftOk, true);

  const driftExceeded = TOTP.verify(seed, currentCode, {
    timestamp: t0 + 60,
    stepSeconds: 30,
    digits: 6,
    driftSteps: 1
  });
  assert.strictEqual(driftExceeded, false);
}

{
  const payload = 'multi-slot-js-sdk-payload';
  const pass0 = 'primary-js-key';
  const pass1 = 'recovery-js-key';

  const container = MultiSlotVault.create(payload, pass0, 'chacha20-poly1305');
  assert.ok(container instanceof Uint8Array);
  assert.ok(container.length >= 367);

  const initialSlots = MultiSlotVault.activeSlots(container);
  assert.deepStrictEqual(initialSlots, [true, false, false, false]);

  const slot1 = MultiSlotVault.addSlot(container, pass0, pass1, 'aes-256-gcm');
  assert.strictEqual(slot1, 1);

  const updatedSlots = MultiSlotVault.activeSlots(container);
  assert.deepStrictEqual(updatedSlots, [true, true, false, false]);

  const opened = MultiSlotVault.open(container, pass1);
  assert.strictEqual(opened.text(), payload);
  opened.free();

  const newPayload = 'updated-payload-without-re-running-argon2id';
  const updatedContainer = MultiSlotVault.updatePayload(container, pass0, newPayload);

  const unsealed = Vault.unseal(updatedContainer, pass1);
  assert.strictEqual(unsealed.text(), newPayload);
  unsealed.free();

  assert.throws(() => {
    MultiSlotVault.addSlot('not-a-uint8array', pass0, pass1);
  }, TypeError);

  assert.throws(() => {
    MultiSlotVault.removeSlot('not-a-uint8array', pass0, 1);
  }, TypeError);

  assert.throws(() => {
    MultiSlotVault.removeSlot(updatedContainer, 'wrong-passphrase', 1);
  }, /failed to remove slot/);

  assert.throws(() => {
    MultiSlotVault.removeSlot(updatedContainer, pass0, 99);
  }, /failed to remove slot/);

  MultiSlotVault.removeSlot(updatedContainer, pass0, 1);
  assert.throws(() => {
    MultiSlotVault.open(updatedContainer, pass1);
  }, /vault unseal failed/);
}

console.log('all lsec js tests passed');
