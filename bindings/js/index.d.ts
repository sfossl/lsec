export type BinarySource = string | Uint8Array | Buffer;

export type CipherAlgorithm = 'chacha20-poly1305' | 'aes-256-gcm';

export type HashAlgorithm = 'sha1' | 'sha256' | 'sha512';

export interface TOTPGenerateOptions {
  timestamp?: number | bigint;
  stepSeconds?: number | bigint;
  digits?: number;
  algorithm?: HashAlgorithm;
}

export interface TOTPVerifyOptions extends TOTPGenerateOptions {
  driftSteps?: number;
}

export interface VersionInfo {
  major: number;
  minor: number;
  patch: number;
}

export function init(
  wasmSource?: BufferSource | WebAssembly.Module | Response
): Promise<void>;

export function version(): VersionInfo;

export class Buffer {
  constructor(handle: number, length: number);

  static from(input: BinarySource): Buffer;
  static alloc(length: number): Buffer;

  get length(): number;
  get rawHandle(): number;

  bytes(): Uint8Array;
  text(): string;
  wipe(): void;
  free(): void;
}

export class Vault {
  static seal(
    plaintext: BinarySource,
    passphrase: BinarySource,
    cipher?: CipherAlgorithm
  ): Uint8Array;

  static unseal(
    vaultBytes: BinarySource,
    passphrase: BinarySource
  ): Buffer;
}

export class MultiSlotVault {
  static create(
    payload: BinarySource,
    passphrase: BinarySource,
    cipher?: CipherAlgorithm
  ): Uint8Array;

  static open(
    container: BinarySource,
    passphrase: BinarySource
  ): Buffer;

  static addSlot(
    container: Uint8Array,
    existingPassphrase: BinarySource,
    newPassphrase: BinarySource,
    cipher?: CipherAlgorithm
  ): number;

  static removeSlot(
    container: Uint8Array,
    existingPassphrase: BinarySource,
    slotIndex: number
  ): void;

  static updatePayload(
    container: BinarySource,
    existingPassphrase: BinarySource,
    newPayload: BinarySource
  ): Uint8Array;

  static activeSlots(
    container: BinarySource
  ): [boolean, boolean, boolean, boolean];
}

export class TOTP {
  static decodeBase32(base32Secret: string): Buffer;

  static generate(
    secret: BinarySource,
    options?: TOTPGenerateOptions
  ): string;

  static verify(
    secret: BinarySource,
    candidateCode: string,
    options?: TOTPVerifyOptions
  ): boolean;
}

export { TOTP as Totp };

