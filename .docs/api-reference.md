[Docs Overview](../README.md#documentation) / API Reference

# API Reference

Complete reference of exported modules, constants, structs, C-ABI symbols and client SDKs.

### Documentation Guides
[Getting Started](getting-started.md) | [Memory Guard](memguard.md) | [Vault](vault.md) | [TOTP](totp.md) | [C Integration](c-integration.md) | [Go Integration](go-integration.md) | [WebAssembly](wasm-integration.md) | [API Reference](api-reference.md)

## Module: `lsec-core::config`

Central configuration and security parameter limits.

### Constants

| Constant | Value | Description |
| :--- | :--- | :--- |
| `DEFAULT_MAX_LOCKED_MEMORY_BYTES` | `16777216` (16 MiB) | Maximum locked memory permitted per buffer. |
| `DEFAULT_ARGON2_MEMORY_KIB` | `65536` (64 MiB) | Default memory cost for Argon2id. |
| `MIN_ARGON2_MEMORY_KIB` | `1024` (1 MiB) | Minimum acceptable Argon2id memory cost in headers. |
| `MAX_ARGON2_MEMORY_KIB` | `1048576` (1 GiB) | Maximum acceptable Argon2id memory cost in headers. |
| `DEFAULT_ARGON2_ITERATIONS` | `3` | Default time cost passes for Argon2id. |
| `MIN_ARGON2_ITERATIONS` | `1` | Minimum acceptable Argon2id iteration count. |
| `MAX_ARGON2_ITERATIONS` | `64` | Maximum acceptable Argon2id iteration count. |
| `DEFAULT_ARGON2_PARALLELISM` | `4` | Default lane parallelism for Argon2id. |
| `MIN_ARGON2_PARALLELISM` | `1` | Minimum acceptable Argon2id lane count. |
| `MAX_ARGON2_PARALLELISM` | `16` | Maximum acceptable Argon2id lane count. |
| `DEFAULT_KEY_LEN_BYTES` | `32` | Symmetric key length in bytes. |
| `DEFAULT_SALT_LEN_BYTES` | `16` | Cryptographic salt length in bytes. |
| `DEFAULT_NONCE_LEN_BYTES` | `12` | AEAD nonce length in bytes. |
| `DEFAULT_TAG_LEN_BYTES` | `16` | AEAD authentication tag length in bytes. |
| `POSIX_FILE_PERMISSIONS` | `0o600` | Owner-only read/write mask for vault files. |
| `POSIX_DIR_PERMISSIONS` | `0o700` | Owner-only read/write/traverse mask for vault directories. |
| `VAULT_MAGIC_HEADER` | `b"LSEC\x01\x00"` | 6-byte magic identifier for binary vault envelopes. |
| `DEFAULT_TOTP_STEP_SECONDS` | `30` | Default time-step window in seconds. |
| `DEFAULT_TOTP_DIGITS` | `6` | Default output code digit length. |
| `MIN_TOTP_DIGITS` | `6` | Minimum supported TOTP digits. |
| `MAX_TOTP_DIGITS` | `8` | Maximum supported TOTP digits. |
| `DEFAULT_TOTP_DRIFT_STEPS` | `1` | Allowed verification window drift steps (+/- 1 step). |

### Structs

- `SecurityConfig`: Container for runtime security parameters.
- `SecurityConfigBuilder`: Fluent builder for constructing `SecurityConfig`. Methods:
  - `max_locked_memory(bytes: usize) -> Self`
  - `argon2_memory_kib(kib: u32) -> Self`
  - `argon2_iterations(iterations: u32) -> Self`
  - `argon2_parallelism(lanes: u32) -> Self`
  - `totp_step_seconds(seconds: u64) -> Self`
  - `totp_digits(digits: u32) -> Self`
  - `totp_drift_steps(steps: u8) -> Self`
  - `build(self) -> SecurityConfig`

---

## Module: `lsec-core::memguard`

OS page-aligned memory allocation, physical RAM locking and deterministic wiping.

| Function / Method | Signature | Description |
| :--- | :--- | :--- |
| `ProtectedBuffer::new` | `fn new(data: &[u8]) -> Result<Self, MemguardError>` | Allocates page-aligned memory, locks to physical RAM (`mlock`/`VirtualLock`), excludes from core dumps (`MADV_DONTDUMP`) and copies data. |
| `ProtectedBuffer::zeroed` | `fn zeroed(len: usize) -> Result<Self, MemguardError>` | Allocates page-aligned zeroed locked memory without an initial source slice. |
| `ProtectedBuffer::len` | `fn len(&self) -> usize` | Returns payload length in bytes. |
| `ProtectedBuffer::is_empty` | `fn is_empty(&self) -> bool` | Returns true if length is zero. |
| `ProtectedBuffer::as_slice` | `fn as_slice(&self) -> &[u8]` | Returns immutable slice reference to locked memory. |
| `ProtectedBuffer::as_mut_slice` | `fn as_mut_slice(&mut self) -> &mut [u8]` | Returns mutable slice reference to locked memory. |
| `ProtectedBuffer::wipe` | `fn wipe(&mut self)` | Overwrites buffer using volatile memory zeroization. |

### `MemguardError`

- `ExceedsMaxAllocation(usize)`: Requested buffer size exceeds `DEFAULT_MAX_LOCKED_MEMORY_BYTES`.
- `AllocationFailed`: Memory allocator was unable to allocate layout.
- `LockFailed(std::io::Error)`: Operating system refused memory lock system call.

---

## Module: `lsec-core::crypto`

Cryptographic primitives for key derivation, symmetric ciphers and constant-time comparisons.

| Function | Signature | Description |
| :--- | :--- | :--- |
| `generate_salt` | `fn generate_salt() -> Result<[u8; 16], CryptoError>` | Generates CSPRNG salt using platform entropy. |
| `generate_nonce` | `fn generate_nonce() -> Result<[u8; 12], CryptoError>` | Generates random 96-bit nonce for AEAD ciphers. |
| `derive_key_argon2id` | `fn derive_key_argon2id(passphrase: &[u8], salt: &[u8], config: &SecurityConfig) -> Result<ProtectedBuffer, CryptoError>` | Derives a 256-bit symmetric key into locked memory using Argon2id. |
| `encrypt_chacha20` | `fn encrypt_chacha20(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>` | Encrypts payload with ChaCha20-Poly1305, prefixing 12-byte nonce. |
| `decrypt_chacha20` | `fn decrypt_chacha20(key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<ProtectedBuffer, CryptoError>` | Decrypts ChaCha20-Poly1305 ciphertext directly into locked memory. |
| `encrypt_aes256_gcm` | `fn encrypt_aes256_gcm(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>` | Encrypts payload with AES-256-GCM, prefixing 12-byte nonce. |
| `decrypt_aes256_gcm` | `fn decrypt_aes256_gcm(key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<ProtectedBuffer, CryptoError>` | Decrypts AES-256-GCM ciphertext directly into locked memory. |
| `constant_time_eq` | `fn constant_time_eq(a: &[u8], b: &[u8]) -> bool` | Constant-time slice comparison preventing timing attacks. |

---

## Module: `lsec-core::vault`

Binary envelope container and atomic filesystem storage.

| Function | Signature | Description |
| :--- | :--- | :--- |
| `seal` | `fn seal(plaintext: &[u8], passphrase: &[u8], config: &SecurityConfig, cipher: CipherSuite) -> Result<Vec<u8>, VaultError>` | Encrypts plaintext into a self-describing binary vault container. |
| `unseal` | `fn unseal(vault_bytes: &[u8], passphrase: &[u8]) -> Result<ProtectedBuffer, VaultError>` | Authenticates header and decrypts container into locked memory. |
| `seal_to_file` | `fn seal_to_file<P: AsRef<Path>>(path: P, plaintext: &[u8], passphrase: &[u8], config: &SecurityConfig, cipher: CipherSuite) -> Result<(), VaultError>` | Atomically writes vault container to disk with `0600` permissions. |
| `unseal_from_file` | `fn unseal_from_file<P: AsRef<Path>>(path: P, passphrase: &[u8]) -> Result<ProtectedBuffer, VaultError>` | Reads file from disk and decrypts container into locked memory. |

### `CipherSuite`

- `CipherSuite::ChaCha20Poly1305` (`0x01`): ChaCha20-Poly1305 AEAD.
- `CipherSuite::Aes256Gcm` (`0x02`): Hardware-accelerated AES-256-GCM AEAD.

---

## Module: `lsec-core::totp`

RFC 6238 time-based authentication and Base32 secret decoding.

| Function | Signature | Description |
| :--- | :--- | :--- |
| `decode_secret` | `fn decode_secret(encoded: &str) -> Result<ProtectedBuffer, TotpError>` | Decodes Base32 secret into locked memory, enforcing strict zero padding. |
| `generate_code` | `fn generate_code(secret: &[u8], timestamp: u64, step_seconds: u64, digits: u32, algorithm: TotpAlgorithm) -> Result<String, TotpError>` | Calculates TOTP passcode for specified time counter. |
| `generate_current` | `fn generate_current(secret: &[u8], config: &SecurityConfig, algorithm: TotpAlgorithm) -> Result<String, TotpError>` | Calculates TOTP passcode for current system time. |
| `verify_code_at` | `fn verify_code_at(secret: &[u8], candidate_code: &str, timestamp: u64, config: &SecurityConfig, algorithm: TotpAlgorithm) -> Result<bool, TotpError>` | Verifies candidate passcode in constant time across drift tolerance window. |
| `verify_code_current` | `fn verify_code_current(secret: &[u8], candidate_code: &str, config: &SecurityConfig, algorithm: TotpAlgorithm) -> Result<bool, TotpError>` | Verifies candidate passcode against current system time. |

### `TotpAlgorithm`

- `TotpAlgorithm::Sha1`: HMAC-SHA1 (RFC 6238 default).
- `TotpAlgorithm::Sha256`: HMAC-SHA256.
- `TotpAlgorithm::Sha512`: HMAC-SHA512.

---

## Module: `lsec-ffi` (C-ABI)

C99 header `include/lsec.h` function declarations and error codes.

### Return Codes

| Error Constant | Code | Description |
| :--- | :--- | :--- |
| `LSEC_OK` | `0` | Operation succeeded. |
| `LSEC_ERR_NULL_POINTER` | `-1` | Null pointer passed to function. |
| `LSEC_ERR_BUFFER_TOO_SMALL` | `-2` | Destination capacity insufficient. |
| `LSEC_ERR_INVALID_PARAM` | `-3` | Parameter or KDF limit out of range. |
| `LSEC_ERR_ALLOC_FAILED` | `-4` | Memory allocation failed. |
| `LSEC_ERR_LOCK_FAILED` | `-5` | Failed to pin memory to physical RAM. |
| `LSEC_ERR_CRYPTO_FAILED` | `-6` | Cryptographic tag mismatch or cipher failure. |
| `LSEC_ERR_VAULT_CORRUPT` | `-7` | Header corrupted or invalid magic identifier. |
| `LSEC_ERR_IO_FAILED` | `-8` | Filesystem IO error. |
| `LSEC_ERR_TOTP_FAILED` | `-9` | TOTP generation or verification error. |
| `LSEC_ERR_PANIC` | `-10` | Caught internal Rust panic. |

### Function Reference

#### Version Information

| Function | Signature | Description |
| :--- | :--- | :--- |
| `lsec_version_major` | `uint32_t lsec_version_major(void)` | Returns major version integer. |
| `lsec_version_minor` | `uint32_t lsec_version_minor(void)` | Returns minor version integer. |
| `lsec_version_patch` | `uint32_t lsec_version_patch(void)` | Returns patch version integer. |

#### Memory Guard

| Function | Signature | Description |
| :--- | :--- | :--- |
| `lsec_buffer_new` | `int32_t lsec_buffer_new(const uint8_t *data, size_t len, lsec_protected_buffer_t **out_buf)` | Allocates locked buffer with initial data. |
| `lsec_buffer_zeroed` | `int32_t lsec_buffer_zeroed(size_t len, lsec_protected_buffer_t **out_buf)` | Allocates zero-filled locked buffer. |
| `lsec_buffer_len` | `size_t lsec_buffer_len(const lsec_protected_buffer_t *buf)` | Returns length of buffer in bytes. |
| `lsec_buffer_data` | `const uint8_t *lsec_buffer_data(const lsec_protected_buffer_t *buf)` | Returns read-only pointer to buffer bytes. |
| `lsec_buffer_data_mut` | `uint8_t *lsec_buffer_data_mut(lsec_protected_buffer_t *buf)` | Returns mutable pointer to buffer bytes. |
| `lsec_buffer_wipe` | `int32_t lsec_buffer_wipe(lsec_protected_buffer_t *buf)` | Overwrites buffer memory with zeros. |
| `lsec_buffer_free` | `void lsec_buffer_free(lsec_protected_buffer_t *buf)` | Unlocks and frees buffer memory. |

#### Vault Storage

| Function | Signature | Description |
| :--- | :--- | :--- |
| `lsec_vault_seal` | `int32_t lsec_vault_seal(const uint8_t *plain, size_t plain_len, const uint8_t *pass, size_t pass_len, uint8_t cipher_id, uint8_t **out_bytes, size_t *out_len)` | Encrypts plaintext into binary vault envelope. |
| `lsec_vault_unseal` | `int32_t lsec_vault_unseal(const uint8_t *vault, size_t vault_len, const uint8_t *pass, size_t pass_len, lsec_protected_buffer_t **out_plain)` | Decrypts vault envelope into protected buffer. |
| `lsec_vault_seal_to_file` | `int32_t lsec_vault_seal_to_file(const char *path, const uint8_t *plain, size_t plain_len, const uint8_t *pass, size_t pass_len, uint8_t cipher_id)` | Atomically seals payload to disk with `0600` permissions. |
| `lsec_vault_unseal_from_file` | `int32_t lsec_vault_unseal_from_file(const char *path, const uint8_t *pass, size_t pass_len, lsec_protected_buffer_t **out_plain)` | Reads and decrypts file into protected buffer. |
| `lsec_vault_bytes_free` | `void lsec_vault_bytes_free(uint8_t *bytes, size_t len)` | Deallocates byte slice returned by `lsec_vault_seal`. |

#### Time-Based Authentication

| Function | Signature | Description |
| :--- | :--- | :--- |
| `lsec_totp_decode_base32` | `int32_t lsec_totp_decode_base32(const char *base32_str, lsec_protected_buffer_t **out_buf)` | Decodes Base32 secret into protected buffer. |
| `lsec_totp_generate` | `int32_t lsec_totp_generate(const uint8_t *secret, size_t secret_len, uint64_t timestamp, uint64_t step_seconds, uint32_t digits, uint8_t algorithm_id, char *out_code, size_t out_code_capacity)` | Generates TOTP passcode for specified timestamp. |
| `lsec_totp_verify` | `int32_t lsec_totp_verify(const uint8_t *secret, size_t secret_len, const char *candidate_code, uint64_t timestamp, uint64_t step_seconds, uint32_t digits, uint8_t drift_steps, uint8_t algorithm_id, int32_t *out_is_valid)` | Verifies candidate passcode with drift tolerance. |

---

## Module: `bindings/go`

Idiomatic Go package using C-ABI bindings.

### Constants & Types

- `CipherSuite`: `CipherChaCha20Poly1305` (`1`), `CipherAES256GCM` (`2`)
- `TotpAlgorithm`: `TotpSha1` (`0`), `TotpSha256` (`1`), `TotpSha512` (`2`)
- `Buffer`: Opaque pointer wrapper with `runtime.SetFinalizer` auto-reclaim and `runtime.KeepAlive` safety.

### Functions

| Function / Method | Signature | Description |
| :--- | :--- | :--- |
| `Version` | `func Version() (major, minor, patch uint32)` | Returns library version numbers. |
| `NewBuffer` | `func NewBuffer(data []byte) (*Buffer, error)` | Allocates locked buffer with initial data. |
| `NewZeroedBuffer` | `func NewZeroedBuffer(length int) (*Buffer, error)` | Allocates zero-filled locked buffer. |
| `(*Buffer).Len` | `func (b *Buffer) Len() int` | Returns buffer byte count. |
| `(*Buffer).Bytes` | `func (b *Buffer) Bytes() []byte` | Returns copy of protected memory. |
| `(*Buffer).Wipe` | `func (b *Buffer) Wipe() error` | Zeroizes buffer contents immediately. |
| `(*Buffer).Free` | `func (b *Buffer) Free()` | Unlocks and frees memory, unregistering finalizer. |
| `Seal` | `func Seal(plaintext, passphrase []byte, cipher CipherSuite) ([]byte, error)` | Encrypts payload into binary envelope bytes. |
| `Unseal` | `func Unseal(vaultBytes, passphrase []byte) (*Buffer, error)` | Decrypts binary envelope into a protected buffer. |
| `SealToFile` | `func SealToFile(path string, plaintext, passphrase []byte, cipher CipherSuite) error` | Atomically writes vault container with `0600` permissions. |
| `UnsealFromFile` | `func UnsealFromFile(path string, passphrase []byte) (*Buffer, error)` | Reads and decrypts file into a protected buffer. |
| `TOTPDecodeBase32` | `func TOTPDecodeBase32(base32Secret string) (*Buffer, error)` | Decodes Base32 secret string into protected buffer. |
| `TOTPGenerateCode` | `func TOTPGenerateCode(secret []byte, timestamp, stepSeconds uint64, digits uint32, algo TotpAlgorithm) (string, error)` | Generates TOTP code for timestamp. |
| `TOTPVerifyCode` | `func TOTPVerifyCode(secret []byte, candidate string, timestamp, stepSeconds uint64, digits uint32, driftSteps uint8, algo TotpAlgorithm) (bool, error)` | Verifies passcode across drift window. |

---

## Module: `bindings/js`

Zero-dependency JavaScript and TypeScript SDK for Node.js, browsers and offline web apps.

### Lifecycle & Introspection

| Function | Signature | Description |
| :--- | :--- | :--- |
| `init` | `async function init(wasmSource?: BufferSource \| Response): Promise<void>` | Compiles and initializes WebAssembly runtime module. |
| `version` | `function version(): { major: number, minor: number, patch: number }` | Returns loaded Wasm binary version numbers. |

### Classes & Methods

| Class / Method | Signature | Description |
| :--- | :--- | :--- |
| `new Buffer` | `constructor(data: Uint8Array \| number)` | Allocates locked buffer with initial data or zero length. |
| `Buffer.prototype.length` | `get length(): number` | Returns byte length of allocated buffer. |
| `Buffer.prototype.bytes` | `get bytes(): Uint8Array` | Returns copy of buffer contents. |
| `Buffer.prototype.wipe` | `wipe(): void` | Overwrites buffer memory with zeros. |
| `Buffer.prototype.free` | `free(): void` | Deallocates Wasm linear memory buffer. |
| `Vault.seal` | `static seal(plaintext: Uint8Array, passphrase: Uint8Array, cipher?: number): Uint8Array` | Encrypts plaintext into binary vault envelope. |
| `Vault.unseal` | `static unseal(vaultBytes: Uint8Array, passphrase: Uint8Array): Buffer` | Decrypts vault envelope into protected buffer. |
| `TOTP.decodeBase32` | `static decodeBase32(base32Str: string): Buffer` | Decodes Base32 secret into protected buffer. |
| `TOTP.generate` | `static generate(secret: Uint8Array, timestamp?: number, stepSeconds?: number, digits?: number, algorithm?: number): string` | Generates TOTP passcode string. |
| `TOTP.verify` | `static verify(secret: Uint8Array, candidateCode: string, timestamp?: number, stepSeconds?: number, digits?: number, driftSteps?: number, algorithm?: number): boolean` | Verifies candidate passcode with drift tolerance. |
