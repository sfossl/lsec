#ifndef LSEC_H
#define LSEC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* return codes */
#define LSEC_OK                    0
#define LSEC_ERR_NULL_POINTER     -1
#define LSEC_ERR_BUFFER_TOO_SMALL -2
#define LSEC_ERR_INVALID_PARAM    -3
#define LSEC_ERR_ALLOC_FAILED     -4
#define LSEC_ERR_LOCK_FAILED      -5
#define LSEC_ERR_CRYPTO_FAILED    -6
#define LSEC_ERR_VAULT_CORRUPT    -7
#define LSEC_ERR_IO_FAILED        -8
#define LSEC_ERR_TOTP_FAILED      -9
#define LSEC_ERR_PANIC            -10

/* cipher suites */
#define LSEC_CIPHER_CHACHA20_POLY1305 1
#define LSEC_CIPHER_AES256_GCM        2

/* totp hash algorithms */
#define LSEC_TOTP_ALGO_SHA1   0
#define LSEC_TOTP_ALGO_SHA256 1
#define LSEC_TOTP_ALGO_SHA512 2

/* process isolation and hardening */
int32_t lsec_process_harden(void);

/* opaque handle to protected memory buffer */
typedef struct LsecProtectedBuffer lsec_protected_buffer_t;

/* version information */
uint32_t lsec_version_major(void);
uint32_t lsec_version_minor(void);
uint32_t lsec_version_patch(void);

/* memory guard functions */
int32_t lsec_buffer_new(const uint8_t *data, size_t len, lsec_protected_buffer_t **out_buf);
int32_t lsec_buffer_zeroed(size_t len, lsec_protected_buffer_t **out_buf);
size_t lsec_buffer_len(const lsec_protected_buffer_t *buf);
const uint8_t *lsec_buffer_data(const lsec_protected_buffer_t *buf);
uint8_t *lsec_buffer_data_mut(lsec_protected_buffer_t *buf);
int32_t lsec_buffer_wipe(lsec_protected_buffer_t *buf);
void lsec_buffer_free(lsec_protected_buffer_t *buf);

/* vault encryption and storage */
int32_t lsec_vault_seal(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *passphrase,
    size_t passphrase_len,
    uint8_t cipher_id,
    uint8_t **out_bytes,
    size_t *out_len
);

int32_t lsec_vault_unseal(
    const uint8_t *vault_bytes,
    size_t vault_len,
    const uint8_t *passphrase,
    size_t passphrase_len,
    lsec_protected_buffer_t **out_plaintext
);

int32_t lsec_vault_seal_to_file(
    const char *path,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *passphrase,
    size_t passphrase_len,
    uint8_t cipher_id
);

int32_t lsec_vault_unseal_from_file(
    const char *path,
    const uint8_t *passphrase,
    size_t passphrase_len,
    lsec_protected_buffer_t **out_plaintext
);

/* multi-slot vault operations */
int32_t lsec_multi_vault_create(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *passphrase,
    size_t passphrase_len,
    uint8_t cipher_id,
    uint8_t **out_bytes,
    size_t *out_len
);

int32_t lsec_multi_vault_open(
    const uint8_t *container,
    size_t container_len,
    const uint8_t *passphrase,
    size_t passphrase_len,
    lsec_protected_buffer_t **out_plaintext
);

int32_t lsec_multi_vault_add_slot(
    uint8_t *container,
    size_t container_len,
    const uint8_t *existing_passphrase,
    size_t existing_passphrase_len,
    const uint8_t *new_passphrase,
    size_t new_passphrase_len,
    uint8_t new_cipher_id,
    size_t *out_slot_index
);

int32_t lsec_multi_vault_remove_slot(
    uint8_t *container,
    size_t container_len,
    const uint8_t *existing_passphrase,
    size_t existing_passphrase_len,
    size_t slot_index
);

int32_t lsec_multi_vault_update_payload(
    const uint8_t *container,
    size_t container_len,
    const uint8_t *existing_passphrase,
    size_t existing_passphrase_len,
    const uint8_t *new_payload,
    size_t new_payload_len,
    uint8_t **out_bytes,
    size_t *out_len
);

int32_t lsec_multi_vault_active_slots(
    const uint8_t *container,
    size_t container_len,
    uint8_t *out_active_slots,
    size_t out_active_slots_len
);

void lsec_vault_bytes_free(uint8_t *bytes, size_t len);

/* time-based authentication (totp) */
int32_t lsec_totp_decode_base32(
    const char *base32_str,
    lsec_protected_buffer_t **out_buf
);

int32_t lsec_totp_generate(
    const uint8_t *secret,
    size_t secret_len,
    uint64_t timestamp,
    uint64_t step_seconds,
    uint32_t digits,
    uint8_t algorithm_id,
    char *out_code,
    size_t out_code_capacity
);

int32_t lsec_totp_verify(
    const uint8_t *secret,
    size_t secret_len,
    const char *candidate_code,
    uint64_t timestamp,
    uint64_t step_seconds,
    uint32_t digits,
    uint8_t drift_steps,
    uint8_t algorithm_id,
    int32_t *out_is_valid
);

#ifdef __cplusplus
}
#endif

#endif /* LSEC_H */

