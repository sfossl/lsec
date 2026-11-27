#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "lsec.h"

static void test_versions(void) {
    assert(lsec_version_major() == 0);
    assert(lsec_version_minor() == 3);
    assert(lsec_version_patch() == 0);
    printf("c-abi: version checks passed\n");
}

static void test_memguard(void) {
    const uint8_t secret[] = "super-secret-c-payload";
    size_t len = sizeof(secret) - 1;
    lsec_protected_buffer_t *buf = NULL;

    int32_t status = lsec_buffer_new(secret, len, &buf);
    assert(status == LSEC_OK);
    assert(buf != NULL);
    assert(lsec_buffer_len(buf) == len);

    const uint8_t *data = lsec_buffer_data(buf);
    assert(memcmp(data, secret, len) == 0);

    status = lsec_buffer_wipe(buf);
    assert(status == LSEC_OK);

    for (size_t i = 0; i < len; i++) {
        assert(data[i] == 0);
    }

    lsec_buffer_free(buf);
    printf("c-abi: memguard lifecycle passed\n");
}

static void test_vault(void) {
    const uint8_t plain[] = "database-master-encryption-key";
    size_t plain_len = sizeof(plain) - 1;
    const uint8_t pass[] = "passphrase-for-c-test";
    size_t pass_len = sizeof(pass) - 1;

    uint8_t *out_bytes = NULL;
    size_t out_len = 0;

    int32_t status = lsec_vault_seal(
        plain, plain_len,
        pass, pass_len,
        LSEC_CIPHER_CHACHA20_POLY1305,
        &out_bytes, &out_len
    );
    assert(status == LSEC_OK);
    assert(out_bytes != NULL);
    assert(out_len > plain_len);

    lsec_protected_buffer_t *unsealed = NULL;
    status = lsec_vault_unseal(out_bytes, out_len, pass, pass_len, &unsealed);
    assert(status == LSEC_OK);
    assert(unsealed != NULL);
    assert(lsec_buffer_len(unsealed) == plain_len);
    assert(memcmp(lsec_buffer_data(unsealed), plain, plain_len) == 0);

    lsec_vault_bytes_free(out_bytes, out_len);
    lsec_buffer_free(unsealed);
    printf("c-abi: vault seal/unseal passed\n");
}

static void test_totp(void) {
    const char *base32_seed = "JBSWY3DPEHPK3PXP";
    lsec_protected_buffer_t *seed_buf = NULL;

    int32_t status = lsec_totp_decode_base32(base32_seed, &seed_buf);
    assert(status == LSEC_OK);
    assert(seed_buf != NULL);

    char code[16] = {0};
    uint64_t timestamp = 1234567890;

    status = lsec_totp_generate(
        lsec_buffer_data(seed_buf),
        lsec_buffer_len(seed_buf),
        timestamp,
        30,
        6,
        LSEC_TOTP_ALGO_SHA1,
        code,
        sizeof(code)
    );
    assert(status == LSEC_OK);
    assert(strlen(code) == 6);

    int32_t is_valid = 0;
    status = lsec_totp_verify(
        lsec_buffer_data(seed_buf),
        lsec_buffer_len(seed_buf),
        code,
        timestamp,
        30,
        6,
        1,
        LSEC_TOTP_ALGO_SHA1,
        &is_valid
    );
    assert(status == LSEC_OK);
    assert(is_valid == 1);

    lsec_buffer_free(seed_buf);
    printf("c-abi: totp decode, generate, verify passed (code: %s)\n", code);
}

static void test_multi_vault(void) {
    const uint8_t payload[] = "c-abi-multi-vault-payload";
    size_t payload_len = sizeof(payload) - 1;
    const uint8_t pass0[] = "primary-passphrase";
    size_t pass0_len = sizeof(pass0) - 1;
    const uint8_t pass1[] = "secondary-passphrase";
    size_t pass1_len = sizeof(pass1) - 1;

    uint8_t *container = NULL;
    size_t container_len = 0;

    int32_t status = lsec_multi_vault_create(
        payload, payload_len,
        pass0, pass0_len,
        LSEC_CIPHER_CHACHA20_POLY1305,
        &container, &container_len
    );
    assert(status == LSEC_OK);
    assert(container != NULL);
    assert(container_len >= 367);

    uint8_t active[4] = {0};
    status = lsec_multi_vault_active_slots(container, container_len, active, sizeof(active));
    assert(status == LSEC_OK);
    assert(active[0] == 1 && active[1] == 0 && active[2] == 0 && active[3] == 0);

    size_t slot_idx = 0;
    status = lsec_multi_vault_add_slot(
        container, container_len,
        pass0, pass0_len,
        pass1, pass1_len,
        LSEC_CIPHER_AES256_GCM,
        &slot_idx
    );
    assert(status == LSEC_OK);
    assert(slot_idx == 1);

    lsec_protected_buffer_t *opened = NULL;
    status = lsec_multi_vault_open(container, container_len, pass1, pass1_len, &opened);
    assert(status == LSEC_OK);
    assert(lsec_buffer_len(opened) == payload_len);
    assert(memcmp(lsec_buffer_data(opened), payload, payload_len) == 0);
    lsec_buffer_free(opened);

    const uint8_t updated_payload[] = "updated-c-abi-payload";
    size_t updated_payload_len = sizeof(updated_payload) - 1;
    uint8_t *updated = NULL;
    size_t updated_len = 0;
    status = lsec_multi_vault_update_payload(
        container, container_len,
        pass0, pass0_len,
        updated_payload, updated_payload_len,
        &updated, &updated_len
    );
    assert(status == LSEC_OK);
    assert(updated != NULL);

    status = lsec_multi_vault_remove_slot(updated, updated_len, pass0, pass0_len, 1);
    assert(status == LSEC_OK);

    lsec_protected_buffer_t *removed_open = NULL;
    status = lsec_multi_vault_open(updated, updated_len, pass1, pass1_len, &removed_open);
    assert(status == LSEC_ERR_CRYPTO_FAILED);
    assert(removed_open == NULL);

    lsec_vault_bytes_free(container, container_len);
    lsec_vault_bytes_free(updated, updated_len);
    printf("c-abi: multi-vault lifecycle passed\n");
}

static void test_error_paths(void) {
    assert(lsec_buffer_new(NULL, 10, NULL) == LSEC_ERR_NULL_POINTER);

    uint8_t *out_bytes = NULL;
    size_t out_len = 0;
    assert(lsec_vault_seal(NULL, 10, NULL, 0, LSEC_CIPHER_CHACHA20_POLY1305, &out_bytes, &out_len) == LSEC_ERR_NULL_POINTER);
    assert(lsec_vault_seal((const uint8_t *)"x", 1, (const uint8_t *)"p", 1, 99, &out_bytes, &out_len) == LSEC_ERR_INVALID_PARAM);

    char small_code[6] = {0};
    const uint8_t secret[] = "1234567890";
    assert(lsec_totp_generate(secret, sizeof(secret) - 1, 1234567890, 30, 6, LSEC_TOTP_ALGO_SHA1, small_code, sizeof(small_code)) == LSEC_ERR_BUFFER_TOO_SMALL);
    printf("c-abi: error-path checks passed\n");
}

int main(void) {
    test_versions();
    test_memguard();
    test_vault();
    test_totp();
    test_multi_vault();
    test_error_paths();
    printf("all c-abi integration tests passed successfully.\n");
    return 0;
}

