#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "lsec.h"

static void test_versions(void) {
    assert(lsec_version_major() == 0);
    assert(lsec_version_minor() == 1);
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

int main(void) {
    test_versions();
    test_memguard();
    test_vault();
    test_totp();
    printf("all c-abi integration tests passed successfully.\n");
    return 0;
}

