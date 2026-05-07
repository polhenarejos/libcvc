#include "cvc.h"
#include "cvc_oids.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

static int write_file(const char *path, const unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    if (fwrite(buf, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode) ? 0 : -1;
    }
    if (mkdir(path, 0755) == 0) {
        return 0;
    }
    return (errno == EEXIST) ? 0 : -1;
}

int main(void) {
    int rc;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    cvc_write_cert w;
    unsigned char cert[2048];
    uint16_t cert_len = 0;
    unsigned char key_pem[1600];

    static const uint8_t car[] = "ZZATCVCA10000";
    static const uint8_t chr[] = "ZZATCVCA10000";
    static const uint8_t valid_from[] = {2, 6, 0, 5, 0, 7}; /* 2026-05-07 -> YYMMDD */
    static const uint8_t valid_to[] = {2, 7, 0, 5, 0, 7};   /* 2027-05-07 -> YYMMDD */
    static const uint8_t chat[] = {
        0x06, 0x09, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x03, 0x01, 0x02, 0x02,
        0x53, 0x05, 0xC0, 0x00, 0x00, 0x00, 0x04
    };

    mbedtls_pk_init(&key);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);

    rc = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *)"libcvc-gen", 10);
    if (rc != 0) {
        fprintf(stderr, "mbedtls_ctr_drbg_seed failed: %d\n", rc);
        return 1;
    }

    rc = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (rc != 0) {
        fprintf(stderr, "mbedtls_pk_setup failed: %d\n", rc);
        return 1;
    }

    rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key),
                             mbedtls_ctr_drbg_random, &drbg);
    if (rc != 0) {
        fprintf(stderr, "mbedtls_ecp_gen_key failed: %d\n", rc);
        return 1;
    }

    memset(key_pem, 0, sizeof(key_pem));
    rc = mbedtls_pk_write_key_pem(&key, key_pem, sizeof(key_pem));
    if (rc != 0) {
        fprintf(stderr, "mbedtls_pk_write_key_pem failed: %d\n", rc);
        return 1;
    }

    cvc_write_cert_init(&w);
    cvc_write_set_subject_key(&w, &key);
    cvc_write_set_issuer_key(&w, &key); /* self-signed */
    cvc_write_set_algorithm_oid(&w,
                                (const uint8_t *)OID_ID_TA_ECDSA_SHA_256,
                                (uint16_t)(sizeof(OID_ID_TA_ECDSA_SHA_256) - 1u));
    cvc_write_set_md(&w, MBEDTLS_MD_SHA256);
    cvc_write_set_car(&w, car, (uint16_t)(sizeof(car) - 1u));
    cvc_write_set_chr(&w, chr, (uint16_t)(sizeof(chr) - 1u));
    cvc_write_set_chat(&w, chat, (uint16_t)sizeof(chat));
    cvc_write_set_validity(&w, valid_from, sizeof(valid_from), valid_to, sizeof(valid_to));
    cvc_write_set_include_ec_domain_parameters(&w, true);
    cvc_write_set_strict_profile(&w, true);

    rc = cvc_write_cert_der(&w, cert, sizeof(cert), &cert_len,
                            mbedtls_ctr_drbg_random, &drbg);
    if (rc != 0) {
        fprintf(stderr, "cvc_write_cert_der failed: %d\n", rc);
        return 1;
    }

    if (ensure_dir("tests") != 0 || ensure_dir("tests/generated") != 0) {
        fprintf(stderr, "creating output directory tests/generated failed\n");
        return 1;
    }

    if (write_file("tests/generated/LIBCVC_CVCA10000.cvcert", cert, cert_len) != 0) {
        fprintf(stderr, "writing certificate failed\n");
        return 1;
    }
    if (write_file("tests/generated/LIBCVC_CVCA10000.key.pem", key_pem, strlen((const char *)key_pem)) != 0) {
        fprintf(stderr, "writing key failed\n");
        return 1;
    }

    printf("Generated tests/generated/LIBCVC_CVCA10000.cvcert (%u bytes)\n", cert_len);
    printf("Generated tests/generated/LIBCVC_CVCA10000.key.pem\n");

    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return 0;
}
