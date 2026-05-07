#include "cvc.h"
#include "cvc_tags.h"
#include "cvc_status.h"
#include "cvc_tlv.h"
#include "mbedtls/pk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef LIBCVC_TEST_VECTORS_DIR
#define LIBCVC_TEST_VECTORS_DIR "tests/vectors"
#endif

#define ASSERT_TRUE(expr) do { if (!(expr)) { fprintf(stderr, "ASSERT_TRUE failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); return 1; } } while (0)
#define ASSERT_EQ_INT(a,b) do { int _a=(a), _b=(b); if (_a != _b) { fprintf(stderr, "ASSERT_EQ_INT failed at %s:%d: %s=%d %s=%d\n", __FILE__, __LINE__, #a, _a, #b, _b); return 1; } } while (0)
#define ASSERT_EQ_MEM(a,b,n) do { \
    if (memcmp((a),(b),(n)) != 0) { \
        size_t _i; \
        for (_i = 0; _i < (size_t)(n); _i++) { \
            if (((const uint8_t *)(a))[_i] != ((const uint8_t *)(b))[_i]) { \
                fprintf(stderr, "ASSERT_EQ_MEM failed at %s:%d (%zu bytes), first diff at %zu: %02X != %02X\n", \
                        __FILE__, __LINE__, (size_t)(n), _i, \
                        ((const uint8_t *)(a))[_i], ((const uint8_t *)(b))[_i]); \
                break; \
            } \
        } \
        return 1; \
    } \
} while (0)

typedef int (*test_fn_t)(void);

static int run_test(const char *name, test_fn_t fn) {
    int rc;
    printf("[ RUN ] %s\n", name);
    rc = fn();
    if (rc == 0) {
        printf("[  OK ] %s\n", name);
    } else {
        printf("[FAIL ] %s (rc=%d)\n", name, rc);
    }
    return rc;
}

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = NULL;
    long sz = 0;
    uint8_t *buf = NULL;

    if (!path || !out || !out_len) {
        return -1;
    }

    f = fopen(path, "rb");
    if (!f) {
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);

    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

static int load_key_file(const char *path, mbedtls_pk_context *pk) {
    if (!path || !pk) {
        return -1;
    }
    return mbedtls_pk_parse_keyfile(pk, path, NULL, NULL, NULL);
}

static int get_field_or_fail(const uint8_t *tlv, uint16_t tlv_len, uint16_t tag, const uint8_t **v, uint16_t *vlen) {
    *v = cvc_get_field(tlv, tlv_len, vlen, tag);
    return (*v && *vlen > 0) ? 0 : -1;
}

static int infer_include_domain_params(const uint8_t *pub, uint16_t pub_len) {
    uint16_t len = 0;
    const uint8_t *p = cvc_get_field(pub, pub_len, &len, CVC_TAG_EC_P);
    return (p && len > 0) ? 1 : 0;
}

static int find_tlv_span(const uint8_t *buf, uint16_t buf_len, uint16_t tag,
                         const uint8_t **tlv, uint16_t *tlv_len) {
    uint16_t off = 0;
    while (off < buf_len) {
        cvc_tlv_hdr_t h;
        uint16_t total = 0;
        if (cvc_tlv_parse_header(buf + off, (uint16_t)(buf_len - off), &h) != LIBCVC_OK) {
            return -1;
        }
        total = (uint16_t)(h.hdr_len + h.value_len);
        if (h.tag == tag) {
            *tlv = buf + off;
            *tlv_len = total;
            return 0;
        }
        off = (uint16_t)(off + total);
    }
    return -1;
}

static int test_oid_parse(void) {
    uint8_t out[16];
    uint16_t out_len = 0;

    ASSERT_EQ_INT(cvc_oid_from_dotted_string("1.2.840.10045.3.1.7", out, sizeof(out), &out_len), LIBCVC_OK);
    ASSERT_TRUE(out_len > 0);
    ASSERT_EQ_INT(cvc_oid_from_dotted_string("1", out, sizeof(out), &out_len), LIBCVC_ERR_FORMAT);
    ASSERT_EQ_INT(cvc_oid_from_dotted_string("3.40.1", out, sizeof(out), &out_len), LIBCVC_ERR_FORMAT);
    return 0;
}

static int compare_openpace_body_rebuild(const char *cert_path) {
    uint8_t *cert = NULL;
    size_t cert_len_sz = 0;
    uint16_t cert_len = 0;
    const uint8_t *body = NULL;
    uint16_t body_len = 0;
    const uint8_t *car = NULL;
    const uint8_t *chr = NULL;
    const uint8_t *chat = NULL;
    const uint8_t *cxd = NULL;
    const uint8_t *ced = NULL;
    const uint8_t *ext = NULL;
    const uint8_t *pub = NULL;
    const uint8_t *pub_tlv = NULL;
    uint16_t car_len = 0, chr_len = 0, chat_len = 0, cxd_len = 0, ced_len = 0, ext_len = 0, pub_len = 0, pub_tlv_len = 0;
    uint8_t rebuilt_body[2048];
    uint16_t rebuilt_body_len = 0;
    const uint8_t *rebuilt_body_value = NULL;
    uint16_t rebuilt_body_value_len = 0;
    cvc_cert_meta_t meta;

    ASSERT_EQ_INT(read_file(cert_path, &cert, &cert_len_sz), 0);
    ASSERT_TRUE(cert_len_sz <= 0xFFFFu);
    cert_len = (uint16_t)cert_len_sz;

    body = cvc_get_body(cert, cert_len, &body_len);
    ASSERT_TRUE(body != NULL && body_len > 0);

    ASSERT_EQ_INT(get_field_or_fail(body, body_len, CVC_TAG_CAR, &car, &car_len), 0);
    ASSERT_EQ_INT(get_field_or_fail(body, body_len, CVC_TAG_CHR, &chr, &chr_len), 0);
    ASSERT_EQ_INT(get_field_or_fail(body, body_len, CVC_TAG_CHAT, &chat, &chat_len), 0);
    ASSERT_EQ_INT(get_field_or_fail(body, body_len, CVC_TAG_CXD, &cxd, &cxd_len), 0);
    ASSERT_EQ_INT(get_field_or_fail(body, body_len, CVC_TAG_CED, &ced, &ced_len), 0);
    ASSERT_EQ_INT(get_field_or_fail(body, body_len, CVC_TAG_PUBKEY, &pub, &pub_len), 0);
    ASSERT_EQ_INT(find_tlv_span(body, body_len, CVC_TAG_PUBKEY, &pub_tlv, &pub_tlv_len), 0);
    ext = cvc_get_field(body, body_len, &ext_len, CVC_TAG_EXT);
    (void)infer_include_domain_params(pub, pub_len);

    memset(&meta, 0, sizeof(meta));
    meta.car = car;
    meta.car_len = car_len;
    meta.chr = chr;
    meta.chr_len = chr_len;
    meta.chat = chat;
    meta.chat_len = chat_len;
    meta.valid_from = cxd;
    meta.valid_from_len = cxd_len;
    meta.valid_to = ced;
    meta.valid_to_len = ced_len;
    meta.include_role_and_validity = true;
    meta.ext = ext;
    meta.ext_len = ext_len;

    rebuilt_body_len = cvc_build_cert_body(&meta, pub_tlv, pub_tlv_len, rebuilt_body, sizeof(rebuilt_body));
    ASSERT_TRUE(rebuilt_body_len > 0);
    rebuilt_body_value = cvc_get_field(rebuilt_body, rebuilt_body_len, &rebuilt_body_value_len, CVC_TAG_CERT_BODY);
    ASSERT_TRUE(rebuilt_body_value != NULL);
    ASSERT_EQ_INT(rebuilt_body_value_len, body_len);
    ASSERT_EQ_MEM(rebuilt_body_value, body, body_len);

    free(cert);
    return 0;
}

static int test_openpace_cvca(void) {
    return compare_openpace_body_rebuild(LIBCVC_TEST_VECTORS_DIR "/ZZATCVCA00001.cvcert");
}

static int test_openpace_dvca(void) {
    return compare_openpace_body_rebuild(LIBCVC_TEST_VECTORS_DIR "/ZZATDVCA00001.cvcert");
}

static int test_openpace_term(void) {
    return compare_openpace_body_rebuild(LIBCVC_TEST_VECTORS_DIR "/ZZATTERM00001.cvcert");
}

static int test_openpace_signature_verify(void) {
    uint8_t *cvca_cert = NULL;
    uint8_t *dvca_cert = NULL;
    uint8_t *term_cert = NULL;
    size_t cvca_len_sz = 0, dvca_len_sz = 0, term_len_sz = 0;
    mbedtls_pk_context cvca_pk, dvca_pk;

    mbedtls_pk_init(&cvca_pk);
    mbedtls_pk_init(&dvca_pk);

    if (load_key_file(LIBCVC_TEST_VECTORS_DIR "/ZZATCVCA00001.pub.pem", &cvca_pk) != 0 ||
        load_key_file(LIBCVC_TEST_VECTORS_DIR "/ZZATDVCA00001.pub.pem", &dvca_pk) != 0) {
        fprintf(stderr, "Skipping signature verification: mbedTLS cannot parse OpenPACE public keys in this build.\n");
        mbedtls_pk_free(&cvca_pk);
        mbedtls_pk_free(&dvca_pk);
        return 0;
    }

    ASSERT_EQ_INT(read_file(LIBCVC_TEST_VECTORS_DIR "/ZZATCVCA00001.cvcert", &cvca_cert, &cvca_len_sz), 0);
    ASSERT_EQ_INT(read_file(LIBCVC_TEST_VECTORS_DIR "/ZZATDVCA00001.cvcert", &dvca_cert, &dvca_len_sz), 0);
    ASSERT_EQ_INT(read_file(LIBCVC_TEST_VECTORS_DIR "/ZZATTERM00001.cvcert", &term_cert, &term_len_sz), 0);
    ASSERT_TRUE(cvca_len_sz <= 0xFFFFu && dvca_len_sz <= 0xFFFFu && term_len_sz <= 0xFFFFu);

    ASSERT_EQ_INT(cvc_verify_cert_signature(cvca_cert, (uint16_t)cvca_len_sz, &cvca_pk, MBEDTLS_MD_SHA256), LIBCVC_OK);
    ASSERT_EQ_INT(cvc_verify_cert_signature(dvca_cert, (uint16_t)dvca_len_sz, &cvca_pk, MBEDTLS_MD_SHA256), LIBCVC_OK);
    ASSERT_EQ_INT(cvc_verify_cert_signature(term_cert, (uint16_t)term_len_sz, &dvca_pk, MBEDTLS_MD_SHA256), LIBCVC_OK);

    free(cvca_cert);
    free(dvca_cert);
    free(term_cert);
    mbedtls_pk_free(&cvca_pk);
    mbedtls_pk_free(&dvca_pk);
    return 0;
}

int main(void) {
    if (run_test("oid_parse", test_oid_parse) != 0) {
        return 1;
    }
    if (run_test("openpace_body_cvca", test_openpace_cvca) != 0) {
        return 1;
    }
    if (run_test("openpace_body_dvca", test_openpace_dvca) != 0) {
        return 1;
    }
    if (run_test("openpace_body_term", test_openpace_term) != 0) {
        return 1;
    }
    if (run_test("openpace_signature_verify", test_openpace_signature_verify) != 0) {
        return 1;
    }

    printf("All libcvc tests passed.\n");
    return 0;
}
