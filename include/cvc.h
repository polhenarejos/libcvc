/*
 * This file is part of the libcvc distribution (https://github.com/polhenarejos/libcvc).
 * Copyright (c) 2026 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * libcvc - compact CVC parser helpers
 * Copyright (c) 2026 Pol Henarejos
 *
 * Licensed under the GNU Affero General Public License v3.0.
 */

#ifndef LIBCVC_CVC_H
#define LIBCVC_CVC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cvc_status.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"

#ifdef __cplusplus
extern "C" {
#endif

const uint8_t *cvc_get_field(const uint8_t *data, uint16_t len, uint16_t *olen, uint16_t tag);
const uint8_t *cvc_get_body(const uint8_t *data, uint16_t len, uint16_t *olen);
const uint8_t *cvc_get_sig(const uint8_t *data, uint16_t len, uint16_t *olen);
const uint8_t *cvc_get_car(const uint8_t *data, uint16_t len, uint16_t *olen);
const uint8_t *cvc_get_chr(const uint8_t *data, uint16_t len, uint16_t *olen);
const uint8_t *cvc_get_pub(const uint8_t *data, uint16_t len, uint16_t *olen);
const uint8_t *cvc_get_ext(const uint8_t *data, uint16_t len, uint16_t *olen);

typedef enum {
    CVC_KEY_KIND_UNKNOWN = 0,
    CVC_KEY_KIND_RSA,
    CVC_KEY_KIND_EC
} cvc_key_kind_t;

typedef struct {
    cvc_key_kind_t kind;
    /* Raw pointers into source buffer. */
    const uint8_t *n;
    uint16_t n_len;
    const uint8_t *e;
    uint16_t e_len;
    const uint8_t *q;
    uint16_t q_len;
    const uint8_t *alg_oid;
    uint16_t alg_oid_len;
} cvc_pubkey_t;

typedef struct {
    const uint8_t *car;
    uint16_t car_len;
    const uint8_t *chr;
    uint16_t chr_len;
    const uint8_t *chat;
    uint16_t chat_len;
    const uint8_t *valid_from; /* YYMMDD or custom 6-byte date representation */
    uint16_t valid_from_len;   /* Usually 6 */
    const uint8_t *valid_to;   /* YYMMDD or custom 6-byte date representation */
    uint16_t valid_to_len;     /* Usually 6 */
    const uint8_t *ext;
    uint16_t ext_len;
    bool include_role_and_validity;
} cvc_cert_meta_t;

typedef enum {
    CVC_DOMAIN_PARAMS_ALLOW = 0,
    CVC_DOMAIN_PARAMS_REQUIRE,
    CVC_DOMAIN_PARAMS_FORBID
} cvc_domain_params_policy_t;

/* Parse and classify public key template (0x7F49). */
int cvc_parse_pubkey_template(const uint8_t *pub_tmpl, uint16_t pub_tmpl_len, cvc_pubkey_t *out);

/* Extract public key template from cert/request and classify it. */
int cvc_extract_pubkey(const uint8_t *cert, uint16_t cert_len, cvc_pubkey_t *out);

/* Extract EC public key bytes (typically tag 0x86, RI ECDH may use 0x84)
 * and optionally compress if uncompressed SEC1 is provided.
 * Returns 0 on success.
 */
int cvc_extract_ec_point(const uint8_t *cert, uint16_t cert_len, uint8_t *out, uint16_t out_cap, uint16_t *out_len, bool prefer_compressed);

/* Parse extensions (0x65) and find a DDT (0x73) by OID (0x06).
 * On success, ext_data/ext_data_len point to the extension payload after OID TLV.
 */
int cvc_extension_find_by_oid(const uint8_t *cert,
                              uint16_t cert_len,
                              const uint8_t *oid_der,
                              uint16_t oid_der_len,
                              const uint8_t **ext_data,
                              uint16_t *ext_data_len);

/* Convert dotted OID string (e.g. \"1.3.6.1.4.1\") to DER bytes. */
int cvc_oid_from_dotted_string(const char *oid_str,
                               uint8_t *out,
                               uint16_t out_cap,
                               uint16_t *out_len);

/* Build 0x7F49 public key template from mbedtls key context.
 * alg_oid is copied into tag 0x06.
 * Returns total bytes written, 0 on error/insufficient buffer.
 */
uint16_t cvc_build_pubkey_template(const mbedtls_pk_context *pk, const uint8_t *alg_oid, uint16_t alg_oid_len, uint8_t *out, uint16_t out_cap);
uint16_t cvc_build_pubkey_template_ex(const mbedtls_pk_context *pk,
                                      const uint8_t *alg_oid, uint16_t alg_oid_len,
                                      bool include_ec_domain_parameters,
                                      uint8_t *out, uint16_t out_cap);

/* Build certificate body (0x7F4E). */
uint16_t cvc_build_cert_body(const cvc_cert_meta_t *meta, const uint8_t *pub_tmpl, uint16_t pub_tmpl_len, uint8_t *out, uint16_t out_cap);

/* Wrap body + signature into certificate (0x7F21). */
uint16_t cvc_build_cert(const uint8_t *body, uint16_t body_len, const uint8_t *sig, uint16_t sig_len, uint8_t *out, uint16_t out_cap);

/* Build request wrapper (0x67) containing certificate, outer CAR and outer signature. */
uint16_t cvc_build_request(const uint8_t *cert, uint16_t cert_len, const uint8_t *outer_car, uint16_t outer_car_len, const uint8_t *outer_sig, uint16_t outer_sig_len, uint8_t *out, uint16_t out_cap);

/* Sign arbitrary data for CVC using mbedtls PK.
 * RSA: raw PKCS#1/PKCS#1-PSS signature output as returned by PK.
 * Weierstrass ECDSA: raw r||s.
 * Edwards: raw EdDSA signature (if MBEDTLS_EDDSA_C enabled).
 * Montgomery: unsupported for signatures.
 */
int cvc_sign_data_mbedtls_pk(const mbedtls_pk_context *pk,
                             mbedtls_md_type_t md_alg,
                             const uint8_t *data, size_t data_len,
                             uint8_t *sig, size_t sig_cap, size_t *sig_len,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

/* Verify certificate inner signature over encoded certificate body TLV. */
int cvc_verify_cert_signature(const uint8_t *cert,
                              uint16_t cert_len,
                              const mbedtls_pk_context *signer_pk,
                              mbedtls_md_type_t md_alg);

/* Verify request signatures:
 * - inner signature: cert body signed by inner_pk
 * - outer signature (optional): signature over encoded cert TLV || encoded CAR TLV by outer_pk
 * If require_outer is true, missing outer signature is an error.
 */
int cvc_verify_request_signatures(const uint8_t *req,
                                  uint16_t req_len,
                                  const mbedtls_pk_context *inner_pk,
                                  const mbedtls_pk_context *outer_pk,
                                  mbedtls_md_type_t md_alg,
                                  bool require_outer);

/* High-level helpers that enforce TR-03110 profile structures. */
int cvc_build_and_sign_cert(const cvc_cert_meta_t *meta,
                            const mbedtls_pk_context *subject_pk,
                            const uint8_t *alg_oid, uint16_t alg_oid_len,
                            const mbedtls_pk_context *issuer_signing_key,
                            mbedtls_md_type_t md_alg,
                            uint8_t *out, uint16_t out_cap, uint16_t *out_len,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int cvc_build_and_sign_request(const cvc_cert_meta_t *meta,
                               const mbedtls_pk_context *subject_pk,
                               const uint8_t *alg_oid, uint16_t alg_oid_len,
                               const mbedtls_pk_context *subject_signing_key,
                               mbedtls_md_type_t md_alg,
                               const uint8_t *outer_car, uint16_t outer_car_len,
                               const mbedtls_pk_context *outer_signing_key, /* optional */
                               uint8_t *out, uint16_t out_cap, uint16_t *out_len,
                               int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

typedef struct {
    cvc_cert_meta_t meta;
    const mbedtls_pk_context *subject_pk;
    const mbedtls_pk_context *issuer_pk;
    const uint8_t *alg_oid;
    uint16_t alg_oid_len;
    mbedtls_md_type_t md_alg;
    bool include_ec_domain_parameters;
    bool strict_profile;
    cvc_domain_params_policy_t domain_params_policy;

    uint8_t car_buf[64];
    uint8_t chr_buf[64];
    uint8_t chat_buf[128];
    uint8_t valid_from_buf[16];
    uint8_t valid_to_buf[16];
    uint8_t ext_buf[512];
    uint16_t ext_len;
} cvc_write_cert;

typedef struct {
    cvc_write_cert cert;
    const mbedtls_pk_context *outer_signing_key;
    uint8_t outer_car_buf[64];
    uint16_t outer_car_len;
} cvc_write_req;

void cvc_write_cert_init(cvc_write_cert *ctx);
void cvc_write_req_init(cvc_write_req *ctx);

int cvc_write_set_subject_key(cvc_write_cert *ctx, const mbedtls_pk_context *subject_key);
int cvc_write_set_issuer_key(cvc_write_cert *ctx, const mbedtls_pk_context *issuer_key);
int cvc_write_set_algorithm_oid(cvc_write_cert *ctx, const uint8_t *alg_oid, uint16_t alg_oid_len);
int cvc_write_set_md(cvc_write_cert *ctx, mbedtls_md_type_t md_alg);
int cvc_write_set_car(cvc_write_cert *ctx, const uint8_t *car, uint16_t car_len);
int cvc_write_set_chr(cvc_write_cert *ctx, const uint8_t *chr, uint16_t chr_len);
int cvc_write_set_chat(cvc_write_cert *ctx, const uint8_t *chat, uint16_t chat_len);
int cvc_write_set_validity(cvc_write_cert *ctx, const uint8_t *valid_from, uint16_t valid_from_len, const uint8_t *valid_to, uint16_t valid_to_len);
int cvc_write_append_extension(cvc_write_cert *ctx, const uint8_t *oid, uint16_t oid_len, const uint8_t *ctx_specific_tlvs, uint16_t ctx_specific_tlvs_len);
int cvc_write_set_include_ec_domain_parameters(cvc_write_cert *ctx, bool enable);
int cvc_write_set_strict_profile(cvc_write_cert *ctx, bool enable);
int cvc_write_set_domain_params_policy(cvc_write_cert *ctx, cvc_domain_params_policy_t policy);
int cvc_write_cert_der(cvc_write_cert *ctx, uint8_t *out, uint16_t out_cap, uint16_t *out_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int cvc_req_set_outer_car(cvc_write_req *ctx, const uint8_t *car, uint16_t car_len);
int cvc_req_set_outer_signing_key(cvc_write_req *ctx, const mbedtls_pk_context *outer_key);
int cvc_write_req_der(cvc_write_req *ctx, uint8_t *out, uint16_t out_cap, uint16_t *out_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

#ifdef __cplusplus
}
#endif

#endif /* LIBCVC_CVC_H */
