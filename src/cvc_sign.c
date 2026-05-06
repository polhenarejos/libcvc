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
 * libcvc - signing helpers
 */

#include "cvc.h"

#include <string.h>
#include "mbedtls/ecp.h"
#include "mbedtls/asn1.h"
#include "mbedtls/rsa.h"
#if defined(MBEDTLS_EDDSA_C)
#include "mbedtls/eddsa.h"
#endif

static int hash_for_sign(mbedtls_md_type_t md_alg, const uint8_t *data, size_t data_len, uint8_t *hash, size_t *hash_len) {
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_alg);
    if (md_info == NULL || data == NULL || hash == NULL || hash_len == NULL) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    *hash_len = mbedtls_md_get_size(md_info);
    if (*hash_len == 0 || *hash_len > 64) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    if (mbedtls_md(md_info, data, data_len, hash) != 0) {
        return LIBCVC_ERR_CRYPTO;
    }
    return LIBCVC_OK;
}

static int ecdsa_der_to_raw_rs(const unsigned char *der, size_t der_len, const mbedtls_ecp_group *grp, uint8_t *out, size_t out_cap, size_t *out_len) {
    unsigned char *p = (unsigned char *)der;
    const unsigned char *end = der + der_len;
    size_t seq_len = 0;
    mbedtls_mpi r, s;
    size_t nbytes = (grp->pbits + 7u) / 8u;
    int rc = LIBCVC_ERR_FORMAT;

    if (out == NULL || out_len == NULL || grp == NULL || nbytes == 0 || out_cap < 2 * nbytes) {
        return LIBCVC_ERR_INVALID_ARG;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (mbedtls_asn1_get_tag(&p, end, &seq_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0 || p + seq_len != end) {
        goto cleanup;
    }
    if (mbedtls_asn1_get_mpi(&p, end, &r) != 0 || mbedtls_asn1_get_mpi(&p, end, &s) != 0 || p != end) {
        goto cleanup;
    }
    if (mbedtls_mpi_write_binary(&r, out, nbytes) != 0 || mbedtls_mpi_write_binary(&s, out + nbytes, nbytes) != 0) {
        goto cleanup;
    }
    *out_len = 2 * nbytes;
    rc = LIBCVC_OK;

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return rc;
}

int cvc_sign_data_mbedtls_pk(const mbedtls_pk_context *pk,
                             mbedtls_md_type_t md_alg,
                             const uint8_t *data, size_t data_len,
                             uint8_t *sig, size_t sig_cap, size_t *sig_len,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
    uint8_t hash[64];
    size_t hash_len = 0;
    mbedtls_pk_context pk_mut;
    int ret = -1;

    if (pk == NULL || data == NULL || sig == NULL || sig_len == NULL || f_rng == NULL) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    *sig_len = 0;
    if (hash_for_sign(md_alg, data, data_len, hash, &hash_len) != LIBCVC_OK) {
        return LIBCVC_ERR_INVALID_ARG;
    }

    memcpy(&pk_mut, pk, sizeof(pk_mut));
    mbedtls_pk_type_t t = mbedtls_pk_get_type(&pk_mut);
    if (t == MBEDTLS_PK_RSA) {
        size_t olen = 0;
        ret = mbedtls_pk_sign(&pk_mut, md_alg, hash, hash_len, sig, sig_cap, &olen, f_rng, p_rng);
        if (ret != 0) {
            return LIBCVC_ERR_CRYPTO;
        }
        *sig_len = olen;
        return LIBCVC_OK;
    }
    if (t == MBEDTLS_PK_ECKEY || t == MBEDTLS_PK_ECDSA) {
        mbedtls_ecp_keypair *ec = mbedtls_pk_ec(pk_mut);
        if (ec == NULL) {
            return LIBCVC_ERR_INVALID_ARG;
        }
        mbedtls_ecp_group grp;
        mbedtls_ecp_point q;
        mbedtls_ecp_group_init(&grp);
        mbedtls_ecp_point_init(&q);
        if (mbedtls_ecp_export(ec, &grp, NULL, &q) != 0) {
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&q);
            return LIBCVC_ERR_INVALID_ARG;
        }
        mbedtls_ecp_curve_type ctype = mbedtls_ecp_get_type(&grp);
        if (ctype == MBEDTLS_ECP_TYPE_MONTGOMERY) {
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&q);
            return LIBCVC_ERR_UNSUPPORTED;
        }
#if defined(MBEDTLS_EDDSA_C)
        if (ctype == MBEDTLS_ECP_TYPE_EDWARDS) {
            size_t olen = 0;
            ret = mbedtls_eddsa_write_signature(ec, hash, hash_len, sig, sig_cap, &olen, MBEDTLS_EDDSA_PURE, NULL, 0, f_rng, p_rng);
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&q);
            if (ret != 0) {
                return LIBCVC_ERR_CRYPTO;
            }
            *sig_len = olen;
            return LIBCVC_OK;
        }
#endif
        {
            unsigned char der_sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
            size_t der_len = 0;
            ret = mbedtls_pk_sign(&pk_mut, md_alg, hash, hash_len, der_sig, sizeof(der_sig), &der_len, f_rng, p_rng);
            if (ret != 0) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return LIBCVC_ERR_CRYPTO;
            }
            ret = ecdsa_der_to_raw_rs(der_sig, der_len, &grp, sig, sig_cap, sig_len);
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&q);
            if (ret != LIBCVC_OK) {
                return ret;
            }
            return LIBCVC_OK;
        }
    }
    return LIBCVC_ERR_UNSUPPORTED;
}

int cvc_build_and_sign_cert(const cvc_cert_meta_t *meta,
                            const mbedtls_pk_context *subject_pk,
                            const uint8_t *alg_oid, uint16_t alg_oid_len,
                            const mbedtls_pk_context *issuer_signing_key,
                            mbedtls_md_type_t md_alg,
                            uint8_t *out, uint16_t out_cap, uint16_t *out_len,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
    cvc_write_cert ctx;

    if (meta == NULL || subject_pk == NULL || issuer_signing_key == NULL || out == NULL || out_len == NULL) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    *out_len = 0;
    cvc_write_cert_init(&ctx);
    ctx.meta = *meta;
    ctx.meta.include_role_and_validity = true;
    ctx.md_alg = md_alg;
    ctx.subject_pk = subject_pk;
    ctx.issuer_pk = issuer_signing_key;
    ctx.alg_oid = alg_oid;
    ctx.alg_oid_len = alg_oid_len;
    return cvc_write_cert_der(&ctx, out, out_cap, out_len, f_rng, p_rng);
}

int cvc_build_and_sign_request(const cvc_cert_meta_t *meta,
                               const mbedtls_pk_context *subject_pk,
                               const uint8_t *alg_oid, uint16_t alg_oid_len,
                               const mbedtls_pk_context *subject_signing_key,
                               mbedtls_md_type_t md_alg,
                               const uint8_t *outer_car, uint16_t outer_car_len,
                               const mbedtls_pk_context *outer_signing_key,
                               uint8_t *out, uint16_t out_cap, uint16_t *out_len,
                               int (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
    cvc_write_req ctx;

    if (meta == NULL || subject_pk == NULL || subject_signing_key == NULL || out == NULL || out_len == NULL) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    *out_len = 0;
    cvc_write_req_init(&ctx);
    ctx.cert.meta = *meta;
    ctx.cert.meta.include_role_and_validity = false;
    ctx.cert.md_alg = md_alg;
    ctx.cert.subject_pk = subject_pk;
    ctx.cert.issuer_pk = subject_signing_key;
    ctx.cert.alg_oid = alg_oid;
    ctx.cert.alg_oid_len = alg_oid_len;

    if (outer_car != NULL && outer_car_len > 0 && outer_signing_key != NULL) {
        if (outer_car_len > sizeof(ctx.outer_car_buf)) {
            return LIBCVC_ERR_INVALID_ARG;
        }
        memcpy(ctx.outer_car_buf, outer_car, outer_car_len);
        ctx.outer_car_len = outer_car_len;
        ctx.outer_signing_key = outer_signing_key;
    }
    return cvc_write_req_der(&ctx, out, out_cap, out_len, f_rng, p_rng);
}
