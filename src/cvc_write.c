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

#include "cvc.h"
#include "cvc_tags.h"
#include "cvc_tlv.h"

#include <string.h>

static int cvc_is_bcd_date_6(const uint8_t *d, uint16_t len) {
    uint16_t i = 0;
    if (!d || len != 6) {
        return 0;
    }
    for (i = 0; i < 6; i++) {
        if (d[i] > 9) {
            return 0;
        }
    }
    return 1;
}

static int cvc_cmp_date_6(const uint8_t *a, const uint8_t *b) {
    uint16_t i = 0;
    for (i = 0; i < 6; i++) {
        if (a[i] < b[i]) {
            return -1;
        }
        if (a[i] > b[i]) {
            return 1;
        }
    }
    return 0;
}

static int cvc_write_validate_profile(const cvc_write_cert *ctx) {
    mbedtls_pk_type_t t;
    if (!ctx || !ctx->subject_pk) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    t = mbedtls_pk_get_type((mbedtls_pk_context *)ctx->subject_pk);
    if (ctx->domain_params_policy == CVC_DOMAIN_PARAMS_REQUIRE &&
        t != MBEDTLS_PK_RSA &&
        !ctx->include_ec_domain_parameters) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    if (ctx->domain_params_policy == CVC_DOMAIN_PARAMS_FORBID &&
        t != MBEDTLS_PK_RSA &&
        ctx->include_ec_domain_parameters) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    if (ctx->strict_profile && ctx->meta.include_role_and_validity) {
        if (!ctx->meta.valid_from || !ctx->meta.valid_to) {
            return LIBCVC_ERR_INVALID_ARG;
        }
        if (!cvc_is_bcd_date_6(ctx->meta.valid_from, ctx->meta.valid_from_len) ||
            !cvc_is_bcd_date_6(ctx->meta.valid_to, ctx->meta.valid_to_len)) {
            return LIBCVC_ERR_INVALID_ARG;
        }
        if (cvc_cmp_date_6(ctx->meta.valid_from, ctx->meta.valid_to) > 0) {
            return LIBCVC_ERR_INVALID_ARG;
        }
    }
    return LIBCVC_OK;
}

static int copy_field(uint8_t *dst, uint16_t dst_cap, uint16_t *out_len, const uint8_t *src, uint16_t src_len) {
    if (!dst || !out_len || !src || src_len == 0 || src_len > dst_cap) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    memcpy(dst, src, src_len);
    *out_len = src_len;
    return LIBCVC_OK;
}

void cvc_write_cert_init(cvc_write_cert *ctx) {
    if (!ctx) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->md_alg = MBEDTLS_MD_SHA256;
    ctx->meta.include_role_and_validity = true;
    ctx->strict_profile = false;
    ctx->domain_params_policy = CVC_DOMAIN_PARAMS_ALLOW;
}

void cvc_write_req_init(cvc_write_req *ctx) {
    if (!ctx) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    cvc_write_cert_init(&ctx->cert);
    ctx->cert.meta.include_role_and_validity = false;
    ctx->cert.include_ec_domain_parameters = true;
}

int cvc_write_set_subject_key(cvc_write_cert *ctx, const mbedtls_pk_context *subject_key) {
    if (!ctx || !subject_key) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    ctx->subject_pk = subject_key;
    return LIBCVC_OK;
}

int cvc_write_set_issuer_key(cvc_write_cert *ctx, const mbedtls_pk_context *issuer_key) {
    if (!ctx || !issuer_key) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    ctx->issuer_pk = issuer_key;
    return LIBCVC_OK;
}

int cvc_write_set_algorithm_oid(cvc_write_cert *ctx, const uint8_t *alg_oid, uint16_t alg_oid_len) {
    if (!ctx || !alg_oid || alg_oid_len == 0) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    ctx->alg_oid = alg_oid;
    ctx->alg_oid_len = alg_oid_len;
    return LIBCVC_OK;
}

int cvc_write_set_md(cvc_write_cert *ctx, mbedtls_md_type_t md_alg) {
    if (!ctx) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    ctx->md_alg = md_alg;
    return LIBCVC_OK;
}

int cvc_write_set_car(cvc_write_cert *ctx, const uint8_t *car, uint16_t car_len) {
    if (!ctx) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    if (copy_field(ctx->car_buf, sizeof(ctx->car_buf), &ctx->meta.car_len, car, car_len) != 0) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    ctx->meta.car = ctx->car_buf;
    return LIBCVC_OK;
}

int cvc_write_set_chr(cvc_write_cert *ctx, const uint8_t *chr, uint16_t chr_len) {
    if (!ctx) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    if (copy_field(ctx->chr_buf, sizeof(ctx->chr_buf), &ctx->meta.chr_len, chr, chr_len) != 0) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    ctx->meta.chr = ctx->chr_buf;
    return LIBCVC_OK;
}

int cvc_write_set_chat(cvc_write_cert *ctx, const uint8_t *chat, uint16_t chat_len) {
    if (!ctx) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    if (copy_field(ctx->chat_buf, sizeof(ctx->chat_buf), &ctx->meta.chat_len, chat, chat_len) != 0) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    ctx->meta.chat = ctx->chat_buf;
    return LIBCVC_OK;
}

int cvc_write_set_validity(cvc_write_cert *ctx,
                           const uint8_t *valid_from,
                           uint16_t valid_from_len,
                           const uint8_t *valid_to,
                           uint16_t valid_to_len) {
    if (!ctx) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    if (copy_field(ctx->valid_from_buf, sizeof(ctx->valid_from_buf), &ctx->meta.valid_from_len, valid_from, valid_from_len) != 0) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    if (copy_field(ctx->valid_to_buf, sizeof(ctx->valid_to_buf), &ctx->meta.valid_to_len, valid_to, valid_to_len) != 0) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    ctx->meta.valid_from = ctx->valid_from_buf;
    ctx->meta.valid_to = ctx->valid_to_buf;
    return LIBCVC_OK;
}

int cvc_write_append_extension(cvc_write_cert *ctx,
                               const uint8_t *oid,
                               uint16_t oid_len,
                               const uint8_t *ctx_specific_tlvs,
                               uint16_t ctx_specific_tlvs_len) {
    uint16_t ddt_len = 0;
    uint16_t need = 0;
    uint8_t *p = NULL;

    if (!ctx || !oid || oid_len == 0) {
        return LIBCVC_ERR_INVALID_ARG;
    }

    ddt_len = (uint16_t)(cvc_tlv_len_tag(CVC_TAG_OID, oid_len) + ctx_specific_tlvs_len);
    need = (uint16_t)cvc_tlv_len_tag(CVC_TAG_DDT, ddt_len);
    if ((uint32_t)ctx->ext_len + need > sizeof(ctx->ext_buf)) {
        return LIBCVC_ERR_NO_SPACE;
    }

    p = ctx->ext_buf + ctx->ext_len;
    p += cvc_tlv_write_tag(CVC_TAG_DDT, p);
    p += cvc_tlv_write_len(ddt_len, p);

    p += cvc_tlv_write_tag(CVC_TAG_OID, p);
    p += cvc_tlv_write_len(oid_len, p);
    memcpy(p, oid, oid_len);
    p += oid_len;

    if (ctx_specific_tlvs && ctx_specific_tlvs_len) {
        memcpy(p, ctx_specific_tlvs, ctx_specific_tlvs_len);
        p += ctx_specific_tlvs_len;
    }

    ctx->ext_len = (uint16_t)(ctx->ext_len + need);
    ctx->meta.ext = ctx->ext_buf;
    ctx->meta.ext_len = ctx->ext_len;
    return LIBCVC_OK;
}

int cvc_write_set_include_ec_domain_parameters(cvc_write_cert *ctx, bool enable) {
    if (!ctx) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    ctx->include_ec_domain_parameters = enable;
    return LIBCVC_OK;
}

int cvc_write_set_strict_profile(cvc_write_cert *ctx, bool enable) {
    if (!ctx) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    ctx->strict_profile = enable;
    return LIBCVC_OK;
}

int cvc_write_set_domain_params_policy(cvc_write_cert *ctx, cvc_domain_params_policy_t policy) {
    if (!ctx) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    ctx->domain_params_policy = policy;
    return LIBCVC_OK;
}

int cvc_write_cert_der(cvc_write_cert *ctx,
                       uint8_t *out,
                       uint16_t out_cap,
                       uint16_t *out_len,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng) {
    uint8_t pub_tmpl[768];
    uint16_t pub_tmpl_len = 0;
    uint8_t body[1024];
    uint16_t body_len = 0;
    uint8_t sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t sig_len = 0;

    if (!ctx || !out || !out_len || !ctx->subject_pk || !ctx->issuer_pk || !ctx->alg_oid || ctx->alg_oid_len == 0) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    if (cvc_write_validate_profile(ctx) != LIBCVC_OK) {
        return LIBCVC_ERR_POLICY;
    }

    pub_tmpl_len = cvc_build_pubkey_template_ex(ctx->subject_pk,
                                                 ctx->alg_oid,
                                                 ctx->alg_oid_len,
                                                 ctx->include_ec_domain_parameters,
                                                 pub_tmpl,
                                                 sizeof(pub_tmpl));
    if (pub_tmpl_len == 0) {
        return LIBCVC_ERR_INVALID_ARG;
    }

    body_len = cvc_build_cert_body(&ctx->meta, pub_tmpl, pub_tmpl_len, body, sizeof(body));
    if (body_len == 0) {
        return LIBCVC_ERR_INVALID_ARG;
    }

    if (cvc_sign_data_mbedtls_pk(ctx->issuer_pk,
                                 ctx->md_alg,
                                 body,
                                 body_len,
                                 sig,
                                 sizeof(sig),
                                 &sig_len,
                                 f_rng,
                                 p_rng) != LIBCVC_OK) {
        return LIBCVC_ERR_CRYPTO;
    }

    *out_len = cvc_build_cert(body, body_len, sig, (uint16_t)sig_len, out, out_cap);
    return (*out_len > 0) ? 0 : -1;
}

int cvc_req_set_outer_car(cvc_write_req *ctx, const uint8_t *car, uint16_t car_len) {
    if (!ctx || !car || car_len == 0 || car_len > sizeof(ctx->outer_car_buf)) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    memcpy(ctx->outer_car_buf, car, car_len);
    ctx->outer_car_len = car_len;
    return LIBCVC_OK;
}

int cvc_req_set_outer_signing_key(cvc_write_req *ctx, const mbedtls_pk_context *outer_key) {
    if (!ctx || !outer_key) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    ctx->outer_signing_key = outer_key;
    return LIBCVC_OK;
}

int cvc_write_req_der(cvc_write_req *ctx,
                      uint8_t *out,
                      uint16_t out_cap,
                      uint16_t *out_len,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng) {
    uint8_t cert[1400];
    uint16_t cert_len = 0;
    uint8_t auth_data[1500];
    uint8_t outer_sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t outer_sig_len = 0;
    uint16_t auth_len = 0;
    uint16_t car_tlv_len = 0;
    uint8_t *ap = NULL;

    if (!ctx || !out || !out_len) {
        return LIBCVC_ERR_INVALID_ARG;
    }

    ctx->cert.meta.include_role_and_validity = false;
    if (cvc_write_set_issuer_key(&ctx->cert, ctx->cert.subject_pk) != 0) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    if (cvc_write_cert_der(&ctx->cert, cert, sizeof(cert), &cert_len, f_rng, p_rng) != 0) {
        return LIBCVC_ERR_INVALID_ARG;
    }

    if (ctx->outer_signing_key && ctx->outer_car_len > 0) {
        car_tlv_len = cvc_tlv_len_tag(CVC_TAG_CAR, ctx->outer_car_len);
        if ((uint32_t)cert_len + car_tlv_len > sizeof(auth_data)) {
            return LIBCVC_ERR_INVALID_ARG;
        }

        memcpy(auth_data, cert, cert_len);
        ap = auth_data + cert_len;
        ap += cvc_tlv_write_tag(CVC_TAG_CAR, ap);
        ap += cvc_tlv_write_len(ctx->outer_car_len, ap);
        memcpy(ap, ctx->outer_car_buf, ctx->outer_car_len);
        ap += ctx->outer_car_len;
        auth_len = (uint16_t)(ap - auth_data);

        if (cvc_sign_data_mbedtls_pk(ctx->outer_signing_key,
                                     ctx->cert.md_alg,
                                     auth_data,
                                     auth_len,
                                     outer_sig,
                                     sizeof(outer_sig),
                                     &outer_sig_len,
                                     f_rng,
                                     p_rng) != LIBCVC_OK) {
            return LIBCVC_ERR_CRYPTO;
        }

        *out_len = cvc_build_request(cert,
                                     cert_len,
                                     ctx->outer_car_buf,
                                     ctx->outer_car_len,
                                     outer_sig,
                                     (uint16_t)outer_sig_len,
                                     out,
                                     out_cap);
        return (*out_len > 0) ? 0 : -1;
    }

    if (out_cap < cert_len) {
        return LIBCVC_ERR_NO_SPACE;
    }
    memcpy(out, cert, cert_len);
    *out_len = cert_len;
    return LIBCVC_OK;
}
