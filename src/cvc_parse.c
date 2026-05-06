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

const uint8_t *cvc_get_field(const uint8_t *data, uint16_t len, uint16_t *olen, uint16_t tag) {
    if (olen) *olen = 0;
    if (!data || len == 0) return NULL;
    return cvc_tlv_find_tag_recursive(data, len, olen, tag);
}

const uint8_t *cvc_get_body(const uint8_t *data, uint16_t len, uint16_t *olen) {
    const uint8_t *outer = NULL;
    const uint8_t *cert = NULL;
    uint16_t outer_len = 0, cert_len = 0;
    outer = cvc_get_field(data, len, &outer_len, CVC_TAG_AUTH);
    if (!outer) {
        outer = data;
        outer_len = len;
    }
    cert = cvc_get_field(outer, outer_len, &cert_len, CVC_TAG_CERT);
    if (!cert) return NULL;
    return cvc_get_field(cert, cert_len, olen, CVC_TAG_CERT_BODY);
}

const uint8_t *cvc_get_sig(const uint8_t *data, uint16_t len, uint16_t *olen) {
    const uint8_t *outer = NULL;
    const uint8_t *cert = NULL;
    uint16_t outer_len = 0, cert_len = 0;
    outer = cvc_get_field(data, len, &outer_len, CVC_TAG_AUTH);
    if (!outer) {
        outer = data;
        outer_len = len;
    }
    cert = cvc_get_field(outer, outer_len, &cert_len, CVC_TAG_CERT);
    if (!cert) return NULL;
    return cvc_get_field(cert, cert_len, olen, CVC_TAG_SIG);
}

const uint8_t *cvc_get_car(const uint8_t *data, uint16_t len, uint16_t *olen) {
    uint16_t body_len = 0;
    const uint8_t *body = cvc_get_body(data, len, &body_len);
    return body ? cvc_get_field(body, body_len, olen, CVC_TAG_CAR) : NULL;
}

const uint8_t *cvc_get_chr(const uint8_t *data, uint16_t len, uint16_t *olen) {
    uint16_t body_len = 0;
    const uint8_t *body = cvc_get_body(data, len, &body_len);
    return body ? cvc_get_field(body, body_len, olen, CVC_TAG_CHR) : NULL;
}

const uint8_t *cvc_get_pub(const uint8_t *data, uint16_t len, uint16_t *olen) {
    uint16_t body_len = 0;
    const uint8_t *body = cvc_get_body(data, len, &body_len);
    return body ? cvc_get_field(body, body_len, olen, CVC_TAG_PUBKEY) : NULL;
}

const uint8_t *cvc_get_ext(const uint8_t *data, uint16_t len, uint16_t *olen) {
    uint16_t body_len = 0;
    const uint8_t *body = cvc_get_body(data, len, &body_len);
    return body ? cvc_get_field(body, body_len, olen, CVC_TAG_EXT) : NULL;
}

int cvc_parse_pubkey_template(const uint8_t *pub_tmpl, uint16_t pub_tmpl_len, cvc_pubkey_t *out) {
    uint16_t oid_len = 0, t81_len = 0, t82_len = 0, t83_len = 0, t84_len = 0, t86_len = 0;
    const uint8_t *oid = NULL, *t81 = NULL, *t82 = NULL, *t83 = NULL, *t84 = NULL, *t86 = NULL;
    if (!pub_tmpl || !pub_tmpl_len || !out) return LIBCVC_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    oid = cvc_get_field(pub_tmpl, pub_tmpl_len, &oid_len, CVC_TAG_OID);
    if (!oid || !oid_len) return LIBCVC_ERR_FORMAT;
    out->alg_oid = oid; out->alg_oid_len = oid_len;
    t86 = cvc_get_field(pub_tmpl, pub_tmpl_len, &t86_len, CVC_TAG_EC_POINT);
    t81 = cvc_get_field(pub_tmpl, pub_tmpl_len, &t81_len, CVC_TAG_RSA_N);
    t82 = cvc_get_field(pub_tmpl, pub_tmpl_len, &t82_len, CVC_TAG_RSA_E);
    t83 = cvc_get_field(pub_tmpl, pub_tmpl_len, &t83_len, CVC_TAG_EC_B);
    t84 = cvc_get_field(pub_tmpl, pub_tmpl_len, &t84_len, CVC_TAG_EC_G);
    if (t86 && t86_len) {
        out->kind = CVC_KEY_KIND_EC; out->q = t86; out->q_len = t86_len; return LIBCVC_OK;
    }
    if (t81 && t81_len && t82 && t82_len && t83 && t83_len && t84 && t84_len) {
        out->kind = CVC_KEY_KIND_EC;
        out->q = t84;
        out->q_len = t84_len;
        return LIBCVC_OK;
    }
    if (t81 && t81_len && t82 && t82_len) {
        out->kind = CVC_KEY_KIND_RSA; out->n = t81; out->n_len = t81_len; out->e = t82; out->e_len = t82_len; return LIBCVC_OK;
    }
    out->kind = CVC_KEY_KIND_UNKNOWN;
    return LIBCVC_ERR_UNSUPPORTED;
}

int cvc_extract_pubkey(const uint8_t *cert, uint16_t cert_len, cvc_pubkey_t *out) {
    uint16_t l = 0;
    const uint8_t *p = cvc_get_pub(cert, cert_len, &l);
    if (!p || !l) return LIBCVC_ERR_INVALID_ARG;
    return cvc_parse_pubkey_template(p, l, out);
}

int cvc_extract_ec_point(const uint8_t *cert, uint16_t cert_len, uint8_t *out, uint16_t out_cap, uint16_t *out_len, bool prefer_compressed) {
    cvc_pubkey_t pk;
    if (out_len) *out_len = 0;
    if (cvc_extract_pubkey(cert, cert_len, &pk) != 0 || pk.kind != CVC_KEY_KIND_EC || !pk.q || !pk.q_len) return LIBCVC_ERR_INVALID_ARG;
    if (!prefer_compressed || pk.q_len != 65 || pk.q[0] != 0x04) {
        if (pk.q_len > out_cap) return LIBCVC_ERR_FORMAT;
        memcpy(out, pk.q, pk.q_len);
        if (out_len) *out_len = pk.q_len;
        return LIBCVC_OK;
    }
    if (out_cap < 33) return LIBCVC_ERR_UNSUPPORTED;
    out[0] = (uint8_t)((pk.q[64] & 1u) ? 0x03u : 0x02u);
    memcpy(out + 1, pk.q + 1, 32);
    if (out_len) *out_len = 33;
    return LIBCVC_OK;
}

int cvc_extract_pubkey_compressed_secp256k1(const uint8_t *cert, uint16_t cert_len, uint8_t out33[33]) {
    uint16_t olen = 0;
    return cvc_extract_ec_point(cert, cert_len, out33, 33, &olen, true);
}
