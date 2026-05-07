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
#include "mbedtls/rsa.h"
#include "mbedtls/ecp.h"

static int cvc_curve_has_a_minus_3(mbedtls_ecp_group_id gid) {
    switch (gid) {
        case MBEDTLS_ECP_DP_SECP192R1:
        case MBEDTLS_ECP_DP_SECP224R1:
        case MBEDTLS_ECP_DP_SECP256R1:
        case MBEDTLS_ECP_DP_SECP384R1:
        case MBEDTLS_ECP_DP_SECP521R1:
            return 1;
        default:
            return 0;
    }
}

uint16_t cvc_build_pubkey_template_ex(const mbedtls_pk_context *pk,
                                      const uint8_t *alg_oid, uint16_t alg_oid_len,
                                      bool include_ec_domain_parameters,
                                      uint8_t *out, uint16_t out_cap) {
    uint16_t oid_tlv_len = 0;
    uint16_t data_len = 0;
    uint16_t total_len = 0;
    uint8_t *p = out;

    if (!pk || !alg_oid || !alg_oid_len) {
        return 0;
    }

    oid_tlv_len = cvc_tlv_len_tag(CVC_TAG_OID, alg_oid_len);

    if (mbedtls_pk_get_type((mbedtls_pk_context *)pk) == MBEDTLS_PK_RSA) {
        const mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*pk);
        size_t n_len_sz = 0;
        size_t e_len_sz = 0;
        uint16_t n_len = 0;
        uint16_t e_len = 0;
        mbedtls_mpi n;
        mbedtls_mpi e;

        mbedtls_mpi_init(&n);
        mbedtls_mpi_init(&e);

        if (mbedtls_rsa_export((mbedtls_rsa_context *)rsa, &n, NULL, NULL, NULL, &e) != 0) {
            mbedtls_mpi_free(&n);
            mbedtls_mpi_free(&e);
            return 0;
        }

        n_len_sz = mbedtls_mpi_size(&n);
        e_len_sz = mbedtls_mpi_size(&e);
        if (!n_len_sz || !e_len_sz || n_len_sz > UINT16_MAX || e_len_sz > UINT16_MAX) {
            mbedtls_mpi_free(&n);
            mbedtls_mpi_free(&e);
            return 0;
        }

        n_len = (uint16_t)n_len_sz;
        e_len = (uint16_t)e_len_sz;
        data_len = (uint16_t)(oid_tlv_len + cvc_tlv_len_tag(CVC_TAG_RSA_N, n_len) + cvc_tlv_len_tag(CVC_TAG_RSA_E, e_len));
        total_len = cvc_tlv_len_tag(CVC_TAG_PUBKEY, data_len);

        if (!out || !out_cap) {
            mbedtls_mpi_free(&n);
            mbedtls_mpi_free(&e);
            return total_len;
        }
        if (out_cap < total_len) {
            mbedtls_mpi_free(&n);
            mbedtls_mpi_free(&e);
            return 0;
        }

        p += cvc_tlv_write_tag(CVC_TAG_PUBKEY, p);
        p += cvc_tlv_write_len(data_len, p);

        p += cvc_tlv_write_tag(CVC_TAG_OID, p);
        p += cvc_tlv_write_len(alg_oid_len, p);
        memcpy(p, alg_oid, alg_oid_len);
        p += alg_oid_len;

        p += cvc_tlv_write_tag(CVC_TAG_RSA_N, p);
        p += cvc_tlv_write_len(n_len, p);
        if (mbedtls_mpi_write_binary(&n, p, n_len) != 0) {
            mbedtls_mpi_free(&n);
            mbedtls_mpi_free(&e);
            return 0;
        }
        p += n_len;

        p += cvc_tlv_write_tag(CVC_TAG_RSA_E, p);
        p += cvc_tlv_write_len(e_len, p);
        if (mbedtls_mpi_write_binary(&e, p, e_len) != 0) {
            mbedtls_mpi_free(&n);
            mbedtls_mpi_free(&e);
            return 0;
        }
        p += e_len;

        mbedtls_mpi_free(&n);
        mbedtls_mpi_free(&e);
        return (uint16_t)(p - out);
    }

    if (mbedtls_pk_get_type((mbedtls_pk_context *)pk) == MBEDTLS_PK_ECKEY ||
        mbedtls_pk_get_type((mbedtls_pk_context *)pk) == MBEDTLS_PK_ECKEY_DH) {
        const mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*pk);
        mbedtls_ecp_curve_type ctype;
        mbedtls_ecp_group grp;
        mbedtls_ecp_point q;

        size_t p_len = 0;
        size_t a_len = 0;
        size_t b_len = 0;
        size_t g_len = 0;
        size_t r_len = 0;
        size_t f_len = 1;
        size_t q_len = 0;
        size_t dh_q_len = 0;
        size_t dh_g_len = 0;
        size_t dh_y_len = 0;
        size_t written_len = 0;
        static const uint8_t f_buf[1] = {1};

        mbedtls_ecp_group_init(&grp);
        mbedtls_ecp_point_init(&q);

        if (mbedtls_ecp_export(ec, &grp, NULL, &q) != 0) {
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&q);
            return 0;
        }
        ctype = mbedtls_ecp_get_type(&grp);
        if (ctype == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
            q_len = 1u + 2u * ((grp.pbits + 7u) / 8u);
            if (q_len == 0 || q_len > UINT16_MAX) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return 0;
            }

            data_len = (uint16_t)(oid_tlv_len + cvc_tlv_len_tag(CVC_TAG_EC_POINT, (uint16_t)q_len));
        }
        else if (ctype == MBEDTLS_ECP_TYPE_MONTGOMERY
#if defined(MBEDTLS_EDDSA_C)
                 || ctype == MBEDTLS_ECP_TYPE_EDWARDS
#endif
                 ) {
            p_len = mbedtls_mpi_size(&grp.P);
            dh_q_len = mbedtls_mpi_size(&grp.N);
            dh_g_len = mbedtls_mpi_size(&grp.G.MBEDTLS_PRIVATE(X));
            dh_y_len = mbedtls_mpi_size(&q.MBEDTLS_PRIVATE(X));
            if (p_len == 0 || dh_q_len == 0 || dh_g_len == 0 || dh_y_len == 0 ||
                p_len > UINT16_MAX || dh_q_len > UINT16_MAX || dh_g_len > UINT16_MAX || dh_y_len > UINT16_MAX) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return 0;
            }
            data_len = (uint16_t)(oid_tlv_len
                                  + cvc_tlv_len_tag(CVC_TAG_EC_P, (uint16_t)p_len)
                                  + cvc_tlv_len_tag(CVC_TAG_EC_A, (uint16_t)dh_q_len)
                                  + cvc_tlv_len_tag(CVC_TAG_EC_B, (uint16_t)dh_g_len)
                                  + cvc_tlv_len_tag(CVC_TAG_EC_G, (uint16_t)dh_y_len));
        }
        else {
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&q);
            return 0;
        }

        if (include_ec_domain_parameters && ctype == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
            size_t field_len = (grp.pbits + 7u) / 8u;
            p_len = mbedtls_mpi_size(&grp.P);
            a_len = mbedtls_mpi_size(&grp.A);
            b_len = mbedtls_mpi_size(&grp.B);
            r_len = mbedtls_mpi_size(&grp.N);
            g_len = 1u + 2u * ((grp.pbits + 7u) / 8u);

            if (p_len == 0 || b_len == 0 || r_len == 0 || g_len == 0) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return 0;
            }

            /* Keep domain parameters width-consistent within the selected curve. */
            if (field_len > 0) {
                p_len = field_len;
                a_len = field_len;
                b_len = field_len;
                if (r_len < field_len) {
                    r_len = field_len;
                }
            }

            data_len = (uint16_t)(data_len
                + cvc_tlv_len_tag(CVC_TAG_EC_P, (uint16_t)p_len)
                + cvc_tlv_len_tag(CVC_TAG_EC_A, (uint16_t)a_len)
                + cvc_tlv_len_tag(CVC_TAG_EC_B, (uint16_t)b_len)
                + cvc_tlv_len_tag(CVC_TAG_EC_G, (uint16_t)g_len)
                + cvc_tlv_len_tag(CVC_TAG_EC_R, (uint16_t)r_len)
                + cvc_tlv_len_tag(CVC_TAG_EC_F, (uint16_t)f_len));

        }

        total_len = cvc_tlv_len_tag(CVC_TAG_PUBKEY, data_len);
        if (!out || !out_cap) {
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&q);
            return total_len;
        }
        if (out_cap < total_len) {
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&q);
            return 0;
        }

        p += cvc_tlv_write_tag(CVC_TAG_PUBKEY, p);
        p += cvc_tlv_write_len(data_len, p);

        p += cvc_tlv_write_tag(CVC_TAG_OID, p);
        p += cvc_tlv_write_len(alg_oid_len, p);
        memcpy(p, alg_oid, alg_oid_len);
        p += alg_oid_len;

        if (ctype == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS &&
            include_ec_domain_parameters) {
            p += cvc_tlv_write_tag(CVC_TAG_EC_P, p);
            p += cvc_tlv_write_len((uint16_t)p_len, p);
            if (mbedtls_mpi_write_binary(&grp.P, p, p_len) != 0) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return 0;
            }
            p += p_len;

            p += cvc_tlv_write_tag(CVC_TAG_EC_A, p);
            p += cvc_tlv_write_len((uint16_t)a_len, p);
            {
                mbedtls_mpi a_mod_p;
                mbedtls_mpi_init(&a_mod_p);
                if (mbedtls_mpi_mod_mpi(&a_mod_p, &grp.A, &grp.P) != 0) {
                    mbedtls_mpi_free(&a_mod_p);
                    mbedtls_ecp_group_free(&grp);
                    mbedtls_ecp_point_free(&q);
                    return 0;
                }
                if (mbedtls_mpi_cmp_int(&a_mod_p, 0) < 0) {
                    if (mbedtls_mpi_add_mpi(&a_mod_p, &a_mod_p, &grp.P) != 0) {
                        mbedtls_mpi_free(&a_mod_p);
                        mbedtls_ecp_group_free(&grp);
                        mbedtls_ecp_point_free(&q);
                        return 0;
                    }
                }
                /* Some mbedTLS builds expose A=0 for NIST Weierstrass curves with A=-3. */
                if (mbedtls_mpi_cmp_int(&a_mod_p, 0) == 0 &&
                    cvc_curve_has_a_minus_3(grp.id)) {
                    if (mbedtls_mpi_copy(&a_mod_p, &grp.P) != 0 ||
                        mbedtls_mpi_sub_int(&a_mod_p, &a_mod_p, 3) != 0) {
                        mbedtls_mpi_free(&a_mod_p);
                        mbedtls_ecp_group_free(&grp);
                        mbedtls_ecp_point_free(&q);
                        return 0;
                    }
                }
                if (mbedtls_mpi_write_binary(&a_mod_p, p, a_len) != 0) {
                    mbedtls_mpi_free(&a_mod_p);
                    mbedtls_ecp_group_free(&grp);
                    mbedtls_ecp_point_free(&q);
                    return 0;
                }
                mbedtls_mpi_free(&a_mod_p);
            }
            p += a_len;

            p += cvc_tlv_write_tag(CVC_TAG_EC_B, p);
            p += cvc_tlv_write_len((uint16_t)b_len, p);
            if (mbedtls_mpi_write_binary(&grp.B, p, b_len) != 0) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return 0;
            }
            p += b_len;

            p += cvc_tlv_write_tag(CVC_TAG_EC_G, p);
            p += cvc_tlv_write_len((uint16_t)g_len, p);
            if (mbedtls_ecp_point_write_binary(&grp, &grp.G, MBEDTLS_ECP_PF_UNCOMPRESSED, &written_len, p, g_len) != 0 ||
                written_len != g_len) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return 0;
            }
            p += g_len;

            p += cvc_tlv_write_tag(CVC_TAG_EC_R, p);
            p += cvc_tlv_write_len((uint16_t)r_len, p);
            if (mbedtls_mpi_write_binary(&grp.N, p, r_len) != 0) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return 0;
            }
            p += r_len;

            p += cvc_tlv_write_tag(CVC_TAG_EC_POINT, p);
            p += cvc_tlv_write_len((uint16_t)q_len, p);
            if (mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &written_len, p, q_len) != 0 ||
                written_len != q_len) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return 0;
            }
            p += q_len;

            p += cvc_tlv_write_tag(CVC_TAG_EC_F, p);
            p += cvc_tlv_write_len((uint16_t)f_len, p);
            memcpy(p, f_buf, f_len);
            p += f_len;
        }
        else if (ctype == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
            p += cvc_tlv_write_tag(CVC_TAG_EC_POINT, p);
            p += cvc_tlv_write_len((uint16_t)q_len, p);
            if (mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &written_len, p, q_len) != 0 ||
                written_len != q_len) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return 0;
            }
            p += q_len;
        }
        else {
            p += cvc_tlv_write_tag(CVC_TAG_EC_P, p);
            p += cvc_tlv_write_len((uint16_t)p_len, p);
            if (mbedtls_mpi_write_binary(&grp.P, p, p_len) != 0) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return 0;
            }
            p += p_len;

            p += cvc_tlv_write_tag(CVC_TAG_EC_A, p);
            p += cvc_tlv_write_len((uint16_t)dh_q_len, p);
            if (mbedtls_mpi_write_binary(&grp.N, p, dh_q_len) != 0) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return 0;
            }
            p += dh_q_len;

            p += cvc_tlv_write_tag(CVC_TAG_EC_B, p);
            p += cvc_tlv_write_len((uint16_t)dh_g_len, p);
            if (mbedtls_mpi_write_binary(&grp.G.MBEDTLS_PRIVATE(X), p, dh_g_len) != 0) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return 0;
            }
            p += dh_g_len;

            p += cvc_tlv_write_tag(CVC_TAG_EC_G, p);
            p += cvc_tlv_write_len((uint16_t)dh_y_len, p);
            if (mbedtls_mpi_write_binary(&q.MBEDTLS_PRIVATE(X), p, dh_y_len) != 0) {
                mbedtls_ecp_group_free(&grp);
                mbedtls_ecp_point_free(&q);
                return 0;
            }
            p += dh_y_len;
        }

        mbedtls_ecp_group_free(&grp);
        mbedtls_ecp_point_free(&q);
        return (uint16_t)(p - out);
    }

    return 0;
}

uint16_t cvc_build_pubkey_template(const mbedtls_pk_context *pk,
                                   const uint8_t *alg_oid,
                                   uint16_t alg_oid_len,
                                   uint8_t *out,
                                   uint16_t out_cap) {
    return cvc_build_pubkey_template_ex(pk, alg_oid, alg_oid_len, false, out, out_cap);
}

uint16_t cvc_build_cert_body(const cvc_cert_meta_t *meta,
                             const uint8_t *pub_tmpl,
                             uint16_t pub_tmpl_len,
                             uint8_t *out,
                             uint16_t out_cap) {
    uint16_t cpi_len = cvc_tlv_len_tag(CVC_TAG_CPI, CVC_CPI_LEN);
    uint16_t car_tlv = 0;
    uint16_t chr_tlv = 0;
    uint16_t role_tlv = 0;
    uint16_t vf_tlv = 0;
    uint16_t vt_tlv = 0;
    uint16_t ext_tlv = 0;
    uint16_t data_len = 0;
    uint16_t total_len = 0;
    uint8_t *p = out;
    static const uint8_t default_chat[] = {0x06, 0x09, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x03, 0x01, 0x02, 0x02, 0x53, 0x01, 0x00};

    if (!meta || !pub_tmpl || !pub_tmpl_len || !meta->car || !meta->chr || !meta->car_len || !meta->chr_len) {
        return 0;
    }

    car_tlv = cvc_tlv_len_tag(CVC_TAG_CAR, meta->car_len);
    chr_tlv = cvc_tlv_len_tag(CVC_TAG_CHR, meta->chr_len);

    if (meta->include_role_and_validity) {
        uint16_t chat_len = meta->chat ? meta->chat_len : (uint16_t)sizeof(default_chat);
        role_tlv = cvc_tlv_len_tag(CVC_TAG_CHAT, chat_len);
        vf_tlv = cvc_tlv_len_tag(CVC_TAG_CXD, meta->valid_from_len);
        vt_tlv = cvc_tlv_len_tag(CVC_TAG_CED, meta->valid_to_len);
        if (!meta->valid_from || !meta->valid_to || !meta->valid_from_len || !meta->valid_to_len) {
            return 0;
        }
    }

    if (meta->ext && meta->ext_len) {
        ext_tlv = cvc_tlv_len_tag(CVC_TAG_EXT, meta->ext_len);
    }

    data_len = (uint16_t)(cpi_len + car_tlv + pub_tmpl_len + chr_tlv + role_tlv + vf_tlv + vt_tlv + ext_tlv);
    total_len = cvc_tlv_len_tag(CVC_TAG_CERT_BODY, data_len);

    if (!out || !out_cap) {
        return total_len;
    }
    if (out_cap < total_len) {
        return 0;
    }

    p += cvc_tlv_write_tag(CVC_TAG_CERT_BODY, p);
    p += cvc_tlv_write_len(data_len, p);

    p += cvc_tlv_write_tag(CVC_TAG_CPI, p);
    p += cvc_tlv_write_len(CVC_CPI_LEN, p);
    *p++ = CVC_CPI_VERSION_00;

    p += cvc_tlv_write_tag(CVC_TAG_CAR, p);
    p += cvc_tlv_write_len(meta->car_len, p);
    memcpy(p, meta->car, meta->car_len);
    p += meta->car_len;

    memcpy(p, pub_tmpl, pub_tmpl_len);
    p += pub_tmpl_len;

    p += cvc_tlv_write_tag(CVC_TAG_CHR, p);
    p += cvc_tlv_write_len(meta->chr_len, p);
    memcpy(p, meta->chr, meta->chr_len);
    p += meta->chr_len;

    if (meta->include_role_and_validity) {
        const uint8_t *chat = meta->chat ? meta->chat : default_chat;
        uint16_t chat_len = meta->chat ? meta->chat_len : (uint16_t)sizeof(default_chat);

        p += cvc_tlv_write_tag(CVC_TAG_CHAT, p);
        p += cvc_tlv_write_len(chat_len, p);
        memcpy(p, chat, chat_len);
        p += chat_len;

        p += cvc_tlv_write_tag(CVC_TAG_CXD, p);
        p += cvc_tlv_write_len(meta->valid_from_len, p);
        memcpy(p, meta->valid_from, meta->valid_from_len);
        p += meta->valid_from_len;

        p += cvc_tlv_write_tag(CVC_TAG_CED, p);
        p += cvc_tlv_write_len(meta->valid_to_len, p);
        memcpy(p, meta->valid_to, meta->valid_to_len);
        p += meta->valid_to_len;
    }

    if (meta->ext && meta->ext_len) {
        p += cvc_tlv_write_tag(CVC_TAG_EXT, p);
        p += cvc_tlv_write_len(meta->ext_len, p);
        memcpy(p, meta->ext, meta->ext_len);
        p += meta->ext_len;
    }

    return (uint16_t)(p - out);
}

uint16_t cvc_build_cert(const uint8_t *body,
                        uint16_t body_len,
                        const uint8_t *sig,
                        uint16_t sig_len,
                        uint8_t *out,
                        uint16_t out_cap) {
    cvc_tlv_hdr_t body_hdr;
    uint16_t sig_tlv = 0;
    uint16_t data_len = 0;
    uint16_t total_len = 0;
    uint8_t *p = out;

    if (!body || !body_len || !sig || !sig_len) {
        return 0;
    }
    if (cvc_tlv_parse_header(body, body_len, &body_hdr) != LIBCVC_OK ||
        body_hdr.tag != CVC_TAG_CERT_BODY ||
        (uint16_t)(body_hdr.hdr_len + body_hdr.value_len) != body_len) {
        return 0;
    }

    sig_tlv = cvc_tlv_len_tag(CVC_TAG_SIG, sig_len);
    data_len = (uint16_t)(body_len + sig_tlv);
    total_len = cvc_tlv_len_tag(CVC_TAG_CERT, data_len);

    if (!out || !out_cap) {
        return total_len;
    }
    if (out_cap < total_len) {
        return 0;
    }

    p += cvc_tlv_write_tag(CVC_TAG_CERT, p);
    p += cvc_tlv_write_len(data_len, p);
    memcpy(p, body, body_len);
    p += body_len;

    p += cvc_tlv_write_tag(CVC_TAG_SIG, p);
    p += cvc_tlv_write_len(sig_len, p);
    memcpy(p, sig, sig_len);
    p += sig_len;

    return (uint16_t)(p - out);
}

uint16_t cvc_build_request(const uint8_t *cert,
                           uint16_t cert_len,
                           const uint8_t *outer_car,
                           uint16_t outer_car_len,
                           const uint8_t *outer_sig,
                           uint16_t outer_sig_len,
                           uint8_t *out,
                           uint16_t out_cap) {
    uint16_t car_tlv = 0;
    uint16_t sig_tlv = 0;
    uint16_t data_len = cert_len;
    uint16_t total_len = 0;
    uint8_t *p = out;

    if (!cert || !cert_len) {
        return 0;
    }

    if (outer_car && outer_car_len) {
        car_tlv = cvc_tlv_len_tag(CVC_TAG_CAR, outer_car_len);
        data_len = (uint16_t)(data_len + car_tlv);
    }

    if (outer_sig && outer_sig_len) {
        sig_tlv = cvc_tlv_len_tag(CVC_TAG_SIG, outer_sig_len);
        data_len = (uint16_t)(data_len + sig_tlv);
    }

    total_len = cvc_tlv_len_tag(CVC_TAG_AUTH, data_len);
    if (!out || !out_cap) {
        return total_len;
    }
    if (out_cap < total_len) {
        return 0;
    }

    p += cvc_tlv_write_tag(CVC_TAG_AUTH, p);
    p += cvc_tlv_write_len(data_len, p);
    memcpy(p, cert, cert_len);
    p += cert_len;

    if (outer_car && outer_car_len) {
        p += cvc_tlv_write_tag(CVC_TAG_CAR, p);
        p += cvc_tlv_write_len(outer_car_len, p);
        memcpy(p, outer_car, outer_car_len);
        p += outer_car_len;
    }

    if (outer_sig && outer_sig_len) {
        p += cvc_tlv_write_tag(CVC_TAG_SIG, p);
        p += cvc_tlv_write_len(outer_sig_len, p);
        memcpy(p, outer_sig, outer_sig_len);
        p += outer_sig_len;
    }

    return (uint16_t)(p - out);
}
