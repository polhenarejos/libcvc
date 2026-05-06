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

#include "cvc_tlv.h"
#include "cvc_status.h"
#include <stddef.h>

uint8_t cvc_tlv_len_size(uint16_t len) {
    if (len < 0x80) {
        return 1;
    }
    if (len < 0x100) {
        return 2;
    }
    return 3;
}

uint8_t cvc_tlv_write_len(uint16_t len, uint8_t *out) {
    if (len < 0x80) {
        if (out) {
            out[0] = (uint8_t)len;
        }
        return 1;
    }
    if (len < 0x100) {
        if (out) {
            out[0] = 0x81;
            out[1] = (uint8_t)len;
        }
        return 2;
    }
    if (out) {
        out[0] = 0x82;
        out[1] = (uint8_t)(len >> 8);
        out[2] = (uint8_t)(len & 0xFFu);
    }
    return 3;
}

uint16_t cvc_tlv_tag_size(uint16_t tag) {
    return (tag > 0xFFu) ? 2 : 1;
}

uint16_t cvc_tlv_len_tag(uint16_t tag, uint16_t len) {
    return (uint16_t)(cvc_tlv_tag_size(tag) + cvc_tlv_len_size(len) + len);
}

uint8_t cvc_tlv_write_tag(uint16_t tag, uint8_t *out) {
    if (cvc_tlv_tag_size(tag) == 1) {
        if (out) {
            out[0] = (uint8_t)tag;
        }
        return 1;
    }
    if (out) {
        out[0] = (uint8_t)((tag >> 8) & 0xFFu);
        out[1] = (uint8_t)(tag & 0xFFu);
    }
    return 2;
}

int cvc_tlv_parse_header(const uint8_t *p, uint16_t rem, cvc_tlv_hdr_t *h) {
    uint16_t pos = 0, len = 0, tag = 0;
    uint8_t lb = 0;
    if (!p || !h || rem < 2) {
        return LIBCVC_ERR_INVALID_ARG;
    }
    tag = p[pos++];
    h->constructed = ((tag & 0x20u) != 0);
    if ((tag & 0x1Fu) == 0x1Fu) {
        if (pos >= rem) {
            return LIBCVC_ERR_FORMAT;
        }
        tag = (uint16_t)((tag << 8) | p[pos++]);
    }
    if (pos >= rem) {
        return LIBCVC_ERR_FORMAT;
    }
    lb = p[pos++];
    if ((lb & 0x80u) == 0) {
        len = lb;
    } else {
        uint8_t n = (uint8_t)(lb & 0x7Fu);
        if (n == 0 || n > 2 || pos + n > rem) {
            return LIBCVC_ERR_FORMAT;
        }
        len = 0;
        while (n--) {
            len = (uint16_t)((len << 8) | p[pos++]);
        }
    }
    if (pos + len > rem) {
        return LIBCVC_ERR_FORMAT;
    }
    h->tag = tag;
    h->hdr_len = pos;
    h->value = p + pos;
    h->value_len = len;
    return LIBCVC_OK;
}

const uint8_t *cvc_tlv_find_tag_recursive(const uint8_t *p, uint16_t len, uint16_t *olen, uint16_t tag) {
    uint16_t off = 0;
    while (off < len) {
        cvc_tlv_hdr_t h;
        if (cvc_tlv_parse_header(p + off, (uint16_t)(len - off), &h) != LIBCVC_OK) {
            return NULL;
        }
        if (h.tag == tag) {
            if (olen) {
                *olen = h.value_len;
            }
            return h.value;
        }
        if (h.constructed) {
            const uint8_t *v = cvc_tlv_find_tag_recursive(h.value, h.value_len, olen, tag);
            if (v) {
                return v;
            }
        }
        off = (uint16_t)(off + h.hdr_len + h.value_len);
    }
    return NULL;
}
