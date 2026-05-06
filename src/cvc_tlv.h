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

#ifndef LIBCVC_TLV_H
#define LIBCVC_TLV_H

#include <stdint.h>

typedef struct {
    uint16_t tag;
    const uint8_t *value;
    uint16_t value_len;
    uint16_t hdr_len;
    int constructed;
} cvc_tlv_hdr_t;

uint8_t cvc_tlv_len_size(uint16_t len);
uint8_t cvc_tlv_write_len(uint16_t len, uint8_t *out);
uint16_t cvc_tlv_tag_size(uint16_t tag);
uint16_t cvc_tlv_len_tag(uint16_t tag, uint16_t len);
uint8_t cvc_tlv_write_tag(uint16_t tag, uint8_t *out);
int cvc_tlv_parse_header(const uint8_t *p, uint16_t rem, cvc_tlv_hdr_t *h);
const uint8_t *cvc_tlv_find_tag_recursive(const uint8_t *p, uint16_t len, uint16_t *olen, uint16_t tag);

#endif
