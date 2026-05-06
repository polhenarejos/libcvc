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
 * libcvc tag definitions (TR-03110)
 */

#ifndef LIBCVC_TAGS_H
#define LIBCVC_TAGS_H

#define CVC_TAG_OID                 0x06
#define CVC_TAG_CAR                 0x42
#define CVC_TAG_DISCRETIONARY_DATA  0x53
#define CVC_TAG_CHR                 0x5F20
#define CVC_TAG_CED                 0x5F24
#define CVC_TAG_CXD                 0x5F25
#define CVC_TAG_CPI                 0x5F29
#define CVC_CPI_LEN                 1
#define CVC_CPI_VERSION_00          0x00
#define CVC_TAG_SIG                 0x5F37
#define CVC_TAG_EXT                 0x65
#define CVC_TAG_AUTH                0x67
#define CVC_TAG_DDT                 0x73
#define CVC_TAG_CERT                0x7F21
#define CVC_TAG_PUBKEY              0x7F49
#define CVC_TAG_CHAT                0x7F4C
#define CVC_TAG_CERT_BODY           0x7F4E

/* Common key-template internals. */
#define CVC_TAG_RSA_N               0x81
#define CVC_TAG_RSA_E               0x82
#define CVC_TAG_EC_P                0x81
#define CVC_TAG_EC_A                0x82
#define CVC_TAG_EC_B                0x83
#define CVC_TAG_EC_G                0x84
#define CVC_TAG_EC_R                0x85
#define CVC_TAG_EC_POINT            0x86
#define CVC_TAG_EC_F                0x87

#endif /* LIBCVC_TAGS_H */
