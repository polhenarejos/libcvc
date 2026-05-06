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

#ifndef LIBCVC_OIDS_H
#define LIBCVC_OIDS_H

#define OID_BSI_DE                      "\x04\x00\x7F\x00\x07"
#define OID_ID_TA                       OID_BSI_DE "\x02\x02\x02"

#define OID_ID_TA_RSA                   OID_ID_TA "\x01"

#define OID_ID_TA_RSA_V1_5_SHA_1        OID_ID_TA_RSA "\x01"
#define OID_ID_TA_RSA_V1_5_SHA_256      OID_ID_TA_RSA "\x02"
#define OID_ID_TA_RSA_PSS_SHA_1         OID_ID_TA_RSA "\x03"
#define OID_ID_TA_RSA_PSS_SHA_256       OID_ID_TA_RSA "\x04"
#define OID_ID_TA_RSA_V1_5_SHA_512      OID_ID_TA_RSA "\x05"
#define OID_ID_TA_RSA_PSS_SHA_512       OID_ID_TA_RSA "\x06"

#define OID_ID_TA_ECDSA                 OID_ID_TA "\x02"

#define OID_ID_TA_ECDSA_SHA_1           OID_ID_TA_ECDSA "\x01"
#define OID_ID_TA_ECDSA_SHA_224         OID_ID_TA_ECDSA "\x02"
#define OID_ID_TA_ECDSA_SHA_256         OID_ID_TA_ECDSA "\x03"
#define OID_ID_TA_ECDSA_SHA_384         OID_ID_TA_ECDSA "\x04"
#define OID_ID_TA_ECDSA_SHA_512         OID_ID_TA_ECDSA "\x05"

#define OID_ID_RI                       OID_BSI_DE "\x02\x02\x05"

#define OID_ID_RI_DH                    OID_ID_RI "\x01"

#define OID_ID_RI_DH_SHA_1              OID_ID_RI_DH "\x01"
#define OID_ID_RI_DH_SHA_224            OID_ID_RI_DH "\x02"
#define OID_ID_RI_DH_SHA_256            OID_ID_RI_DH "\x03"

#define OID_ID_RI_ECDH                  OID_ID_RI "\x02"

#define OID_ID_RI_ECDH_SHA_1            OID_ID_RI_ECDH "\x01"
#define OID_ID_RI_ECDH_SHA_224          OID_ID_RI_ECDH "\x02"
#define OID_ID_RI_ECDH_SHA_256          OID_ID_RI_ECDH "\x03"

#define OID_ID_TA_RSA_LEN               9
#define OID_ID_TA_ECDSA_LEN             9
#define OID_ID_RI_ECDH_LEN              9

#endif
