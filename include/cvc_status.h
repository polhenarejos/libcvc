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

#ifndef LIBCVC_STATUS_H
#define LIBCVC_STATUS_H

typedef enum {
    LIBCVC_OK = 0,
    LIBCVC_ERR_INVALID_ARG = -1,
    LIBCVC_ERR_FORMAT = -2,
    LIBCVC_ERR_UNSUPPORTED = -3,
    LIBCVC_ERR_NO_SPACE = -4,
    LIBCVC_ERR_CRYPTO = -5,
    LIBCVC_ERR_POLICY = -6
} libcvc_status_t;

#endif
