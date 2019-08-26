/* checksum.h
 *
 * Copyright 2019 Stephen Gallagher
 *
 * Contains code originally written by Tomas Mlcoch and others as part of the
 * createrepo_c project. Relicensed with permission.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __C_SQUISHY_CHECKSUM_H__
#define __C_SQUISHY_CHECKSUM_H__

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup   checksum        API for checksum calculation.
 *  \addtogroup checksum
 *  @{
 */

/** Checksum context.
 */
typedef struct _sq_ChecksumCtx sq_ChecksumCtx;

/**
 * Enum of supported checksum types.
 * Note: SHA is just a "nickname" for the SHA1. This
 * is for the compatibility with original createrepo.
 */
typedef enum {
    SQ_CHECKSUM_UNKNOWN,    /*!< Unknown checksum */
//    SQ_CHECKSUM_MD2,        /*!< MD2 checksum */
    SQ_CHECKSUM_MD5,        /*!< MD5 checksum */
    SQ_CHECKSUM_SHA,        /*!< SHA checksum */
    SQ_CHECKSUM_SHA1,       /*!< SHA1 checksum */
    SQ_CHECKSUM_SHA224,     /*!< SHA224 checksum */
    SQ_CHECKSUM_SHA256,     /*!< SHA256 checksum */
    SQ_CHECKSUM_SHA384,     /*!< SHA384 checksum */
    SQ_CHECKSUM_SHA512,     /*!< SHA512 checksum */
    SQ_CHECKSUM_SENTINEL,   /*!< sentinel of the list */
} sq_ChecksumType;

/** Return checksum name.
 * @param type          checksum type
 * @return              constant null terminated string with checksum name
 *                      or NULL on error
 */
const char *sq_checksum_name_str(sq_ChecksumType type);

/** Return checksum type.
 * @param name          checksum name
 * @return              checksum type
 */
sq_ChecksumType sq_checksum_type(const char *name);

/** Compute file checksum.
 * @param filename      filename
 * @param type          type of checksum
 * @param err           GError **
 * @return              malloced null terminated string with checksum
 *                      or NULL on error
 */
char *sq_checksum_file(const char *filename,
                       sq_ChecksumType type,
                       GError **err);

/** Create new checksum context.
 * @param type      Checksum algorithm of the new checksum context.
 * @param err       GError **
 * @return          sq_ChecksumCtx or NULL on error
 */
sq_ChecksumCtx *sq_checksum_new(sq_ChecksumType type, GError **err);

/** Feeds data into the checksum.
 * @param ctx       Checksum context.
 * @param buf       Pointer to the data.
 * @param len       Length of the data.
 * @param err       GError **
 * @return          sq_Error code.
 */
int sq_checksum_update(sq_ChecksumCtx *ctx,
                       const void *buf,
                       size_t len,
                       GError **err);

/** Finalize checksum calculation, return checksum string and frees
 * all checksum context resources.
 * @param ctx       Checksum context.
 * @param err       GError **
 * @return          Checksum string or NULL on error.
 */
char *sq_checksum_final(sq_ChecksumCtx *ctx, GError **err);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* __C_SQUISHY_CHECKSUM_H__ */
