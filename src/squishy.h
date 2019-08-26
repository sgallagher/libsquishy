/* squishy.h
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

#pragma once

#include <glib.h>

G_BEGIN_DECLS


#define SQUISHY_INSIDE
# include "squishy-version.h"
#undef SQUISHY_INSIDE

#include "checksum.h"

/** \defgroup   compression_wrapper     Wrapper for compressed file.
 *  \addtogroup compression_wrapper
 *  @{
 */

/** Compression type.
 */
typedef enum {
    SQ_CW_AUTO_DETECT_COMPRESSION,    /*!< Autodetection */
    SQ_CW_UNKNOWN_COMPRESSION,        /*!< Unknown compression */
    SQ_CW_NO_COMPRESSION,             /*!< No compression */
    SQ_CW_GZ_COMPRESSION,             /*!< Gzip compression */
    SQ_CW_BZ2_COMPRESSION,            /*!< BZip2 compression */
    SQ_CW_XZ_COMPRESSION,             /*!< XZ compression */
    SQ_CW_ZCK_COMPRESSION,            /*!< ZCK compression */
    SQ_CW_COMPRESSION_SENTINEL,       /*!< Sentinel of the list */
} sq_CompressionType;

/** Open modes.
 */
typedef enum {
    SQ_CW_MODE_READ,            /*!< Read mode */
    SQ_CW_MODE_WRITE,           /*!< Write mode */
    SQ_CW_MODE_SENTINEL,        /*!< Sentinel of the list */
} sq_OpenMode;

/** Stat build about open content during compression (writting).
 */
typedef struct {
    gint64          size;               /*!< Size of content */
    sq_ChecksumType checksum_type;      /*!< Checksum type */
    char            *checksum;          /*!< Checksum */
    gint64          hdr_size;           /*!< Size of content */
    sq_ChecksumType hdr_checksum_type;  /*!< Checksum type */
    char            *hdr_checksum;      /*!< Checksum */
} sq_ContentStat;

/** Creates new sq_ContentStat object
 * @param type      Type of checksum. (if SQ_CHECKSUM_UNKNOWN is used,
 *                  no checksum calculation will be done)
 * @param err       GError **
 * @return          sq_ContentStat object
 */
sq_ContentStat *sq_contentstat_new(sq_ChecksumType type, GError **err);

/** Frees sq_ContentStat object.
 * @param cstat     sq_ContentStat object
 * @param err       GError **
 */
void sq_contentstat_free(sq_ContentStat *cstat, GError **err);

/** Structure represents a compressed file.
 */
typedef struct {
    sq_CompressionType  type;           /*!< Type of compression */
    void                *FILE;          /*!< Pointer to gzFile, BZFILE, ... */
    void                *INNERFILE;     /*!< Pointer to underlying FILE */
    sq_OpenMode         mode;           /*!< Mode */
    sq_ContentStat      *stat;          /*!< Content stats */
    sq_ChecksumCtx      *checksum_ctx;  /*!< Checksum contenxt */
} SQ_FILE;

#define SQ_CW_ERR       -1      /*!< Return value - Error */

/** Returns a common suffix for the specified sq_CompressionType.
 * @param comtype       compression type
 * @return              common file suffix
 */
const char *sq_compression_suffix(sq_CompressionType comtype);

/** Detect a compression type of the specified file.
 * @param filename      filename
 * @param err           GError **
 * @return              detected type of compression
 */
sq_CompressionType sq_detect_compression(const char* filename, GError **err);

/** Return compression type.
 * @param name      compression name
 * @return          compression type
 */
sq_CompressionType sq_compression_type(const char *name);

/** Open/Create the specified file.
 * @param FILENAME      filename
 * @param MODE          open mode
 * @param COMTYPE       type of compression
 * @param ERR           GError **
 * @return              pointer to a SQ_FILE or NULL
 */
#define sq_open(FILENAME, MODE, COMTYPE, ERR) \
                    sq_sopen(FILENAME, MODE, COMTYPE, NULL, ERR)

/** Open/Create the specified file. If opened for writting, you can pass
 * a sq_ContentStat object and after sq_close() get stats of
 * an open content (stats of uncompressed content).
 * @param filename      filename
 * @param mode          open mode
 * @param comtype       type of compression
 * @param stat          pointer to sq_ContentStat or NULL
 * @param err           GError **
 * @return              pointer to a SQ_FILE or NULL
 */
SQ_FILE *sq_sopen(const char *filename,
                  sq_OpenMode mode,
                  sq_CompressionType comtype,
                  sq_ContentStat *stat,
                  GError **err);

/** Sets the compression dictionary for a file
 * @param sq_file       SQ_FILE pointer
 * @param dict          dictionary
 * @param len           length of dictionary
 * @param err           GError **
 * @return              CRE_OK or SQ_CW_ERR (-1)
 */
int sq_set_dict(SQ_FILE *sq_file, const void *dict, unsigned int len, GError **err);

/** Reads an array of len bytes from the SQ_FILE.
 * @param sq_file       SQ_FILE pointer
 * @param buffer        target buffer
 * @param len           number of bytes to read
 * @param err           GError **
 * @return              number of readed bytes or SQ_CW_ERR (-1)
 */
int sq_read(SQ_FILE *sq_file, void *buffer, unsigned int len, GError **err);

/** Writes the array of len bytes from buffer to the sq_file.
 * @param sq_file       SQ_FILE pointer
 * @param buffer        source buffer
 * @param len           number of bytes to read
 * @param err           GError **
 * @return              number of uncompressed bytes readed (0 = EOF)
 *                      or SQ_CW_ERR (-1)
 */
int sq_write(SQ_FILE *sq_file,
             const void *buffer,
             unsigned int len,
             GError **err);

/** Writes the string pointed by str into the sq_file.
 * @param sq_file       SQ_FILE pointer
 * @param str           null terminated ('\0') string
 * @param err           GError **
 * @return              number of uncompressed bytes writed or SQ_CW_ERR
 */
int sq_puts(SQ_FILE *sq_file, const char *str, GError **err);

/** If compression format allows ending of chunks, tell it to end chunk
 * @param sq_file       SQ_FILE pointer
 * @param err           GError **
 * @return              CRE_OK or SQ_CW_ERR
 */
int sq_end_chunk(SQ_FILE *sq_file, GError **err);

/** Set zchunk auto-chunk algorithm.  Must be done before first byte is written
 * @param sq_file       SQ_FILE pointer
 * @param auto_chunk    Whether auto-chunking should be enabled
 * @param err           GError **
 * @return              CRE_OK or SQ_CW_ERR
 */
int sq_set_autochunk(SQ_FILE *sq_file, gboolean auto_chunk, GError **err);

/** Get specific zchunks data indentified by index
 * @param sq_file       SQ_FILE pointer
 * @param zchunk_index  Index of wanted zchunk
 * @param copy_buf      Output pointer, upon return contains wanted zchunk data
 * @param err           GError **
 * @return              Size of data from zchunk indexed by zchunk_index
 */
ssize_t sq_get_zchunk_with_index(SQ_FILE *f, ssize_t zchunk_index, char **copy_buf, GError **err);

/** Writes a formatted string into the sq_file.
 * @param err           GError **
 * @param sq_file       SQ_FILE pointer
 * @param format        format string
 * @param ...           list of additional arguments as specified in format
 * @return              Number of bytes written or SQ_CW_ERR (-1)
 */
int sq_printf(GError **err, SQ_FILE *sq_file, const char *format, ...);

/** Closes the SQ_FILE.
 * @param sq_file       SQ_FILE pointer
 * @param err           GError **
 * @return              sq_Error code
 */
int sq_close(SQ_FILE *sq_file, GError **err);

/** @} */



G_END_DECLS
