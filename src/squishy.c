/* squishy.c
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

#include "config.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <magic.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>
#ifdef WITH_ZCHUNK
#include <zck.h>
#endif  // WITH_ZCHUNK
#include "error.h"
#include "squishy.h"

#define ERR_DOMAIN                      CREATEREPO_C_ERROR

/*
#define Z_SQ_CW_NO_COMPRESSION          0
#define Z_BEST_SPEED                    1
#define Z_BEST_COMPRESSION              9
#define Z_DEFAULT_COMPRESSION           (-1)
*/
#define SQ_CW_GZ_COMPRESSION_LEVEL      Z_DEFAULT_COMPRESSION

/*
#define Z_FILTERED            1
#define Z_HUFFMAN_ONLY        2
#define Z_RLE                 3
#define Z_FIXED               4
#define Z_DEFAULT_STRATEGY    0
*/
#define GZ_STRATEGY             Z_DEFAULT_STRATEGY
#define GZ_BUFFER_SIZE          (1024*128)

#define BZ2_VERBOSITY           0
#define BZ2_BLOCKSIZE100K       5  // Higher gives better compression but takes
                                   // more memory
#define BZ2_WORK_FACTOR         0  // 0 == default == 30 (available 0-250)
#define BZ2_USE_LESS_MEMORY     0
#define BZ2_SKIP_FFLUSH         0

/*
number 0..9
or
LZMA_PRESET_DEFAULT default preset
LZMA_PRESET_EXTREME significantly slower, improving the compression ratio
                    marginally
*/
#define SQ_CW_XZ_COMPRESSION_LEVEL    5

/*
LZMA_CHECK_NONE
LZMA_CHECK_CRC32
LZMA_CHECK_CRC64
LZMA_CHECK_SHA256
*/
#define XZ_CHECK                LZMA_CHECK_CRC32

/* UINT64_MAX effectively disable the limiter */
#define XZ_MEMORY_USAGE_LIMIT   UINT64_MAX
#define XZ_DECODER_FLAGS        0
#define XZ_BUFFER_SIZE          (1024*32)

#if ZLIB_VERNUM < 0x1240
// XXX: Zlib has gzbuffer since 1.2.4
#define gzbuffer(a,b) 0
#endif

sq_ContentStat *
sq_contentstat_new(sq_ChecksumType type, GError **err)
{
    sq_ContentStat *cstat;

    assert(!err || *err == NULL);

    cstat = g_malloc0(sizeof(sq_ContentStat));
    cstat->checksum_type = type;

    return cstat;
}

void
sq_contentstat_free(sq_ContentStat *cstat, GError **err)
{
    assert(!err || *err == NULL);

    if (!cstat)
        return;

    g_free(cstat->hdr_checksum);
    g_free(cstat->checksum);
    g_free(cstat);
}

typedef struct {
    lzma_stream stream;
    FILE *file;
    unsigned char buffer[XZ_BUFFER_SIZE];
} XzFile;

sq_CompressionType
sq_detect_compression(const char *filename, GError **err)
{
    sq_CompressionType type = SQ_CW_UNKNOWN_COMPRESSION;

    assert(filename);
    assert(!err || *err == NULL);

    if (!g_file_test(filename, G_FILE_TEST_IS_REGULAR)) {
        g_debug("%s: File %s doesn't exists or not a regular file",
                __func__, filename);
        g_set_error(err, ERR_DOMAIN, SQE_NOFILE,
                    "File %s doesn't exists or not a regular file", filename);
        return SQ_CW_UNKNOWN_COMPRESSION;
    }

    // Try determine compression type via filename suffix

    if (g_str_has_suffix(filename, ".gz") ||
        g_str_has_suffix(filename, ".gzip") ||
        g_str_has_suffix(filename, ".gunzip"))
    {
        return SQ_CW_GZ_COMPRESSION;
    } else if (g_str_has_suffix(filename, ".bz2") ||
               g_str_has_suffix(filename, ".bzip2"))
    {
        return SQ_CW_BZ2_COMPRESSION;
    } else if (g_str_has_suffix(filename, ".xz"))
    {
        return SQ_CW_XZ_COMPRESSION;
    } else if (g_str_has_suffix(filename, ".zck"))
    {
        return SQ_CW_ZCK_COMPRESSION;
    } else if (g_str_has_suffix(filename, ".xml") ||
               g_str_has_suffix(filename, ".tar") ||
               g_str_has_suffix(filename, ".sqlite"))
    {
        return SQ_CW_NO_COMPRESSION;
    }


    // No success? Let's get hardcore... (Use magic bytes)

    magic_t myt = magic_open(MAGIC_MIME);
    if (myt == NULL) {
        g_set_error(err, ERR_DOMAIN, SQE_MAGIC,
                    "magic_open() failed: Cannot allocate the magic cookie");
        return SQ_CW_UNKNOWN_COMPRESSION;
    }

    if (magic_load(myt, NULL) == -1) {
        g_set_error(err, ERR_DOMAIN, SQE_MAGIC,
                    "magic_load() failed: %s", magic_error(myt));
        return SQ_CW_UNKNOWN_COMPRESSION;
    }

    const char *mime_type = magic_file(myt, filename);

    if (mime_type) {
        g_debug("%s: Detected mime type: %s (%s)", __func__, mime_type,
                filename);

        if (g_str_has_prefix(mime_type, "application/x-gzip") ||
            g_str_has_prefix(mime_type, "application/gzip") ||
            g_str_has_prefix(mime_type, "application/gzip-compressed") ||
            g_str_has_prefix(mime_type, "application/gzipped") ||
            g_str_has_prefix(mime_type, "application/x-gzip-compressed") ||
            g_str_has_prefix(mime_type, "application/x-compress") ||
            g_str_has_prefix(mime_type, "application/x-gzip") ||
            g_str_has_prefix(mime_type, "application/x-gunzip") ||
            g_str_has_prefix(mime_type, "multipart/x-gzip"))
        {
            type = SQ_CW_GZ_COMPRESSION;
        }

        else if (g_str_has_prefix(mime_type, "application/x-bzip2") ||
                 g_str_has_prefix(mime_type, "application/x-bz2") ||
                 g_str_has_prefix(mime_type, "application/bzip2") ||
                 g_str_has_prefix(mime_type, "application/bz2"))
        {
            type = SQ_CW_BZ2_COMPRESSION;
        }

        else if (g_str_has_prefix(mime_type, "application/x-xz"))
        {
            type = SQ_CW_XZ_COMPRESSION;
        }

        else if (g_str_has_prefix(mime_type, "text/plain") ||
                 g_str_has_prefix(mime_type, "text/xml") ||
                 g_str_has_prefix(mime_type, "application/xml") ||
                 g_str_has_prefix(mime_type, "application/x-xml") ||
                 g_str_has_prefix(mime_type, "application/x-empty") ||
                 g_str_has_prefix(mime_type, "application/x-tar") ||
                 g_str_has_prefix(mime_type, "inode/x-empty"))
        {
            type = SQ_CW_NO_COMPRESSION;
        }
    } else {
        g_debug("%s: Mime type not detected! (%s): %s", __func__, filename,
                magic_error(myt));
        g_set_error(err, ERR_DOMAIN, SQE_MAGIC,
                    "mime_type() detection failed: %s", magic_error(myt));
        magic_close(myt);
        return SQ_CW_UNKNOWN_COMPRESSION;
    }


    // Xml detection

    if (type == SQ_CW_UNKNOWN_COMPRESSION && g_str_has_suffix(filename, ".xml"))
        type = SQ_CW_NO_COMPRESSION;


    magic_close(myt);

    return type;
}

sq_CompressionType
sq_compression_type(const char *name)
{
    if (!name)
        return SQ_CW_UNKNOWN_COMPRESSION;

    int type = SQ_CW_UNKNOWN_COMPRESSION;
    gchar *name_lower = g_strdup(name);
    for (gchar *c = name_lower; *c; c++)
        *c = tolower(*c);

    if (!g_strcmp0(name_lower, "gz") || !g_strcmp0(name_lower, "gzip"))
        type = SQ_CW_GZ_COMPRESSION;
    if (!g_strcmp0(name_lower, "bz2") || !g_strcmp0(name_lower, "bzip2"))
        type = SQ_CW_BZ2_COMPRESSION;
    if (!g_strcmp0(name_lower, "xz"))
        type = SQ_CW_XZ_COMPRESSION;
    if (!g_strcmp0(name_lower, "zck"))
        type = SQ_CW_ZCK_COMPRESSION;
    g_free(name_lower);

    return type;
}

const char *
sq_compression_suffix(sq_CompressionType comtype)
{
    switch (comtype) {
        case SQ_CW_GZ_COMPRESSION:
            return ".gz";
        case SQ_CW_BZ2_COMPRESSION:
            return ".bz2";
        case SQ_CW_XZ_COMPRESSION:
            return ".xz";
        case SQ_CW_ZCK_COMPRESSION:
            return ".zck";
        default:
            return NULL;
    }
}


static const char *
sq_gz_strerror(gzFile f)
{
    int errnum;
    const char *msg = gzerror(f, &errnum);
    if (errnum == Z_ERRNO)
        msg = g_strerror(errno);
    return msg;
}

#ifdef WITH_ZCHUNK
sq_ChecksumType
sq_cktype_from_zck(zckCtx *zck, GError **err)
{
    int cktype = zck_get_full_hash_type(zck);
    if (cktype < 0) {
        g_set_error(err, ERR_DOMAIN, SQE_ZCK,
                    "Unable to read hash from zchunk file");
        return SQ_CHECKSUM_UNKNOWN;
    }
    if (cktype == ZCK_HASH_SHA1)
        return SQ_CHECKSUM_SHA1;
    else if (cktype == ZCK_HASH_SHA256)
        return SQ_CHECKSUM_SHA256;
    else {
        const char *ckname = zck_hash_name_from_type(cktype);
        if (ckname == NULL)
            ckname = "Unknown";
        g_set_error(err, ERR_DOMAIN, SQE_ZCK,
                    "Unknown zchunk checksum type: %s", ckname);
        return SQ_CHECKSUM_UNKNOWN;
    }
}
#endif // WITH_ZCHUNK

SQ_FILE *
sq_sopen(const char *filename,
         sq_OpenMode mode,
         sq_CompressionType comtype,
         sq_ContentStat *stat,
         GError **err)
{
    SQ_FILE *file = NULL;
    sq_CompressionType type = comtype;
    GError *tmp_err = NULL;

    assert(filename);
    assert(mode == SQ_CW_MODE_READ || mode == SQ_CW_MODE_WRITE);
    assert(mode < SQ_CW_MODE_SENTINEL);
    assert(comtype < SQ_CW_COMPRESSION_SENTINEL);
    assert(!err || *err == NULL);

    if (mode == SQ_CW_MODE_WRITE) {
        if (comtype == SQ_CW_AUTO_DETECT_COMPRESSION) {
            g_debug("%s: SQ_CW_AUTO_DETECT_COMPRESSION cannot be used if "
                    "mode is SQ_CW_MODE_WRITE", __func__);
            assert(0);
            g_set_error(err, ERR_DOMAIN, SQE_ASSERT,
                        "SQ_CW_AUTO_DETECT_COMPRESSION cannot be used if "
                        "mode is SQ_CW_MODE_WRITE");
            return NULL;
        }

        if (comtype == SQ_CW_UNKNOWN_COMPRESSION) {
            g_debug("%s: SQ_CW_UNKNOWN_COMPRESSION cannot be used if mode"
                    " is SQ_CW_MODE_WRITE", __func__);
            assert(0);
            g_set_error(err, ERR_DOMAIN, SQE_ASSERT,
                        "SQ_CW_UNKNOWN_COMPRESSION cannot be used if mode "
                        "is SQ_CW_MODE_WRITE");
            return NULL;
        }
    }


    if (comtype == SQ_CW_AUTO_DETECT_COMPRESSION) {
        // Try to detect type of compression
        type = sq_detect_compression(filename, &tmp_err);
        if (tmp_err) {
            // Error while detection
            g_propagate_error(err, tmp_err);
            return NULL;
        }
    }

    if (type == SQ_CW_UNKNOWN_COMPRESSION) {
        // Detection without error but compression type is unknown
        g_debug("%s: Cannot detect compression type", __func__);
        g_set_error(err, ERR_DOMAIN, SQE_UNKNOWNCOMPRESSION,
                    "Cannot detect compression type");
        return NULL;
    }


    // Open file

    const char *mode_str = (mode == SQ_CW_MODE_WRITE) ? "wb" : "rb";

    file = g_malloc0(sizeof(SQ_FILE));
    file->mode = mode;
    file->type = type;
    file->INNERFILE = NULL;

    switch (type) {

        case (SQ_CW_NO_COMPRESSION): // ---------------------------------------
            mode_str = (mode == SQ_CW_MODE_WRITE) ? "w" : "r";
            file->FILE = (void *) fopen(filename, mode_str);
            if (!file->FILE)
                g_set_error(err, ERR_DOMAIN, SQE_IO,
                            "fopen(): %s", g_strerror(errno));
            break;

        case (SQ_CW_GZ_COMPRESSION): // ---------------------------------------
            file->FILE = (void *) gzopen(filename, mode_str);
            if (!file->FILE) {
                g_set_error(err, ERR_DOMAIN, SQE_GZ,
                            "gzopen(): %s", g_strerror(errno));
                break;
            }

            if (mode == SQ_CW_MODE_WRITE)
                gzsetparams((gzFile) file->FILE,
                            SQ_CW_GZ_COMPRESSION_LEVEL,
                            GZ_STRATEGY);

            if (gzbuffer((gzFile) file->FILE, GZ_BUFFER_SIZE) == -1) {
                g_debug("%s: gzbuffer() call failed", __func__);
                g_set_error(err, ERR_DOMAIN, SQE_GZ,
                            "gzbuffer() call failed");
            }
            break;

        case (SQ_CW_BZ2_COMPRESSION): { // ------------------------------------
            FILE *f = fopen(filename, mode_str);
            file->INNERFILE = f;
            int bzerror;

            if (!f) {
                g_set_error(err, ERR_DOMAIN, SQE_IO,
                            "fopen(): %s", g_strerror(errno));
                break;
            }

            if (mode == SQ_CW_MODE_WRITE) {
                file->FILE = (void *) BZ2_bzWriteOpen(&bzerror,
                                                      f,
                                                      BZ2_BLOCKSIZE100K,
                                                      BZ2_VERBOSITY,
                                                      BZ2_WORK_FACTOR);
            } else {
                file->FILE = (void *) BZ2_bzReadOpen(&bzerror,
                                                     f,
                                                     BZ2_VERBOSITY,
                                                     BZ2_USE_LESS_MEMORY,
                                                     NULL, 0);
            }

            if (bzerror != BZ_OK) {
                const char *err_msg;

                fclose(f);

                switch (bzerror) {
                    case BZ_CONFIG_ERROR:
                        err_msg = "library has been mis-compiled";
                        break;
                    case BZ_PARAM_ERROR:
                        err_msg = "bad function params";
                        break;
                    case BZ_IO_ERROR:
                        err_msg = "ferror(f) is nonzero";
                        break;
                    case BZ_MEM_ERROR:
                        err_msg = "insufficient memory is available";
                        break;
                    default:
                        err_msg = "other error";
                }

                g_set_error(err, ERR_DOMAIN, SQE_BZ2,
                            "Bz2 error: %s", err_msg);
            }

            break;
        }

        case (SQ_CW_XZ_COMPRESSION): { // -------------------------------------
            int ret;
            XzFile *xz_file = g_malloc(sizeof(XzFile));
            lzma_stream *stream = &(xz_file->stream);
            memset(stream, 0, sizeof(lzma_stream));
            /* ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ XXX: This part
             is a little tricky. Because in the default initializer
             LZMA_STREAM_INIT are some items NULL and (according to C standard)
             NULL may have different internal representation than zero.
             This should not be a problem nowadays.
            */

            // Prepare coder/decoder

            if (mode == SQ_CW_MODE_WRITE) {

#ifdef ENABLE_THREADED_XZ_ENCODER
                // The threaded encoder takes the options as pointer to
                // a lzma_mt structure.
                lzma_mt mt = {
                    // No flags are needed.
                    .flags = 0,

                    // Let liblzma determine a sane block size.
                    .block_size = 0,

                    // Use no timeout for lzma_code() calls by setting timeout
                    // to zero. That is, sometimes lzma_code() might block for
                    // a long time (from several seconds to even minutes).
                    // If this is not OK, for example due to progress indicator
                    // needing updates, specify a timeout in milliseconds here.
                    // See the documentation of lzma_mt in lzma/container.h for
                    // information how to choose a reasonable timeout.
                    .timeout = 0,

                    // Use the default preset (6) for LZMA2.
                    // To use a preset, filters must be set to NULL.
                    .preset = LZMA_PRESET_DEFAULT,
                    .filters = NULL,

                    // Integrity checking.
                    .check = XZ_CHECK,
                };

                // Detect how many threads the CPU supports.
                mt.threads = lzma_cputhreads();

                // If the number of CPU cores/threads cannot be detected,
                // use one thread.
                if (mt.threads == 0)
                    mt.threads = 1;

                // If the number of CPU cores/threads exceeds threads_max,
                // limit the number of threads to keep memory usage lower.
                const uint32_t threads_max = 2;
                if (mt.threads > threads_max)
                    mt.threads = threads_max;

                if (mt.threads > 1)
                    // Initialize the threaded encoder
                    ret = lzma_stream_encoder_mt(stream, &mt);
                else
#endif
                    // Initialize the single-threaded encoder
                    ret = lzma_easy_encoder(stream,
                                            SQ_CW_XZ_COMPRESSION_LEVEL,
                                            XZ_CHECK);

            } else {
                ret = lzma_auto_decoder(stream,
                                        XZ_MEMORY_USAGE_LIMIT,
                                        XZ_DECODER_FLAGS);
            }

            if (ret != LZMA_OK) {
                const char *err_msg;

                switch (ret) {
                    case LZMA_MEM_ERROR:
                        err_msg = "Cannot allocate memory";
                        break;
                    case LZMA_OPTIONS_ERROR:
                        err_msg = "Unsupported flags (options)";
                        break;
                    case LZMA_PROG_ERROR:
                        err_msg = "One or more of the parameters "
                                  "have values that will never be valid. "
                                  "(Possibly a bug)";
                        break;
                    case LZMA_UNSUPPORTED_CHECK:
		        err_msg = "Specified integrity check is not supported";
		        break;
                    default:
                        err_msg = "Unknown error";
                }

                g_set_error(err, ERR_DOMAIN, SQE_XZ,
                            "XZ error (%d): %s", ret, err_msg);
                g_free((void *) xz_file);
                break;
            }

            // Open input/output file

            FILE *f = fopen(filename, mode_str);
            if (!f) {
                g_set_error(err, ERR_DOMAIN, SQE_XZ,
                            "fopen(): %s", g_strerror(errno));
                lzma_end(&(xz_file->stream));
                g_free((void *) xz_file);
                break;
            }

            xz_file->file = f;
            file->FILE = (void *) xz_file;
            break;
        }
        case (SQ_CW_ZCK_COMPRESSION): { // -------------------------------------
#ifdef WITH_ZCHUNK
            FILE *f = fopen(filename, mode_str);
            file->INNERFILE = f;
            int fd = fileno(f);

            if (!f) {
                g_set_error(err, ERR_DOMAIN, SQE_IO,
                            "fopen(): %s", g_strerror(errno));
                break;
            }

            file->FILE = (void *) zck_create();
            zckCtx *zck = file->FILE;
            if (mode == SQ_CW_MODE_WRITE) {
                if (!file->FILE || !zck_init_write(zck, fd) ||
                   !zck_set_ioption(zck, ZCK_MANUAL_CHUNK, 1)) {
                    zck_set_log_fd(STDOUT_FILENO);
                    g_set_error(err, ERR_DOMAIN, SQE_IO, "%s",
                                zck_get_error(zck));
                    g_free(file);
                    break;
                }
            } else {
                if (!file->FILE || !zck_init_read(zck, fd)) {
                    g_set_error(err, ERR_DOMAIN, SQE_IO,
                                "%s", zck_get_error(zck));
                    g_free(file);
                    break;
                }
            }
            break;
#else
            g_set_error(err, ERR_DOMAIN, SQE_IO, "createrepo_c wasn't compiled "
                        "with zchunk support");
            break;
#endif // WITH_ZCHUNK
        }

        default: // -----------------------------------------------------------
            break;
    }

    if (!file->FILE) {
        // File is not open -> cleanup
        if (err && *err == NULL)
            g_set_error(err, ERR_DOMAIN, SQE_XZ,
                        "Unknown error while opening: %s", filename);
        g_free(file);
        return NULL;
    }

    if (stat) {
        file->stat = stat;

        if (stat->checksum_type == SQ_CHECKSUM_UNKNOWN) {
            file->checksum_ctx = NULL;
        } else {
            file->checksum_ctx = sq_checksum_new(stat->checksum_type,
                                                 &tmp_err);
            if (tmp_err) {
                g_propagate_error(err, tmp_err);
                sq_close(file, NULL);
                return NULL;
            }
        }

#ifdef WITH_ZCHUNK
        /* Fill zchunk header_stat with header information */
        if (mode == SQ_CW_MODE_READ && type == SQ_CW_ZCK_COMPRESSION) {
            zckCtx *zck = (zckCtx *)file->FILE;
            sq_ChecksumType cktype = sq_cktype_from_zck(zck, err);
            if (cktype == SQ_CHECKSUM_UNKNOWN) {
                /* Error is already set in sq_cktype_from_zck */
                g_free(file);
                return NULL;
            }
            file->stat->hdr_checksum_type = cktype;
            file->stat->hdr_checksum = zck_get_header_digest(zck);
            file->stat->hdr_size = zck_get_header_length(zck);
            if (*err != NULL || file->stat->hdr_checksum == NULL ||
               file->stat->hdr_size < 0) {
                g_free(file);
                return NULL;
            }
        }
#endif // WITH_ZCHUNK
    }

    assert(!err || (!file && *err != NULL) || (file && *err == NULL));

    return file;
}

int
sq_set_dict(SQ_FILE *sq_file, const void *dict, unsigned int len, GError **err)
{
    int ret = SQE_OK;
    assert(!err || *err == NULL);

    if (len == 0)
        return SQE_OK;

    switch (sq_file->type) {

        case (SQ_CW_ZCK_COMPRESSION): { // ------------------------------------
#ifdef WITH_ZCHUNK
            zckCtx *zck = (zckCtx *)sq_file->FILE;
            size_t wlen = (size_t)len;
            if (!zck_set_soption(zck, ZCK_COMP_DICT, dict, wlen)) {
                ret = SQE_ERROR;
                g_set_error(err, ERR_DOMAIN, SQE_ZCK,
                            "Error setting dict");
                break;
            }
            break;
#else
            g_set_error(err, ERR_DOMAIN, SQE_IO, "createrepo_c wasn't compiled "
                        "with zchunk support");
            break;
#endif // WITH_ZCHUNK
        }

        default: { // ---------------------------------------------------------
            ret = SQE_ERROR;
            g_set_error(err, ERR_DOMAIN, SQE_ERROR,
                            "Compression format doesn't support dict");
            break;
        }

    }
    return ret;
}

int
sq_close(SQ_FILE *sq_file, GError **err)
{
    int ret = SQE_ERROR;
    int rc;

    assert(!err || *err == NULL);

    if (!sq_file)
        return SQE_OK;

    switch (sq_file->type) {

        case (SQ_CW_NO_COMPRESSION): // ---------------------------------------
            if (fclose((FILE *) sq_file->FILE) == 0) {
                ret = SQE_OK;
            } else {
                ret = SQE_IO;
                g_set_error(err, ERR_DOMAIN, SQE_IO,
                            "fclose(): %s", g_strerror(errno));
            }
            break;

        case (SQ_CW_GZ_COMPRESSION): // ---------------------------------------
            rc = gzclose((gzFile) sq_file->FILE);
            if (rc == Z_OK)
                ret = SQE_OK;
            else {
                const char *err_msg;
                switch (rc) {
                    case Z_STREAM_ERROR:
                        err_msg = "file is not valid";
                        break;
                    case Z_ERRNO:
                        err_msg = "file operation error";
                        break;
                    case Z_MEM_ERROR:
                        err_msg = "if out of memory";
                        break;
                    case Z_BUF_ERROR:
                        err_msg = "last read ended in the middle of a stream";
                        break;
                    default:
                        err_msg = "error";
                }

                ret = SQE_GZ;
                g_set_error(err, ERR_DOMAIN, SQE_GZ,
                    "gzclose(): %s", err_msg);
            }
            break;

        case (SQ_CW_BZ2_COMPRESSION): // --------------------------------------
            if (sq_file->mode == SQ_CW_MODE_READ)
                BZ2_bzReadClose(&rc, (BZFILE *) sq_file->FILE);
            else
                BZ2_bzWriteClose(&rc, (BZFILE *) sq_file->FILE,
                                 BZ2_SKIP_FFLUSH, NULL, NULL);

            fclose(sq_file->INNERFILE);

            if (rc == BZ_OK) {
                ret = SQE_OK;
            } else {
                const char *err_msg;

                switch (rc) {
                    case BZ_SEQUENCE_ERROR:
                        // This really shoud not happen
                        err_msg = "file was opened with BZ2_bzReadOpen";
                        break;
                    case BZ_IO_ERROR:
                        err_msg = "error writing the compressed file";
                        break;
                    default:
                        err_msg = "other error";
                }

                ret = SQE_BZ2;
                g_set_error(err, ERR_DOMAIN, SQE_BZ2,
                            "Bz2 error: %s", err_msg);
            }
            break;

        case (SQ_CW_XZ_COMPRESSION): { // -------------------------------------
            XzFile *xz_file = (XzFile *) sq_file->FILE;
            lzma_stream *stream = &(xz_file->stream);

            if (sq_file->mode == SQ_CW_MODE_WRITE) {
                // Write out rest of buffer
                while (1) {
                    stream->next_out = (uint8_t*) xz_file->buffer;
                    stream->avail_out = XZ_BUFFER_SIZE;

                    rc = lzma_code(stream, LZMA_FINISH);

                    if (rc != LZMA_OK && rc != LZMA_STREAM_END) {
                        // Error while coding
                        const char *err_msg;

                        switch (rc) {
                            case LZMA_MEM_ERROR:
                                err_msg = "Memory allocation failed";
                                break;
                            case LZMA_DATA_ERROR:
                                // This error is returned if the compressed
                                // or uncompressed size get near 8 EiB
                                // (2^63 bytes) because that's where the .xz
                                // file format size limits currently are.
                                // That is, the possibility of this error
                                // is mostly theoretical unless you are doing
                                // something very unusual.
                                //
                                // Note that strm->total_in and strm->total_out
                                // have nothing to do with this error. Changing
                                // those variables won't increase or decrease
                                // the chance of getting this error.
                                err_msg = "File size limits exceeded";
                                break;
                            default:
                                // This is most likely LZMA_PROG_ERROR.
                                err_msg = "Unknown error, possibly a bug";
                                break;
                        }

                        ret = SQE_XZ;
                        g_set_error(err, ERR_DOMAIN, SQE_XZ,
                                    "XZ: lzma_code() error (%d): %s",
                                    rc, err_msg);
                        break;
                    }

                    size_t olen = XZ_BUFFER_SIZE - stream->avail_out;
                    if (fwrite(xz_file->buffer, 1, olen, xz_file->file) != olen) {
                        // Error while writing
                        ret = SQE_XZ;
                        g_set_error(err, ERR_DOMAIN, SQE_XZ,
                                    "XZ: fwrite() error: %s", g_strerror(errno));
                        break;
                    }

                    if (rc == LZMA_STREAM_END) {
                        // Everything all right
                        ret = SQE_OK;
                        break;
                    }
                }
            } else {
                ret = SQE_OK;
            }

            fclose(xz_file->file);
            lzma_end(stream);
            g_free(stream);
            break;
        }
        case (SQ_CW_ZCK_COMPRESSION): { // ------------------------------------
#ifdef WITH_ZCHUNK
            zckCtx *zck = (zckCtx *) sq_file->FILE;
            ret = SQE_OK;
            if (sq_file->mode == SQ_CW_MODE_WRITE) {
                if (zck_end_chunk(zck) < 0) {
                    ret = SQE_ZCK;
                    g_set_error(err, ERR_DOMAIN, SQE_ZCK,
                        "Unable to end final chunk: %s", zck_get_error(zck));
                }
            }
            if (!zck_close(zck)) {
                ret = SQE_ZCK;
                g_set_error(err, ERR_DOMAIN, SQE_ZCK,
                        "Unable to close zchunk file: %s", zck_get_error(zck));
            }
            sq_ChecksumType cktype = sq_cktype_from_zck(zck, err);
            if (cktype == SQ_CHECKSUM_UNKNOWN) {
                /* Error is already set in sq_cktype_from_zck */
                break;
            }
            if (sq_file->stat) {
                sq_file->stat->hdr_checksum_type = cktype;
                sq_file->stat->hdr_checksum = zck_get_header_digest(zck);
                sq_file->stat->hdr_size = zck_get_header_length(zck);
                if ((err && *err) || sq_file->stat->hdr_checksum == NULL ||
                   sq_file->stat->hdr_size < 0) {
                    ret = SQE_ZCK;
                    g_set_error(err, ERR_DOMAIN, SQE_ZCK,
                                "Unable to get zchunk header information: %s",
                                zck_get_error(zck));
                    break;
                }
            }
            zck_free(&zck);
            fclose(sq_file->INNERFILE);
            break;
#else
            g_set_error(err, ERR_DOMAIN, SQE_IO, "createrepo_c wasn't compiled "
                        "with zchunk support");
            break;
#endif // WITH_ZCHUNK
        }
        default: // -----------------------------------------------------------
            ret = SQE_BADARG;
            g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                        "Bad compressed file type");
            break;
    }

    if (sq_file->stat) {
        g_free(sq_file->stat->checksum);
        if (sq_file->checksum_ctx)
            sq_file->stat->checksum = sq_checksum_final(sq_file->checksum_ctx,
                                                        NULL);
        else
            sq_file->stat->checksum = NULL;
    }

    g_free(sq_file);

    assert(!err || (ret != SQE_OK && *err != NULL)
           || (ret == SQE_OK && *err == NULL));

    return ret;
}



int
sq_read(SQ_FILE *sq_file, void *buffer, unsigned int len, GError **err)
{
    int bzerror;
    int ret;

    assert(sq_file);
    assert(buffer);
    assert(!err || *err == NULL);

    if (sq_file->mode != SQ_CW_MODE_READ) {
        g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                    "File is not opened in read mode");
        return SQ_CW_ERR;
    }

    switch (sq_file->type) {

        case (SQ_CW_NO_COMPRESSION): // ---------------------------------------
            ret = fread(buffer, 1, len, (FILE *) sq_file->FILE);
            if ((ret != (int) len) && !feof((FILE *) sq_file->FILE)) {
                ret = SQ_CW_ERR;
                g_set_error(err, ERR_DOMAIN, SQE_IO,
                            "fread(): %s", g_strerror(errno));
            }
            break;

        case (SQ_CW_GZ_COMPRESSION): // ---------------------------------------
            ret = gzread((gzFile) sq_file->FILE, buffer, len);
            if (ret == -1) {
                ret = SQ_CW_ERR;
                g_set_error(err, ERR_DOMAIN, SQE_GZ,
                    "fread(): %s", sq_gz_strerror((gzFile) sq_file->FILE));
            }
            break;

        case (SQ_CW_BZ2_COMPRESSION): // --------------------------------------
            ret = BZ2_bzRead(&bzerror, (BZFILE *) sq_file->FILE, buffer, len);
            if (!ret && bzerror == BZ_SEQUENCE_ERROR)
                // Next read after BZ_STREAM_END (EOF)
                return 0;

            if (bzerror != BZ_OK && bzerror != BZ_STREAM_END) {
                const char *err_msg;
                ret = SQ_CW_ERR;

                switch (bzerror) {
                    case BZ_PARAM_ERROR:
                        // This shoud not happend
                        err_msg = "bad function params!";
                        break;
                    case BZ_SEQUENCE_ERROR:
                        // This shoud not happend
                        err_msg = "file was opened with BZ2_bzWriteOpen";
                        break;
                    case BZ_IO_ERROR:
                        err_msg = "error while reading from the compressed file";
                        break;
                    case BZ_UNEXPECTED_EOF:
                        err_msg = "the compressed file ended before "
                                  "the logical end-of-stream was detected";
                        break;
                    case BZ_DATA_ERROR:
                        err_msg = "data integrity error was detected in "
                                  "the compressed stream";
                        break;
                    case BZ_DATA_ERROR_MAGIC:
                        err_msg = "the stream does not begin with "
                                  "the requisite header bytes (ie, is not "
                                  "a bzip2 data file).";
                        break;
                    case BZ_MEM_ERROR:
                        err_msg = "insufficient memory was available";
                        break;
                    default:
                        err_msg = "other error";
                }

                g_set_error(err, ERR_DOMAIN, SQE_BZ2,
                            "Bz2 error: %s", err_msg);
            }
            break;

        case (SQ_CW_XZ_COMPRESSION): { // -------------------------------------
            XzFile *xz_file = (XzFile *) sq_file->FILE;
            lzma_stream *stream = &(xz_file->stream);

            stream->next_out = buffer;
            stream->avail_out = len;

            while (stream->avail_out) {
                int lret;

                // Fill input buffer
                if (stream->avail_in == 0) {
                    if ((lret = fread(xz_file->buffer, 1, XZ_BUFFER_SIZE, xz_file->file)) < 0) {
                        g_debug("%s: XZ: Error while fread", __func__);
                        g_set_error(err, ERR_DOMAIN, SQE_XZ,
                                    "XZ: fread(): %s", g_strerror(errno));
                        return SQ_CW_ERR;   // Error while reading input file
                    } else if (lret == 0) {
                        g_debug("%s: EOF", __func__);
                        break;   // EOF
                    }
                    stream->next_in = xz_file->buffer;
                    stream->avail_in = lret;
                }

                // Decode
                lret = lzma_code(stream, LZMA_RUN);

                if (lret != LZMA_OK && lret != LZMA_STREAM_END) {
                    const char *err_msg;

                    switch (lret) {
                        case LZMA_MEM_ERROR:
                            err_msg = "Memory allocation failed";
                            break;
			case LZMA_FORMAT_ERROR:
                            // .xz magic bytes weren't found.
                            err_msg = "The input is not in the .xz format";
                            break;
			case LZMA_OPTIONS_ERROR:
                            // For example, the headers specify a filter
                            // that isn't supported by this liblzma
                            // version (or it hasn't been enabled when
                            // building liblzma, but no-one sane does
                            // that unless building liblzma for an
                            // embedded system). Upgrading to a newer
                            // liblzma might help.
                            //
                            // Note that it is unlikely that the file has
                            // accidentally became corrupt if you get this
                            // error. The integrity of the .xz headers is
                            // always verified with a CRC32, so
                            // unintentionally corrupt files can be
                            // distinguished from unsupported files.
                            err_msg = "Unsupported compression options";
                            break;
			case LZMA_DATA_ERROR:
                            err_msg = "Compressed file is corrupt";
                            break;
			case LZMA_BUF_ERROR:
                            // Typically this error means that a valid
                            // file has got truncated, but it might also
                            // be a damaged part in the file that makes
                            // the decoder think the file is truncated.
                            // If you prefer, you can use the same error
                            // message for this as for LZMA_DATA_ERROR.
                            err_msg = "Compressed file is truncated or "
                                      "otherwise corrupt";
                            break;
			default:
                            // This is most likely LZMA_PROG_ERROR.
                            err_msg = "Unknown error, possibly a bug";
                            break;
                    }

                    g_debug("%s: XZ: Error while decoding (%d): %s",
                            __func__, lret, err_msg);
                    g_set_error(err, ERR_DOMAIN, SQE_XZ,
                                "XZ: Error while decoding (%d): %s",
                                lret, err_msg);
                    return SQ_CW_ERR;  // Error while decoding
                }

                if (lret == LZMA_STREAM_END)
                    break;
            }

            ret = len - stream->avail_out;
            break;
        }
        case (SQ_CW_ZCK_COMPRESSION): { // ------------------------------------
#ifdef WITH_ZCHUNK
            zckCtx *zck = (zckCtx *) sq_file->FILE;
            ssize_t rb = zck_read(zck, buffer, len);
            if (rb < 0) {
                ret = SQ_CW_ERR;
                g_set_error(err, ERR_DOMAIN, SQE_ZCK, "ZCK: Unable to read: %s",
                            zck_get_error(zck));
                break;
            }
            ret = rb;
            break;
#else
            g_set_error(err, ERR_DOMAIN, SQE_IO, "createrepo_c wasn't compiled "
                        "with zchunk support");
            break;
#endif // WITH_ZCHUNK
        }

        default: // -----------------------------------------------------------
            ret = SQ_CW_ERR;
            g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                        "Bad compressed file type");
            break;
    }

    assert(!err || (ret == SQ_CW_ERR && *err != NULL)
           || (ret != SQ_CW_ERR && *err == NULL));

    if (sq_file->stat && ret != SQ_CW_ERR) {
        sq_file->stat->size += ret;
        if (sq_file->checksum_ctx) {
            GError *tmp_err = NULL;
            sq_checksum_update(sq_file->checksum_ctx, buffer, ret, &tmp_err);
            if (tmp_err) {
                g_propagate_error(err, tmp_err);
                return SQ_CW_ERR;
            }
        }
    }

    return ret;
}



int
sq_write(SQ_FILE *sq_file, const void *buffer, unsigned int len, GError **err)
{
    int bzerror;
    int ret = SQ_CW_ERR;

    assert(sq_file);
    assert(buffer);
    assert(!err || *err == NULL);

    if (sq_file->mode != SQ_CW_MODE_WRITE) {
        g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                    "File is not opened in read mode");
        return ret;
    }

    if (sq_file->stat) {
        sq_file->stat->size += len;
        if (sq_file->checksum_ctx) {
            GError *tmp_err = NULL;
            sq_checksum_update(sq_file->checksum_ctx, buffer, len, &tmp_err);
            if (tmp_err) {
                g_propagate_error(err, tmp_err);
                return SQ_CW_ERR;
            }
        }
    }

    switch (sq_file->type) {

        case (SQ_CW_NO_COMPRESSION): // ---------------------------------------
            if ((ret = (int) fwrite(buffer, 1, len, (FILE *) sq_file->FILE)) != (int) len) {
                ret = SQ_CW_ERR;
                g_set_error(err, ERR_DOMAIN, SQE_IO,
                            "fwrite(): %s", g_strerror(errno));
            }
            break;

        case (SQ_CW_GZ_COMPRESSION): // ---------------------------------------
            if (len == 0) {
                ret = 0;
                break;
            }

            if ((ret = gzwrite((gzFile) sq_file->FILE, buffer, len)) == 0) {
                ret = SQ_CW_ERR;
                g_set_error(err, ERR_DOMAIN, SQE_GZ,
                    "gzwrite(): %s", sq_gz_strerror((gzFile) sq_file->FILE));
            }
            break;

        case (SQ_CW_BZ2_COMPRESSION): // --------------------------------------
            BZ2_bzWrite(&bzerror, (BZFILE *) sq_file->FILE, (void *) buffer, len);
            if (bzerror == BZ_OK) {
                ret = len;
            } else {
                const char *err_msg;
                ret = SQ_CW_ERR;

                switch (bzerror) {
                    case BZ_PARAM_ERROR:
                        // This shoud not happend
                        err_msg = "bad function params!";
                        break;
                    case BZ_SEQUENCE_ERROR:
                        // This shoud not happend
                        err_msg = "file was opened with BZ2_bzReadOpen";
                        break;
                    case BZ_IO_ERROR:
                        err_msg = "error while reading from the compressed file";
                        break;
                    default:
                        err_msg = "other error";
                }

                g_set_error(err, ERR_DOMAIN, SQE_BZ2,
                            "Bz2 error: %s", err_msg);
            }
            break;

        case (SQ_CW_XZ_COMPRESSION): { // -------------------------------------
            XzFile *xz_file = (XzFile *) sq_file->FILE;
            lzma_stream *stream = &(xz_file->stream);

            ret = len;
            stream->next_in = buffer;
            stream->avail_in = len;

            while (stream->avail_in) {
                int lret;
                stream->next_out = xz_file->buffer;
                stream->avail_out = XZ_BUFFER_SIZE;
                lret = lzma_code(stream, LZMA_RUN);
                if (lret != LZMA_OK) {
                    const char *err_msg;
                    ret = SQ_CW_ERR;

                    switch (lret) {
                        case LZMA_MEM_ERROR:
                            err_msg = "Memory allocation failed";
                            break;
			case LZMA_DATA_ERROR:
                            // This error is returned if the compressed
                            // or uncompressed size get near 8 EiB
                            // (2^63 bytes) because that's where the .xz
                            // file format size limits currently are.
                            // That is, the possibility of this error
                            // is mostly theoretical unless you are doing
                            // something very unusual.
                            //
                            // Note that strm->total_in and strm->total_out
                            // have nothing to do with this error. Changing
                            // those variables won't increase or decrease
                            // the chance of getting this error.
                            err_msg = "File size limits exceeded";
                            break;
			default:
                            // This is most likely LZMA_PROG_ERROR.
                            err_msg = "Unknown error, possibly a bug";
                            break;
                    }

                    g_set_error(err, ERR_DOMAIN, SQE_XZ,
                                "XZ: lzma_code() error (%d): %s",
                                lret, err_msg);
                    break;   // Error while coding
                }

                size_t out_len = XZ_BUFFER_SIZE - stream->avail_out;
                if ((fwrite(xz_file->buffer, 1, out_len, xz_file->file)) != out_len) {
                    ret = SQ_CW_ERR;
                    g_set_error(err, ERR_DOMAIN, SQE_XZ,
                                "XZ: fwrite(): %s", g_strerror(errno));
                    break;   // Error while writing
                }
            }

            break;
        }

        case (SQ_CW_ZCK_COMPRESSION): { // ------------------------------------
#ifdef WITH_ZCHUNK
            zckCtx *zck = (zckCtx *) sq_file->FILE;
            ssize_t wb = zck_write(zck, buffer, len);
            if (wb < 0) {
                ret = SQ_CW_ERR;
                g_set_error(err, ERR_DOMAIN, SQE_ZCK,
                            "ZCK: Unable to write: %s", zck_get_error(zck));
                break;
            }
            ret = wb;
            break;
#else
            g_set_error(err, ERR_DOMAIN, SQE_IO, "createrepo_c wasn't compiled "
                        "with zchunk support");
            break;
#endif // WITH_ZCHUNK
        }

        default: // -----------------------------------------------------------
            g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                        "Bad compressed file type");
            break;
    }

    assert(!err || (ret == SQ_CW_ERR && *err != NULL)
           || (ret != SQ_CW_ERR && *err == NULL));

    return ret;
}



int
sq_puts(SQ_FILE *sq_file, const char *str, GError **err)
{
    size_t len;
    int ret = SQ_CW_ERR;

    assert(sq_file);
    assert(!err || *err == NULL);

    if (!str)
        return 0;

    if (sq_file->mode != SQ_CW_MODE_WRITE) {
        g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                    "File is not opened in write mode");
        return SQ_CW_ERR;
    }

    switch (sq_file->type) {

        case (SQ_CW_NO_COMPRESSION): // ---------------------------------------
        case (SQ_CW_GZ_COMPRESSION): // ---------------------------------------
        case (SQ_CW_BZ2_COMPRESSION): // --------------------------------------
        case (SQ_CW_XZ_COMPRESSION): // ---------------------------------------
        case (SQ_CW_ZCK_COMPRESSION): // --------------------------------------
            len = strlen(str);
            ret = sq_write(sq_file, str, len, err);
            if (ret != (int) len)
                ret = SQ_CW_ERR;
            break;

        default: // -----------------------------------------------------------
            g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                        "Bad compressed file type");
            break;
    }

    assert(!err || (ret == SQ_CW_ERR && *err != NULL)
           || (ret != SQ_CW_ERR && *err == NULL));

    return ret;
}

int
sq_end_chunk(SQ_FILE *sq_file, GError **err)
{
    int ret = SQE_OK;

    assert(sq_file);
    assert(!err || *err == NULL);

    if (sq_file->mode != SQ_CW_MODE_WRITE) {
        g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                    "File is not opened in write mode");
        return SQ_CW_ERR;
    }

    switch (sq_file->type) {
        case (SQ_CW_NO_COMPRESSION): // ---------------------------------------
        case (SQ_CW_GZ_COMPRESSION): // ---------------------------------------
        case (SQ_CW_BZ2_COMPRESSION): // --------------------------------------
        case (SQ_CW_XZ_COMPRESSION): // ---------------------------------------
            break;
        case (SQ_CW_ZCK_COMPRESSION): { // ------------------------------------
#ifdef WITH_ZCHUNK
            zckCtx *zck = (zckCtx *) sq_file->FILE;
            ssize_t wb = zck_end_chunk(zck);
            if (wb < 0) {
                g_set_error(err, ERR_DOMAIN, SQE_ZCK,
                            "Error ending chunk: %s",
                            zck_get_error(zck));
                return SQ_CW_ERR;
            }
            ret = wb;
            break;
#else
            g_set_error(err, ERR_DOMAIN, SQE_IO, "createrepo_c wasn't compiled "
                        "with zchunk support");
            break;
#endif // WITH_ZCHUNK
        }

        default: // -----------------------------------------------------------
            g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                        "Bad compressed file type");
            return SQ_CW_ERR;
            break;
    }

    assert(!err || (ret == SQ_CW_ERR && *err != NULL)
           || (ret != SQ_CW_ERR && *err == NULL));

    return ret;
}

int
sq_set_autochunk(SQ_FILE *sq_file, gboolean auto_chunk, GError **err)
{
    int ret = SQE_OK;

    assert(sq_file);
    assert(!err || *err == NULL);

    if (sq_file->mode != SQ_CW_MODE_WRITE) {
        g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                    "File is not opened in write mode");
        return SQ_CW_ERR;
    }

    switch (sq_file->type) {
        case (SQ_CW_NO_COMPRESSION): // ---------------------------------------
        case (SQ_CW_GZ_COMPRESSION): // ---------------------------------------
        case (SQ_CW_BZ2_COMPRESSION): // --------------------------------------
        case (SQ_CW_XZ_COMPRESSION): // ---------------------------------------
            break;
        case (SQ_CW_ZCK_COMPRESSION): { // ------------------------------------
#ifdef WITH_ZCHUNK
            zckCtx *zck = (zckCtx *) sq_file->FILE;
            if (!zck_set_ioption(zck, ZCK_MANUAL_CHUNK, !auto_chunk)) {
                g_set_error(err, ERR_DOMAIN, SQE_ZCK,
                            "Error setting auto_chunk: %s",
                            zck_get_error(zck));
                return SQ_CW_ERR;
            }
            break;
#else
            g_set_error(err, ERR_DOMAIN, SQE_IO, "createrepo_c wasn't compiled "
                        "with zchunk support");
            break;
#endif // WITH_ZCHUNK
        }

        default: // -----------------------------------------------------------
            g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                        "Bad compressed file type");
            return SQ_CW_ERR;
            break;
    }

    assert(!err || (ret == SQ_CW_ERR && *err != NULL)
           || (ret != SQ_CW_ERR && *err == NULL));

    return ret;
}

int
sq_printf(GError **err, SQ_FILE *sq_file, const char *format, ...)
{
    va_list vl;
    int ret;
    gchar *buf = NULL;

    assert(sq_file);
    assert(!err || *err == NULL);

    if (!format)
        return 0;

    if (sq_file->mode != SQ_CW_MODE_WRITE) {
        g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                    "File is not opened in write mode");
        return SQ_CW_ERR;
    }

    // Fill format string
    va_start(vl, format);
    ret = g_vasprintf(&buf, format, vl);
    va_end(vl);

    if (ret < 0) {
        g_debug("%s: vasprintf() call failed", __func__);
        g_set_error(err, ERR_DOMAIN, SQE_MEMORY,
                    "vasprintf() call failed");
        return SQ_CW_ERR;
    }

    assert(buf);

    int tmp_ret;

    switch (sq_file->type) {

        case (SQ_CW_NO_COMPRESSION): // ---------------------------------------
        case (SQ_CW_GZ_COMPRESSION): // ---------------------------------------
        case (SQ_CW_BZ2_COMPRESSION): // --------------------------------------
        case (SQ_CW_XZ_COMPRESSION): // ---------------------------------------
        case (SQ_CW_ZCK_COMPRESSION): // --------------------------------------
            tmp_ret = sq_write(sq_file, buf, ret, err);
            if (tmp_ret != (int) ret)
                ret = SQ_CW_ERR;
            break;

        default: // -----------------------------------------------------------
            ret = SQ_CW_ERR;
            g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                        "Bad compressed file type");
            break;
    }

    g_free(buf);

    assert(!err || (ret == SQ_CW_ERR && *err != NULL)
           || (ret != SQ_CW_ERR && *err == NULL));

    return ret;
}

ssize_t
sq_get_zchunk_with_index(SQ_FILE *sq_file, ssize_t zchunk_index, char **copy_buf, GError **err)
{
    assert(sq_file);
    assert(!err || *err == NULL);
    if (sq_file->mode != SQ_CW_MODE_READ) {
        g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                    "File is not opened in read mode");
        return 0;
    }
    if (sq_file->type != SQ_CW_ZCK_COMPRESSION){
        g_set_error(err, ERR_DOMAIN, SQE_BADARG,
                    "Bad compressed file type");
        return 0;
    }
#ifdef WITH_ZCHUNK
    zckCtx *zck = (zckCtx *) sq_file->FILE;
    zckChunk *idx = zck_get_chunk(zck, zchunk_index);
    ssize_t chunk_size = zck_get_chunk_size(idx);
    if (chunk_size <= 0)
        return 0;
    *copy_buf = g_malloc(chunk_size);
    return zck_get_chunk_data(idx, *copy_buf, chunk_size);
#else
    g_set_error(err, ERR_DOMAIN, SQE_IO, "createrepo_c wasn't compiled "
                        "with zchunk support");
    return 0;
#endif // WITH_ZCHUNK
}
