/* checksum.c
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

#include <glib.h>
#include <glib/gprintf.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/evp.h>
#include "error.h"
#include "checksum.h"

#define ERR_DOMAIN              SQE_ERROR
#define MAX_CHECKSUM_NAME_LEN   7
#define BUFFER_SIZE             2048

struct _sq_ChecksumCtx {
    EVP_MD_CTX      *ctx;
    sq_ChecksumType type;
};

sq_ChecksumType
sq_checksum_type(const char *name)
{
    size_t len;
    char name_lower[MAX_CHECKSUM_NAME_LEN+1];

    if (!name)
        return SQ_CHECKSUM_UNKNOWN;

    len = strlen(name);
    if (len > MAX_CHECKSUM_NAME_LEN)
        return SQ_CHECKSUM_UNKNOWN;

    for (size_t x = 0; x <= len; x++)
        name_lower[x] = tolower(name[x]);

    if (!strncmp(name_lower, "md", 2)) {
        // MD* family
//        if (name_lower[2] == '2')
//            return SQ_CHECKSUM_MD2;
//        else if (name_lower[2] == '5')
        if (name_lower[2] == '5')
            return SQ_CHECKSUM_MD5;
    } else if (!strncmp(name_lower, "sha", 3)) {
        // SHA* family
        char *sha_type = name_lower + 3;
        if (!strcmp(sha_type, ""))
            return SQ_CHECKSUM_SHA;
        else if (!strcmp(sha_type, "1"))
            return SQ_CHECKSUM_SHA1;
        else if (!strcmp(sha_type, "224"))
            return SQ_CHECKSUM_SHA224;
        else if (!strcmp(sha_type, "256"))
            return SQ_CHECKSUM_SHA256;
        else if (!strcmp(sha_type, "384"))
            return SQ_CHECKSUM_SHA384;
        else if (!strcmp(sha_type, "512"))
            return SQ_CHECKSUM_SHA512;
    }

    return SQ_CHECKSUM_UNKNOWN;
}

const char *
sq_checksum_name_str(sq_ChecksumType type)
{
    switch (type) {
    case SQ_CHECKSUM_UNKNOWN:
        return "Unknown checksum";
//    case SQ_CHECKSUM_MD2:
//        return "md2";
    case SQ_CHECKSUM_MD5:
        return "md5";
    case SQ_CHECKSUM_SHA:
        return "sha";
    case SQ_CHECKSUM_SHA1:
        return "sha1";
    case SQ_CHECKSUM_SHA224:
        return "sha224";
    case SQ_CHECKSUM_SHA256:
        return "sha256";
    case SQ_CHECKSUM_SHA384:
        return "sha384";
    case SQ_CHECKSUM_SHA512:
        return "sha512";
    default:
        return NULL;
    }
}

char *
sq_checksum_file(const char *filename,
                 sq_ChecksumType type,
                 GError **err)
{
    FILE *f;
    int rc;
    unsigned int len;
    ssize_t readed;
    char buf[BUFFER_SIZE];
    unsigned char raw_checksum[EVP_MAX_MD_SIZE];
    char *checksum;
    EVP_MD_CTX *ctx;
    const EVP_MD *ctx_type;

    switch (type) {
        //case SQ_CHECKSUM_MD2:    ctx_type = EVP_md2();    break;
        case SQ_CHECKSUM_MD5:    ctx_type = EVP_md5();    break;
        case SQ_CHECKSUM_SHA:    ctx_type = EVP_sha1();   break;
        case SQ_CHECKSUM_SHA1:   ctx_type = EVP_sha1();   break;
        case SQ_CHECKSUM_SHA224: ctx_type = EVP_sha224(); break;
        case SQ_CHECKSUM_SHA256: ctx_type = EVP_sha256(); break;
        case SQ_CHECKSUM_SHA384: ctx_type = EVP_sha384(); break;
        case SQ_CHECKSUM_SHA512: ctx_type = EVP_sha512(); break;
        case SQ_CHECKSUM_UNKNOWN:
        default:
            g_set_error(err, ERR_DOMAIN, SQE_UNKNOWNCHECKSUMTYPE,
                        "Unknown checksum type");
            return NULL;
    }

    f = fopen(filename, "rb");
    if (!f) {
        g_set_error(err, ERR_DOMAIN, SQE_IO,
                    "Cannot open a file: %s", g_strerror(errno));
        return NULL;
    }

    ctx = EVP_MD_CTX_create();
    rc = EVP_DigestInit_ex(ctx, ctx_type, NULL);
    if (!rc) {
        g_set_error(err, ERR_DOMAIN, SQE_OPENSSL,
                    "EVP_DigestInit_ex() failed");
        EVP_MD_CTX_destroy(ctx);
        fclose(f);
        return NULL;
    }

    while ((readed = fread(buf, 1, BUFFER_SIZE, f)) == BUFFER_SIZE)
        EVP_DigestUpdate(ctx, buf, readed);

    if (feof(f)) {
        EVP_DigestUpdate(ctx, buf, readed);
    } else {
        g_set_error(err, ERR_DOMAIN, SQE_IO,
                    "Error while reading a file: %s", g_strerror(errno));
        EVP_MD_CTX_destroy(ctx);
        fclose(f);
        return NULL;
    }

    fclose(f);

    EVP_DigestFinal_ex(ctx, raw_checksum, &len);
    EVP_MD_CTX_destroy(ctx);
    checksum = g_malloc0(sizeof(char) * (len * 2 + 1));
    for (size_t x = 0; x < len; x++)
        sprintf(checksum+(x*2), "%02x", raw_checksum[x]);

    return checksum;
}

sq_ChecksumCtx *
sq_checksum_new(sq_ChecksumType type, GError **err)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *ctx_type;
    sq_ChecksumCtx *sq_ctx;

    assert(!err || *err == NULL);

    switch (type) {
        //case SQ_CHECKSUM_MD2:    ctx_type = EVP_md2();    break;
        case SQ_CHECKSUM_MD5:    ctx_type = EVP_md5();    break;
        case SQ_CHECKSUM_SHA:    ctx_type = EVP_sha1();   break;
        case SQ_CHECKSUM_SHA1:   ctx_type = EVP_sha1();   break;
        case SQ_CHECKSUM_SHA224: ctx_type = EVP_sha224(); break;
        case SQ_CHECKSUM_SHA256: ctx_type = EVP_sha256(); break;
        case SQ_CHECKSUM_SHA384: ctx_type = EVP_sha384(); break;
        case SQ_CHECKSUM_SHA512: ctx_type = EVP_sha512(); break;
        case SQ_CHECKSUM_UNKNOWN:
        default:
            g_set_error(err, ERR_DOMAIN, SQE_UNKNOWNCHECKSUMTYPE,
                        "Unknown checksum type");
            return NULL;
    }

    ctx = EVP_MD_CTX_create();
    if (!ctx) {
        g_set_error(err, ERR_DOMAIN, SQE_OPENSSL,
                    "EVP_MD_CTX_create() failed");
        return NULL;
    }

    if (!EVP_DigestInit_ex(ctx, ctx_type, NULL)) {
        g_set_error(err, ERR_DOMAIN, SQE_OPENSSL,
                    "EVP_DigestInit_ex() failed");
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

    sq_ctx = g_malloc0(sizeof(sq_ChecksumCtx));
    sq_ctx->ctx = ctx;
    sq_ctx->type = type;

    return sq_ctx;
}

int
sq_checksum_update(sq_ChecksumCtx *ctx,
                   const void *buf,
                   size_t len,
                   GError **err)
{
    assert(ctx);
    assert(!err || *err == NULL);

    if (len == 0)
        return SQE_OK;

    if (!EVP_DigestUpdate(ctx->ctx, buf, len)) {
        g_set_error(err, ERR_DOMAIN, SQE_OPENSSL,
                    "EVP_DigestUpdate() failed");
        return SQE_OPENSSL;
    }

    return SQE_OK;
}

char *
sq_checksum_final(sq_ChecksumCtx *ctx, GError **err)
{
    unsigned int len;
    unsigned char raw_checksum[EVP_MAX_MD_SIZE];
    char *checksum;

    assert(ctx);
    assert(!err || *err == NULL);

    if (!EVP_DigestFinal_ex(ctx->ctx, raw_checksum, &len)) {
        g_set_error(err, ERR_DOMAIN, SQE_OPENSSL,
                    "EVP_DigestFinal_ex() failed");
        EVP_MD_CTX_destroy(ctx->ctx);
        g_free(ctx);
        return NULL;
    }

    EVP_MD_CTX_destroy(ctx->ctx);

    checksum = g_malloc0(sizeof(char) * (len * 2 + 1));
    for (size_t x = 0; x < len; x++)
        sprintf(checksum+(x*2), "%02x", raw_checksum[x]);

    g_free(ctx);

    return checksum;
}
