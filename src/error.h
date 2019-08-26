/* createrepo_c - Library of routines for manipulation with repodata
 * Copyright (C) 2013  Tomas Mlcoch
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef __C_SQUISHY_ERROR_H__
#define __C_SQUISHY_ERROR_H__

#include <glib.h>

/* Error codes */
typedef enum {
    SQE_OK,     /*!<
        (0) No error */
    SQE_ERROR, /*!<
        (1) No specified error */
    SQE_IO,     /*!<
        (2) Input/Output error (cannot open file, etc.) */
    SQE_MEMORY, /*!<
        (3) Cannot allocate memory */
    SQE_STAT, /*!<
        (4) Stat() call failed */
    SQE_DB,     /*!<
        (5) A database error */
    SQE_BADARG, /*!<
        (6) At least one argument of function is bad or non complete */
    SQE_NOFILE, /*!<
        (7) File doesn't exist */
    SQE_NODIR, /*!<
        (8) Directory doesn't exist (not a dir or path doesn't exists) */
    SQE_EXISTS, /*!<
        (9) File/Directory already exists */
    SQE_UNKNOWNCHECKSUMTYPE, /*!<
        (10) Unknown/Unsupported checksum type */
    SQE_UNKNOWNCOMPRESSION, /*!<
        (11) Unknown/Unsupported compression type */
    SQE_XMLPARSER, /*!<
        (12) XML parser error (non valid xml, corrupted xml,  ..) */
    SQE_XMLDATA, /*!<
        (13) Loaded xml metadata are bad */
    SQE_CBINTERRUPTED, /*!<
        (14) Interrupted by callback. */
    SQE_BADXMLPRIMARY, /*!<
        (15) Bad filelists.xml file */
    SQE_BADXMLFILELISTS, /*!<
        (16) Bad filelists.xml file */
    SQE_BADXMLOTHER, /*!<
        (17) Bad filelists.xml file */
    SQE_BADXMLREPOMD, /*!<
        (18) Bad repomd.xml file */
    SQE_MAGIC, /*!<
        (19) Magic Number Recognition Library (libmagic) error */
    SQE_GZ, /*!<
        (20) Gzip library related error */
    SQE_BZ2, /*!<
        (21) Bzip2 library related error */
    SQE_XZ, /*!<
        (22) Xz (lzma) library related error */
    SQE_OPENSSL, /*!<
        (23) OpenSSL library related error */
    SQE_CURL, /*!<
        (24) Curl library related error */
    SQE_ASSERT, /*!<
        (25) Ideally this error should never happend. Nevertheless if
        it happend, probable reason is that some values of createrepo_c
        object was changed (by you - a programmer) in a bad way */
    SQE_BADCMDARG, /*!<
        (26) Bad command line argument(s) */
    SQE_SPAWNERRCODE, /*!<
        (27) Child process exited with error code != 0 */
    SQE_SPAWNKILLED, /*!<
        (28) Child process killed by signal */
    SQE_SPAWNSTOPED, /*!<
        (29) Child process stopped by signal */
    SQE_SPAWNABNORMAL, /*!<
        (30) Child process exited abnormally */
    SQE_DELTARPM, /*!<
        (31) Deltarpm related error */
    SQE_BADXMLUPDATEINFO, /*!<
        (32) Bad updateinfo.xml file */
    SQE_SIGPROCMASK, /*!<
        (33) Cannot change blocked signals */
    SQE_ZCK, /*!<
        (34) ZCK library related error */
    SQE_MODULEMD, /*!<
        (35) modulemd related error */
    SQE_SENTINEL, /*!<
        (XX) Sentinel */
} sq_Error;

/** Converts sq_Error return code to error string.
 * @param rc        sq_Error return code
 * @return          Error string
 */
const char *sq_strerror(sq_Error rc);

/* Error domains */
#define CREATEREPO_C_ERROR              createrepo_c_error_quark()

GQuark createrepo_c_error_quark(void);

#endif
