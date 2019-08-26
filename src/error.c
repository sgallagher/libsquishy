/* createrepo_c - Library of routines for manipulation with repodata
 * Copyright (C) 2013      Tomas Mlcoch
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

#include "error.h"

const char *
sq_strerror(sq_Error rc)
{
    switch (rc) {
        case SQE_OK:
            return "No error";
        case SQE_ERROR:
            return "No specified error";
        case SQE_IO:
            return "Input/Output error";
        case SQE_MEMORY:
            return "Out of memory";
        case SQE_STAT:
            return "stat() system call failed";
        case SQE_DB:
            return "Database error";
        case SQE_BADARG:
            return "Bad function argument(s)";
        case SQE_NOFILE:
            return "File doesn't exist";
        case SQE_NODIR:
            return "Directory doesn't exist";
        case SQE_EXISTS:
            return "File/Directory already exists";
        case SQE_UNKNOWNCHECKSUMTYPE:
            return "Unknown/Unsupported checksum type";
        case SQE_UNKNOWNCOMPRESSION:
            return "Unknown/Usupported compression";
        case SQE_XMLPARSER:
            return "Error while parsing XML";
        case SQE_XMLDATA:
            return "Loaded XML data are bad";
        case SQE_CBINTERRUPTED:
            return "Interrupted by callback";
        case SQE_BADXMLPRIMARY:
            return "Bad primary XML";
        case SQE_BADXMLFILELISTS:
            return "Bad filelists XML";
        case SQE_BADXMLOTHER:
            return "Bad other XML";
        case SQE_MAGIC:
            return "Magic Number Recognition Library (libmagic) error";
        case SQE_GZ:
            return "Gzip library related error";
        case SQE_BZ2:
            return "Bzip2 library related error";
        case SQE_XZ:
            return "XZ (lzma) library related error";
        case SQE_OPENSSL:
            return "OpenSSL library related error";
        case SQE_CURL:
            return "Curl library related error";
        case SQE_ASSERT:
            return "Assert error";
        case SQE_BADCMDARG:
            return "Bad command line argument(s)";
        case SQE_SPAWNERRCODE:
            return "Child process exited with error code != 0";
        case SQE_SPAWNKILLED:
            return "Child process killed by signal";
        case SQE_SPAWNSTOPED:
            return "Child process stopped by signal";
        case SQE_SPAWNABNORMAL:
            return "Child process exited abnormally";
        case SQE_DELTARPM:
            return "Deltarpm error";
        default:
            return "Unknown error";
    }
}

GQuark
createrepo_c_error_quark(void)
{
    static GQuark quark = 0;
    if (!quark)
            quark = g_quark_from_static_string ("createrepo_c_error");
    return quark;
}
