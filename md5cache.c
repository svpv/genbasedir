// Copyright (c) 2018 Alexey Tourbin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <mdbx.h>
#include "errexit.h"

// Separate environments for gensrclist and genpkglist.
#ifdef MD5CACHE_SRC
#define ENV "md5-src"
#else
#define ENV "md5-pkg"
#endif
static MDBX_env *env;
// The read-only transaction for fast retrieval.
static MDBX_txn *rtxn;
#ifdef MD5CACHE_SRC
// The unnamed database for gensrclist.
static MDBX_dbi src_dbi;
#endif

// Prepare a NOSUBDIR environment under ~/.cache/genbasedir/.
static void md5cache_init(void)
{
    const char *home = getenv("HOME");
    assert(home && *home == '/');
    size_t hlen = strlen(home);
#define SUBDIR "/.cache/genbasedir/"
#define STRLEN(s) (sizeof("" s) - 1)
    assert(hlen + STRLEN(SUBDIR) + STRLEN(ENV) < PATH_MAX);
    char path[hlen + STRLEN(SUBDIR) + STRLEN(ENV) + 1];
    memcpy(path, home, hlen);
    memcpy(path + hlen, SUBDIR, STRLEN(SUBDIR));
    memcpy(path + hlen + STRLEN(SUBDIR), ENV, STRLEN(ENV) + 1);
    // mkdir -p ~/.cache/genbasedir
    char *slash1 = path + hlen + STRLEN(SUBDIR) - 1;
    assert(*slash1 == '/'), *slash1 = '\0';
    if (mkdir(path, 0777) < 0 && errno != EEXIST) {
	char *slash2 = path + hlen + STRLEN("/.cache/") - 1;
	assert(*slash2 == '/'), *slash2 = '\0';
	if (mkdir(path, 0777) < 0 && errno != EEXIST)
	    die("%s: %m", path);
	*slash2 = '/';
	if (mkdir(path, 0777) < 0 && errno != EEXIST)
	    die("%s: %m", path);
    }
    *slash1 = '/';
    // Create the environment.
    int rc = mdbx_env_create(&env);
    assert(rc == 0);
#ifndef MD5CACHE_SRC
    // Unlike srpms, which use a single unnamed db, binary rpms use a separate
    // database per arch.  Thus there is no need to store either .src.rpm or
    // .$arch.rpm suffixes as part of rpm filenames.
    rc = mdbx_env_set_maxdbs(env, 8), assert(rc == 0);
#endif
    rc = mdbx_env_open(env, path, MDBX_NOSUBDIR, 0666);
    if (rc)
	die("%s: %s", path, mdbx_strerror(rc));
    // Create the read transaction.
    rc = mdbx_txn_begin(env, NULL, MDBX_RDONLY, &rtxn), assert(rc == 0);
#ifdef MD5CACHE_SRC
    // Open the unnamed db for srpms.
    rc = mdbx_dbi_open(rtxn, NULL, 0, &src_dbi), assert(rc == 0);
#endif
}

static inline void md5hex(unsigned char bin[16], char str[33])
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++)
	*str++ = hex[*bin >> 4],
	*str++ = hex[*bin++ & 0xf];
    *str = '\0';
}

#include <unistd.h>
#include <openssl/md5.h>

static inline void md5fd(const char *rpm, int fd, unsigned char bin[16])
{
    MD5_CTX c;
    MD5_Init(&c);
    if (lseek(fd, 0, 0) < 0)
	die("%s: %m", "lseek");
    while (1) {
	char buf[BUFSIZ];
	ssize_t ret = read(fd, buf, sizeof buf);
	if (ret < 0) {
	    if (errno == EINTR)
		continue;
	    die("%s: %m", rpm);
	}
	if (ret == 0)
	    break;
	MD5_Update(&c, buf, ret);
    }
    MD5_Final(bin, &c);
}

#include <endian.h>
#include "md5cache.h"

void md5cache(const char *rpm, struct stat *st, int fd, char md5[33])
{
    // Prepare the key without the .xxx.rpm suffix.
    size_t len = strlen(rpm);
    assert(len > 8);
    assert(memcmp(rpm + len - 4, ".rpm", 4) == 0);
    assert(len <= NAME_MAX);
    char key[len+1];
    memcpy(key, rpm, len + 1);
    // Initialize or renew the read transaction.
    int rc;
    if (!env)
	md5cache_init(), assert(env);
    else
	rc = mdbx_txn_renew(rtxn), assert(rc == 0);
#ifdef MD5CACHE_SRC
    assert(memcmp(rpm + len - 8, ".src.rpm", 8) == 0);
    key[len-8] = '\0';
    MDBX_dbi dbi = src_dbi;
    MDBX_val k = { key, len - 8 };
#else
    // Deduce the arch and use it as the database name.
    assert(memcmp(rpm + len - 8, ".src.rpm", 8) != 0);
    key[len-4] = '\0';
    char *arch = strrchr(key, '.');
    assert(arch);
    MDBX_val k = { key, arch - key };
    *arch++ = '\0', assert(*arch);
    MDBX_dbi dbi;
    rc = mdbx_dbi_open(rtxn, arch, 0, &dbi), assert(rc == 0);
#endif
    // Ready to get.
    MDBX_val v;
    rc = mdbx_get(rtxn, dbi, &k, &v);
    // Retire the read transaction asap.
    mdbx_txn_reset(rtxn);
    // Check that the file size and mtime are the same.
    // Otherwise, the record will be replaced.
    unsigned sm[2] = { htole32(st->st_size), htole32(st->st_mtime) };
    if (rc == 0) {
	// Had better get size+mtime and md5.
	assert(v.iov_len == sizeof sm + 16);
	// Verify size+mtime.
	if (memcmp(sm, v.iov_base, sizeof sm) == 0) {
	    md5hex((unsigned char *) v.iov_base + sizeof sm, md5);
	    return;
	}
    }
    else if (rc != MDBX_NOTFOUND)
	die("%s: %s", "mdbx_get", mdbx_strerror(rc));
    // Combine the "v" record.
    struct { unsigned sm[2]; unsigned char bin[16]; } smb;
    memcpy(smb.sm, sm, sizeof sm);
    // Calculate md5 the hard way.
    md5fd(rpm, fd, smb.bin);
    v.iov_base = &smb, v.iov_len = sizeof smb;
    // Need to run the write transaction.  It is not entirely clear
    // whether dbi can be reused this way, but it seems to work.
    MDBX_txn *wtxn;
    rc = mdbx_txn_begin(env, NULL, 0, &wtxn), assert(rc == 0);
    rc = mdbx_put(wtxn, dbi, &k, &v, 0), assert(rc == 0);
    rc = mdbx_txn_commit(wtxn), assert(rc == 0);
    md5hex(smb.bin, md5);
}

void md5nocache(const char *rpm, int fd, char md5[33])
{
    unsigned char bin[16];
    md5fd(rpm, fd, bin);
    md5hex(bin, md5);
}

// ex:set ts=8 sts=4 sw=4 noet:
