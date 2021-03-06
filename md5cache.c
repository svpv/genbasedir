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

#include <stdbool.h>
#include <string.h>
#include <assert.h>

// Compare a string to a string literal.
#define strLen(s) (sizeof("" s) - 1)
#define startsWith(s, len, ss) \
    memcmp(s, ss, strLen(ss)) == 0
#define endsWith(s, len, ss) \
    memcmp(s + len - strLen(ss), ss, strLen(ss)) == 0

// Somewhat sloppy comparison is justified by the following property.
#define minRpmLen strLen("a-1-1.src.rpm")
#define longestSuffix strLen(".noarch.rpm")
static_assert(minRpmLen >= longestSuffix, "string literals compared safely");

// Additionally a key (typically "N-V-R") should be at least this long.
#define minKeyLen strLen("a-1-1")

#ifdef MD5CACHE_SRC
// Source rpms undergo a much simpler .src.rpm suffix removal.
#else
// Split rpm basename, already without .rpm suffix, into even shorter key
// (without .arch suffix, ending with "-V-R") and arch.
static bool split_ka(char *rpm, size_t len, char **k, size_t *klen, const char **a)
{
    if (endsWith(rpm, len, ".noarch")) {
	*k = rpm, *a = "noarch";
	rpm[len-strLen(".noarch")] = '\0';
	*klen = len - strLen(".noarch");
	return true;
    }
    if (startsWith(rpm, len, "i586-") && endsWith(rpm, len, ".i586")) {
	*k = rpm + strLen("i586-"), *a = "i586-arepo";
	rpm[len-strLen(".i586")] = '\0';
	*klen = len - strLen(".i586") - strLen("i586-");
	return true;
    }
    // Parse N[-debuginfo]-V-R.A.rpm.
    char *endA = rpm + len;
#define falseIfNull(x) if (__builtin_expect(x == NULL, 0)) return false
    char *dotA = strrchr(rpm, '.'); falseIfNull(dotA); *dotA = '\0';
    char *dashR = strrchr(rpm, '-'); falseIfNull(dashR); *dashR = '\0';
    char *dashV = strrchr(rpm, '-'); falseIfNull(dashV); *dashV = '\0';
    char *dashD = strrchr(rpm, '-'); *dashV = *dashR = '-';
#define DSTR "-debuginfo"
#define DLEN strLen(DSTR)
    if (dashD == NULL || dashV - dashD != DLEN || memcmp(dashD, DSTR, DLEN)) {
	*k = rpm, *a = dotA + 1;
	*klen = dotA - rpm;
	return true;
    }
    // Transform N-D V-R A => N-V-R A-D, e.g.
    // foo-debuginfo-1.0-alt1.i586 => foo-1.0-alt1 i586-debuginfo
    memmove(dashD, dashV, dotA - dashV + 1);
    char *A = dashD + (dotA - dashV + 1);
    memmove(A, dotA + 1, endA - dotA - 1);
    memcpy(A + (endA - dotA - 1), DSTR, DLEN + 1);
    *k = rpm, *a = A;
    *klen = A - rpm - 1;
    return true;
}
#endif

// The cache database is a stream of cache entries; the stream is further
// compressed with Zstd, to whom I entrust basic integrity checking such as
// file magic and checksumming (which is no small matter if you think what
// happens after we discharge bad md5).
//
// Each entry is:
// keylen: 1 byte, key: not null-terminated,
// file size+mtime: packed into 6 bytes,
// cache entry atime: 2 bytes (unix time >> 16),
// md5: 16 bytes, sha256: 32 bytes.

// The "entry value", i.e. the entry save the key.
struct entv {
    unsigned short sm[3];
    unsigned short atime;
    unsigned char md5[16];
    unsigned char sha256[32];
};

unsigned short now;

#ifdef MD5CACHE_SRC
// Assume no more than 256K srpms will ever be processed at once.
#define NENT (2<<17)
#else
// Binary repos enjoy moderately larger counts (due to subpackages).
#define NENT (3<<17)
// There can also be special binary repos, such as distro's RPMS.main,
// which are combined of a few repo components (e.g. x86_64, noarch,
// and i586-arepo).  In other words, we may need to open a few per-arch
// sub-databases within a single run.
#define MAXSUBDB 4
#endif

// The average length of srpm keys is 29, the average length of x86_64 keys
// is about 30, while the average length of noarch keys is 35, but the latter
// are fewer in number.
static char strtab[32*NENT];
// This strtab is peculiar in that it stores only short strings (this follows
// from the fact than keys cannot be longer than NAME_MAX, which is 255).
// This makes it possible for the preceding byte to store the string's length,
// saving many a strlen call.  The strings are null-terminated nonetheless.
static unsigned strtabPos = 1;

static inline unsigned addStr(const char *str, size_t len)
{
    assert(len <= 255);
    if (strtabPos + len >= sizeof strtab)
	return -1;
    *(unsigned char *) (strtab + strtabPos - 1) = len;
    memcpy(strtab + strtabPos, str, len);
    unsigned pos = strtabPos;
    strtabPos += len + 2;
    return pos;
}

struct md5db {
    size_t lend; // loaded from disk
    size_t aend; // added during runtime
    unsigned kk[NENT]; // key indexes into strtab
    struct entv ee[NENT];
};

#include "reada.h"
#include "zstdreader.h"
#if NREADA != 4096
#warning "suboptimal NREADA"
#endif

#define ERRSTR(str) err[0] = __func__, err[1] = str

static bool md5db_readloop(struct md5db *db, struct zstdreader *z, const char *err[2])
{
    // Read the first byte, which is the length of a key.
    unsigned char klen;
    ssize_t zret = zstdreader_read(z, &klen, 1, err);
    if (zret <= 0) // Caveat emptor - let the caller beware if it's EOF.
	return zret == 0;
    // The length is known, read the record.
    char buf[256+64];
    while (1) {
	if (klen < minKeyLen)
	    return ERRSTR("bad keylen"), false;
	// Read the rest of the record + 1 more byte.
	size_t nread = klen + sizeof(struct entv) + 1;
	zret = zstdreader_read(z, buf, nread, err);
	if (zret < 0)
	    return false;
	if (zret < nread - 1)
	    return ERRSTR("unexpected EOF"), false;
	if (db->lend == NENT)
	    return ERRSTR("too many entries"), false;
	unsigned six = addStr(buf, klen);
	if (six == -1)
	    return ERRSTR("too many keys"), false;
	db->kk[db->lend] = six;
	memcpy(db->ee + db->lend, buf + klen, sizeof(struct entv));
	db->lend++;
	// EOF?
	if (zret == nread - 1)
	    return true;
	// Next klen.
	klen = *(unsigned char *) &buf[nread-1];
    }
}

static bool md5db_readall(struct md5db *db, int fd, const char *err[2])
{
    char fdabuf[NREADA];
    struct fda fda = { fd, fdabuf };
    struct zstdreader *z;
    int rc = zstdreader_open(&z, &fda, err);
    if (rc <= 0)
	return rc == 0;
    bool ok = md5db_readloop(db, z, err);
    if (ok) {
	// Sloppy test for EOF, saves a system call.
	ok = fda.cur == fda.end;
	if (!ok)
	    ERRSTR("trailing garbage");
    }
    zstdreader_free(z);
    db->aend = db->lend;
    return ok;
}

static struct entv *md5db_find(struct md5db *db, const char *key)
{
    size_t l = 0, u = db->lend;
    unsigned *kk = db->kk;
    while (l < u) {
	size_t i = (l + u) / 2;
	int cmp = strcmp(strtab + kk[i], key);
	if (cmp < 0)
	    l = i + 1;
	else if (cmp > 0)
	    u = i;
	else
	    return &db->ee[i];
    }
    return NULL;
}

#include "qsort.h"

// Sort added entries.
static void md5db_asort(struct md5db *db)
{
    unsigned *kk = db->kk + db->lend;
    struct entv *ee = db->ee + db->lend;
#define LESS(i, j) strcmp(strtab + kk[i], strtab + kk[j]) < 0
    unsigned k; struct entv e;
#define SWAP(i, j) k = kk[i], kk[i] = kk[j], kk[j] = k, \
		   e = ee[i], ee[i] = ee[j], ee[j] = e
    size_t n = db->aend - db->lend;
    QSORT(n, LESS, SWAP);
}

#include "zstdwriter.h"

// Entries older than about 15 days are purged automatically.
#define OLD(atime) (atime + 20 < now)

// Process a single key, write a record from the table, unless it's too old.
// Further merge with the other state, if there is one.  Unless the record
// is fresh (or has been refreshed via cache hit), prefer to pass through
// the record from the other state (in case it was refreshed there).
static inline bool md5db_write1(struct md5db *db, struct zstdwriter *z,
				struct zstdreader *z0, struct state0 *st0,
				const char *k, struct entv *e, const char *err[2])
{
    bool fresh = e->atime == now + 1;
    if (z0) {
	int rc = md5db_catchup(z, z0, st0, k, fresh, err);
	if (rc) // Either error or wrote k.
	    return rc > 0;
    }
    if (fresh)
	e->atime = now;
    else if (OLD(e->atime))
	return true;
    unsigned char klen = *(unsigned char *) &k[-1];
    if (!zstdwriter_write(z, k - 1, klen + 1, err))
	return false;
    if (!zstdwriter_write(z, e, sizeof *e, err))
	return false;
    return true;
}

// Generic 3-way merge, loaded + added + z0 changed in the meantime.
static bool md5db_writeloop(struct md5db *db, struct zstdreader *z0,
			    struct zstdwriter *z, const char *err[2])
{
    struct state0 st0 = {};
    size_t i = 0, j = db->lend;
    unsigned *kk = db->kk;
    // Merge loaded + added entries.
    while (i < db->lend && j < db->aend) {
	const char *k; struct entv *e;
	int cmp = strcmp(strtab + kk[i], strtab + kk[j]);
	if (cmp < 0)
	    k = strtab + kk[i], e = &db->ee[i], i++;
	else
	    k = strtab + kk[j], e = &db->ee[j], j++;
	if (!md5db_write1(db, z, z0, &st0, k, e, err))
	    return false;
    }
    // Append what's left.
    for (; i < db->lend; i++)
	if (!md5db_write1(db, z, z0, &st0, strtab + kk[i], &db->ee[i], err))
	    return false;
    for (; j < db->aend; j++)
	if (!md5db_write1(db, z, z0, &st0, strtab + kk[j], &db->ee[j], err))
	    return false;
    // TODO: append the rest of z0.
    return true;
}

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
    assert(hlen + strLen(SUBDIR) + strLen(ENV) < PATH_MAX);
    char path[hlen + strLen(SUBDIR) + strLen(ENV) + 1];
    memcpy(path, home, hlen);
    memcpy(path + hlen, SUBDIR, strLen(SUBDIR));
    memcpy(path + hlen + strLen(SUBDIR), ENV, strLen(ENV) + 1);
    // mkdir -p ~/.cache/genbasedir
    char *slash1 = path + hlen + strLen(SUBDIR) - 1;
    assert(*slash1 == '/'), *slash1 = '\0';
    if (mkdir(path, 0777) < 0 && errno != EEXIST) {
	char *slash2 = path + hlen + strLen("/.cache/") - 1;
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
    // Going to prepare the key without the .xxx.rpm suffix.
    size_t len = strlen(rpm);
    if (len < minRpmLen)
	die("%s: bad rpm name", rpm);
#ifdef MD5CACHE_SRC
    // Assume it ends with .src.rpm, that's what readdir should check.
    len -= 8;
#else
    // Assume it ends with .rpm but not with .src.rpm.
    len -= 4;
#endif
    char copy[len+1];
    memcpy(copy, rpm, len);
    copy[len] = '\0';
#ifdef MD5CACHE_SRC
    MDBX_val k = { copy, len };
#else
    // Deduce the arch and use it as the database name.
    char *kk; size_t klen; const char *arch;
    if (!split_ka(copy, len, &kk, &klen, &arch) || klen < minKeyLen)
	die("%s: bad rpm name", rpm);
    MDBX_val k = { kk, klen };
#endif
    // Initialize or renew the read transaction.
    int rc;
    if (!env)
	md5cache_init(), assert(env);
    else
	rc = mdbx_txn_renew(rtxn), assert(rc == 0);
#ifdef MD5CACHE_SRC
    MDBX_dbi dbi = src_dbi;
#else
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
