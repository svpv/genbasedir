// Copyright (c) 2017 Alexey Tourbin
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

// Check if a directory from %{DIRNAMES} (i.e. with a trailing slash)
// is a PATH directory.  Files under such a directory will not be
// stripped from the header file list.  The function works even when
// d is not null-terminated and/or when dlen == 0.
static bool bindir(const char *d, size_t dlen)
{
    // Compare a string to a string literal.
#define strLen(ss) (sizeof(ss "") - 1)
#define memEq(s, ss) (memcmp(s, ss, strLen(ss)) == 0)
#define strEq(s, ss) (s##len == strLen(ss) && memEq(s, ss))
#define startsWith(s, ss) (s##len >= strLen(ss) && memEq(s, ss))
#define endsWith(s, ss) (s##len >= strLen(ss) && memEq(s + s##len - strLen(ss), ss))

    switch (dlen) {
#define caseStr(ss) case strLen(ss): return memEq(d, ss)
    caseStr("/bin/");
    caseStr("/sbin/");
    caseStr("/usr/bin/");
    caseStr("/usr/sbin/");
    caseStr("/usr/games/");
    case strLen("/usr/lib/kf5/bin/"):
	return memEq(d, "/usr/lib/kf5/bin/") ||
	       memEq(d, "/usr/lib/kf6/bin/");
    case strLen("/usr/lib/kde4/bin/"):
	return memEq(d, "/usr/lib/kde4/bin/") ||
	       memEq(d, "/usr/lib/kde3/bin/");
    }
    return false;
}

#include <assert.h>
#include <rpm/rpmlib.h>
#include "fpset.h"
#include "t1ha.h"

// The hash function which is used for fingerprinting.
// I wasn't able to compile the ifunc variant with AES-NI just yet.
static uint64_t hash64(const void *data, size_t size, uint64_t seed)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return t1ha1_be(data, size, seed);
#else
    return t1ha1_le(data, size, seed);
#endif
}

// The set of 64-bit fingerprints of filename dependencies.  Works as
// a probabilistic data structure for approximate membership queries.
// In the worst case (which in a typical setting is highly unlikely)
// an unrelated filename can be preserved in the output on behalf of
// filename dependencies.
static struct fpset *depFiles;

// Add a filename dependency (which must start with a slash) to depFiles.
// When the dependency comes from a header, its length is unknown; otherwise,
// when it's been read from --useful-files=FILE, the length must be known.
// Hence the routine should be instantiated with constant hasLen arg.
static inline void addDepFile(const char *dep, size_t len, bool hasLen)
{
    // Skip if it's under bindir; later the check for bindir will
    // pick it up anyway.  This fpset data structure works best when
    // it has the fewest elements.
    const char *rslash = strrchr(dep, '/');
    size_t dlen = rslash + 1 - dep; // including the slash
    if (bindir(dep, dlen))
	return;
    // Further check if it ends with a close paren.  Dependencies like
    // "/etc/rc.d/init.d(status)" or "/usr/lib64/firefox/libxul.so()(64bit)"
    // are not filenames.  Even though such filenames may well exist,
    // dependencies on them are only permitted in between subpackages
    // of the same source package (in which case the dependency gets
    // optimized out by rpmbuild, so we'll never see it).
    if (!hasLen)
	len = dlen + strlen(rslash + 1);
    if (dep[len-1] == ')')
	return;
    // Add the fingerprint for the dir.  Later we check if the dir was added
    // and otherwise skip all the files under the dir.
    uint64_t fp = hash64(dep, dlen, 0);
    int rc = fpset_add(depFiles, fp);
    assert(rc >= 0);
    // Add the fingerprint for the dir+name.  Only the filename is actually
    // hashed, while the dir hash is used as the seed.  Note that, with this
    // hashing scheme, dir and dir+name hashes fall under kind of two different
    // domains.  We might as well use two separate fpsets, which seems redunant
    // given that we have (at the time of writing) 2070 depfiles under 429 dirs.
    fp = hash64(dep + dlen, len - dlen, fp);
    rc = fpset_add(depFiles, fp);
    assert(rc >= 0);
}

// Process filename dependencies from a specific tag.
static bool findDepFilesH1(Header h, int tag)
{
    struct rpmtd_s td;
    int rc = headerGet(h, tag, &td, HEADERGET_MINMEM);
    if (rc != 1)
	return false;
    assert(td.type == RPM_STRING_ARRAY_TYPE);
    // Look for filename dependencies.
    const char **deps = td.data;
    for (unsigned i = 0; i < td.count; i++)
	if (*deps[i] == '/')
	    addDepFile(deps[i], 0, false);
    rpmtdFreeData(&td);
    return true;
}

#include <arpa/inet.h>

// Raw header entry, network byte order.
struct ent { int tag, type, off, cnt; };

// A counterpart to findDepFilesH1 that can process raw blob entries,
// without loading the header with headerImport().
static void findDepFilesB1(struct ent *e, char *data, unsigned dl)
{
    // Note that htonl(const) won't require actual runtime conversion.
    // This is one reason why specialized parsing outperforms general
    // header loading with regionSwab() etc.
    assert(e->type == htonl(RPM_STRING_ARRAY_TYPE));
    // Determine argz, the start of the string array.
    unsigned off = ntohl(e->off);
    assert(off < dl);
    const char *argz = data + off;
    // Use the next entry to find out the end of the string array.
    unsigned off1 = ntohl(e[1].off);
    assert(off1 < dl);
    assert(off1 > off);
    char *end = data + off1;
    assert(end[-1] == '\0');
    // Install the sentinel for rawmemchr.
    char save = *end;
    *end = '/';
    // Instead of iterating each name, the loop tries to iterate only the names
    // that start with a slash.  This is another reason why specialized parsing
    // is much more efficient.
    do {
	// Iterations start at the beginning of a name.
	if (*argz == '/') {
	    size_t len = 1 + strlen(argz + 1);
	    addDepFile(argz, len, true);
	    argz += len + 1;
	}
	else {
	    // The name doesn't start with a slash, so try to jump to a goddamn
	    // slash.  Only about 13% of Requires+Provides names have a slash.
	    // So this should effectively skip a few names at a time, on average.
	    argz = rawmemchr(argz + 1, '/');
	    if (argz == end)
		break;
	    size_t len = 1 + strlen(argz + 1);
	    // Check if the slash is at the beginning of a name.
	    if (argz[-1] == '\0')
		addDepFile(argz, len, true);
	    argz += len + 1;
	    // When the length isn't needed for addDepFile, it might be
	    // tempting to try and jump right to the next slash.  However,
	    // in the presence of dependencies like "perl(Net/DNS/RR/A.pm)",
	    // it's not a clear win.
	}
    } while (argz < end);
    // Restore the byte clobbered by the sentinel.
    *end = save;
}

// So far we have implemented some helpers to collect filename-like
// dependencies.  We now shift gears to tackle the next stage - sifting
// the full list of filenames through the bindir and depFiles filter.
// We want to take advantage of the fact that filenames come in
// (Basenames,Dirnames,Dirindexes) triples, where Dirnames are unique.
// Each dirname has a few files under it (10 on average, with SD > 100).
// Therefore, as the very first step, we classify the directories:
// D_SKIP means that there are no useful files under the directory;
// D_BIN indicates a PATH-like directory, hence all filenames under
// the dir should be preserved unconditionally; D_CHECK means that files
// under the dir are eligible for inclusion, subject to per-file check.
enum dirNeed { D_SKIP, D_BIN, D_CHECK };

// Single dir info from a header.
struct dirInfoH {
    // Whether the dir is needed.
    enum dirNeed need;
    // The info is loaded for each dirname[i].  If the dir makes it to
    // the output triple, its index in the output is dj (otherwise -1).
    unsigned dj;
    // Dirname hash, for D_CHECK.
    uint64_t fp;
};

// Single dir info, header blob version.
struct dirInfoB {
    // Exactly the same as dirInfoH.
    enum dirNeed need;
    unsigned dj;
    uint64_t fp;
    // Additionally stores name offset and length.
    unsigned off, len;
};

// Load single dir info, header version.  Returns true if the dir is useful.
static bool makeDirInfoH1(struct dirInfoH *d, const char *dn, size_t dlen)
{
    d->dj = (unsigned) -1;
    if (bindir(dn, dlen))
	return d->need = D_BIN, true;
    // Note that depFiles is checked here, so there's no need to check
    // depFiles later when iterating filenames.
    if (depFiles) {
	uint64_t fp = hash64(dn, dlen, 0);
	if (fpset_has(depFiles, fp))
	    return d->fp = fp, d->need = D_CHECK, true;
    }
    return d->need = D_SKIP, false;
}

// Load single dir info, header blob version.
static bool makeDirInfoB1(struct dirInfoB *d, const char *dn, size_t dlen)
{
    // Sort of a polymorphic call.
    return makeDirInfoH1((struct dirInfoH *) d, dn, dlen);
}

#include "errexit.h" // xmalloc

// Most packages have only a few dirnames.
// Preallocate a small dirInfo array, to cut down on malloc calls.
static union { struct dirInfoH H[24]; struct dirInfoB B[16]; } dirInfoBuf;
// Should waste no memory in either case.
static_assert(sizeof dirInfoBuf.H == sizeof dirInfoBuf.B, "dirInfoBuf size");

// Load dir info given dn[n] from a header.
static struct dirInfoH *makeDirInfoH(const char **dn, size_t n)
{
    struct dirInfoH *dinfo = dirInfoBuf.H;
    if (n > sizeof dirInfoBuf.H / sizeof *dirInfoBuf.H)
	dinfo = xmalloc(n * sizeof *dinfo);
    bool need = false;
    for (size_t i = 0; i < n; i++)
	need |= makeDirInfoH1(&dinfo[i], dn[i], strlen(dn[i]));
    // Returns NULL if there are no useful dirs.
    if (!need) {
	if (dinfo != dirInfoBuf.H)
	    free(dinfo);
	return NULL;
    }
    return dinfo;
}

// Load dir info given a raw header blob entry.
static struct dirInfoB *makeDirInfoB(struct ent *e, size_t n, char *data, unsigned dl)
{
    struct dirInfoB *dinfo = dirInfoBuf.B;
    if (n > sizeof dirInfoBuf.B / sizeof *dirInfoBuf.B)
	dinfo = xmalloc(n * sizeof *dinfo);
    // Determine argz, the start of the string array.
    unsigned off = ntohl(e->off);
    assert(off < dl);
    const char *argz = data + off;
    // Use the next entry to find out the end of the string array.
    unsigned off1 = ntohl(e[1].off);
    assert(off1 < dl);
    assert(off1 > off);
    char *end = data + off1;
    assert(end[-1] == '\0');
    // Similar to makeDirInfoH.
    bool need = false;
    for (size_t i = 0; i < n; i++) {
	assert(argz < end);
	struct dirInfoB *d = &dinfo[i];
	size_t len = strlen(argz);
	need |= makeDirInfoB1(d, argz, len);
	d->off = argz - data, d->len = len;
	argz += len + 1;
    }
    if (!need) {
	if (dinfo != dirInfoBuf.B)
	    free(dinfo);
	return NULL;
    }
    return dinfo;
}

// Check if a file from %{FILENAMES} is in the set of depFiles.
// Assumes that the dir is D_CHECK and its hash is dirfp.
static bool depFile(uint64_t dirfp, const char *b)
{
    uint64_t fp = hash64(b, strlen(b), dirfp);
    return fpset_has(depFiles, fp);
}

// Called by the routines that add depFiles.
static void initDepFiles(void)
{
    if (!depFiles) {
	depFiles = fpset_new(10);
	assert(depFiles);
    }
}

// Called upon exit.
static __attribute__((destructor)) void freeDepFiles(void)
{
    fpset_free(depFiles);
}

// The API starts here.
#include "depfiles.h"

// Retrieve filename dependencies from tags like %{REQUIRENAME} and store them
// in depFiles.  Later in the second pass, each filename from %{FILENAMES} will
// be tested against the set of depFiles and possibly preserved in the output.
void findDepFilesH(Header h)
{
    initDepFiles();
    // Empty Requires are not permitted - someplace, they check
    // for the "rpmlib(PayloadIsLzma)" dependency as mandatory.
    bool hasReq = findDepFilesH1(h, RPMTAG_REQUIRENAME);
    assert(hasReq);
    // If some package Provides a file, but perhaps no package Requires
    // the file yet, we still want to keep the name in all other packages,
    // so that APT can understand that there are different candidates.
    // Also, if a package Provides a file, it is important to know if
    // the file is actually packaged in this package (the Provide is
    // mostly redundant in this case).  Otherwise, the Provide will be
    // considered an alternative-like virtual path and handled differently
    // by some rpmbuild dependency generators.
    // Provides are mandatory too, due to "Provides: %name = %EVR".
    bool hasProv = findDepFilesH1(h, RPMTAG_PROVIDENAME);
    assert(hasProv);
    // Conflicts are optional.
    findDepFilesH1(h, RPMTAG_CONFLICTNAME);
    // Obsoletes should not be processed - they only work against
    // package names.  They should have no effect on filenames.
}

// A findDepFilesH counterpart which can process raw header blobs.
void findDepFilesB(const void *blob, size_t blobSize)
{
    initDepFiles();
    unsigned il = ntohl(*((unsigned *) blob + 0));
    unsigned dl = ntohl(*((unsigned *) blob + 1));
    assert(8 + 16 * il + dl == blobSize);
    // The blob starts with these "index entries", followed by data.
    struct ent *ee = (void *) ((char *) blob + 8);
    void *data = ee + il;
    // Below we probe ee[19], for which B1 will probe [20].
    assert(il > 20);
    // ProvideName is normally at [13] or at [14], due to Epoch.
    struct ent *e = &ee[13];
    if (e->tag != htonl(RPMTAG_PROVIDENAME)) {
	e++;
	assert(e->tag == htonl(RPMTAG_PROVIDENAME));
    }
    findDepFilesB1(e, data, dl);
    // RequireName follows ProvideName and RequireFlags.
    e += 2;
    assert(e->tag == htonl(RPMTAG_REQUIRENAME));
    findDepFilesB1(e, data, dl);
    // ConflictName follows RequireName, RequireVersion, and ConflictFlags.
    // Conflicts are optional, though.
    e += 3;
    if (e->tag != htonl(RPMTAG_CONFLICTNAME))
	assert(ntohl(e->tag) > RPMTAG_CONFLICTNAME);
    else
	findDepFilesB1(e, data, dl);
}

// Copy useful files from h1 to h2.
void copyStrippedFileList(Header h1, Header h2)
{
    // Load Dirnames first.
    struct rpmtd_s td_dn;
    int rc = headerGet(h1, RPMTAG_DIRNAMES, &td_dn, HEADERGET_MINMEM);
    if (rc != 1)
	return;
    assert(td_dn.type == RPM_STRING_ARRAY_TYPE);
    assert(td_dn.count > 0);
    // Load dirInfo and see if there are useful dirs.
    struct dirInfoH *dinfo = makeDirInfoH(td_dn.data, td_dn.count);
    if (!dinfo) {
	rpmtdFreeData(&td_dn);
	return;
    }
    // Load Basenames and Dirindexes.
    struct rpmtd_s td_bn, td_di;
    rc = headerGet(h1, RPMTAG_BASENAMES, &td_bn, HEADERGET_MINMEM);
    assert(rc == 1);
    assert(td_bn.type == RPM_STRING_ARRAY_TYPE);
    assert(td_bn.count > 0);
    assert(td_bn.count >= td_dn.count);
    rc = headerGet(h1, RPMTAG_DIRINDEXES, &td_di, HEADERGET_MINMEM);
    assert(rc == 1);
    assert(td_di.type == RPM_INT32_TYPE);
    assert(td_di.count == td_bn.count);
    // Initialize (from -> to) arrays.
    const char **bn1 = td_bn.data, **bn2 = NULL;
    const char **dn1 = td_dn.data, **dn2 = NULL;
    unsigned *di1 = td_di.data, *di2 = NULL;
    size_t bnc1 = td_bn.count, bnc2 = 0;
    size_t dnc1 = td_di.count, dnc2 = 0;
    // Run the copy loop.
    for (size_t i = 0; i < bnc1; i++) {
	// Check the dir and the basename.
	size_t di = di1[i];
	assert(di < dnc1);
	struct dirInfoH *d = &dinfo[di];
	switch (d->need) {
	case D_CHECK:
	    if (depFile(d->fp, bn1[i]))
		break;
	case D_SKIP:
	    continue;
	default:
	    assert(d->need == D_BIN);
	}
	// Allocate arrays for h2.
	if (!bn2) {
	    // Will need at most that many basenames and dirindexes.
	    // There is no reduced estimate for dirnames, though.
	    size_t n = bnc1 - i;
	    // Allocate in a single chunk.
	    bn2 = xmalloc(n * (sizeof(*bn2) + sizeof(*di2)) + dnc1 * sizeof(*dn2));
	    // Place dirnames right after basenames, to keep the pointers aligned.
	    dn2 = bn2 + n;
	    // Dirindexes are 32-bit integers, need less alignment than dirnames.
	    di2 = (unsigned *) (dn2 + dnc1);
	}
	// Put basename; bnc2 gets increased when dirindex is added.
	bn2[bnc2] = bn1[i];
	// See if the directory was already added.
	if (d->dj != (unsigned) -1)
	    di2[bnc2++] = d->dj;
	else {
	    dn2[dnc2] = dn1[di];
	    di2[bnc2++] = d->dj = dnc2++;
	}
    }
    // Put to h2.
    if (bn2) {
	headerPutStringArray(h2, RPMTAG_BASENAMES, bn2, bnc2);
	headerPutStringArray(h2, RPMTAG_DIRNAMES, dn2, dnc2);
	headerPutUint32(h2, RPMTAG_DIRINDEXES, di2, bnc2);
	// Arrays were allocated in a single chunk.
	free(bn2);
    }
    // See if dinfo was malloc'd.
    if (dinfo != dirInfoBuf.H)
	free(dinfo);
    // Dispose of h1 data.
    rpmtdFreeData(&td_bn);
    rpmtdFreeData(&td_dn);
    rpmtdFreeData(&td_di);
}

#include <stdio.h>
#include <errno.h>

// Read filenames from --useful-files=FILE.
void readDepFiles(const char *fname, unsigned char delim)
{
    initDepFiles();
    FILE *fp = fopen(fname, "r");
    if (!fp)
	die("%s: %m", fname);
    char *line = NULL;
    size_t alloc_size = 0;
    while (1) {
	errno = 0;
	ssize_t len = getdelim(&line, &alloc_size, delim, fp);
	if (len < 0)
	    break;
	if (len > 0 && (unsigned char) line[len-1] == delim)
	    line[--len] = '\0';
	if (len == 0)
	    continue;
	// Permit comments.
	if (*line == '#' && delim == '\n')
	    continue;
	if (*line != '/')
	    die("%s: bad input", fname);
	addDepFile(line, len, true);
    }
    // Distinguish between EOF and error.
    assert(errno == 0);
    free(line);
    fclose(fp);
}

// ex:set ts=8 sts=4 sw=4 noet:
