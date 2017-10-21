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
bool bindir(const char *d, size_t dlen)
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
uint64_t hash64(const void *data, size_t size)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return t1ha1_be(data, size, 0);
#else
    return t1ha1_le(data, size, 0);
#endif
}

// The set of 64-bit fingerprints of filename dependencies.  Works as
// a probabilistic data structure for approximate membership queries.
// In the worst case (which in a typical setting is highly unlikely)
// an unrelated filename can be preserved in the output on behalf of
// filename dependencies.  Initialized in main().
struct fpset *depFiles;

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
    // Add the fingerprint.
    uint64_t fp = hash64(dep, len);
    int ret = fpset_add(depFiles, fp);
    assert(ret >= 0);
}

// Process filename dependencies from a specific tag.
bool findDepFiles1(Header h, int tag)
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

// Retrieve filename dependencies from tags like %{REQUIRENAME} and store them
// in depFiles.  Later in the second pass, each filename from %{FILENAMES} will
// be tested against the set of depFiles and possibly preserved in the output.
void findDepFiles(Header h)
{
    // Empty Requires are not permitted - someplace, they check
    // for the "rpmlib(PayloadIsLzma)" dependency as mandatory.
    bool hasReq = findDepFiles1(h, RPMTAG_REQUIRENAME);
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
    bool hasProv = findDepFiles1(h, RPMTAG_PROVIDENAME);
    assert(hasProv);
    // Conflicts are optional.
    findDepFiles1(h, RPMTAG_CONFLICTNAME);
    // Obsoletes should not be processed - they only work against
    // package names.  They should have no effect on filenames.
}

// ex:set ts=8 sts=4 sw=4 noet:
