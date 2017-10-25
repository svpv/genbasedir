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

#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <zpkglist.h>
#include <rpm/rpmlib.h>
#include "crpmtag.h"
#include "errexit.h"
#include "prevout.h"

struct prevout {
    struct prevhdr h;
    struct zpkglistReader *z;
    bool has, eof;
    char from[];
};

// Parse the blob and fill its credentials.
static void prevout_parse(struct prevout *p)
{
    unsigned il = ntohl(*((unsigned *) p->h.blob + 0));
    unsigned dl = ntohl(*((unsigned *) p->h.blob + 1));
    assert(8 + 16 * il + dl == p->h.blobSize);
    // The blob starts with these "index entries", followed by data.
    struct ent { int tag; int type; int off; int cnt; };
    struct ent *begin = (void *) ((char *) p->h.blob + 8);
    struct ent *end = begin + il;
    // The blob entries are sorted by tag value, and CRPPMTAG tags have
    // the highest values.  The first among them is CRPPMTAG_FILENAME,
    // followed by CRPPMTAG_FILESIZE.  We first look for CRPPMTAG_FILENAME.
    struct ent *e = (end - begin > 8) ? end - 8 : begin;
    for (; e < end; e++)
	if (e->tag == htonl(CRPMTAG_FILENAME))
	    break;
    if (e == end)
	die("%s: cannot find CRPMTAG_FILENAME", p->from);
    // CRPMTAG_FILENAME
    assert(e->type == htonl(RPM_STRING_TYPE));
    int fnamePos = ntohl(e->off);
    assert(fnamePos >= 0);
    assert(fnamePos < dl);
    p->h.rpm = (const char *) end + fnamePos;
    // CRPMTAG_FILESIZE
    e++;
    assert(e < end);
    assert(e->tag == htonl(CRPMTAG_FILESIZE));
    assert(e->type == htonl(RPM_INT32_TYPE));
    assert(e->cnt == htonl(1));
    int fsizePos = ntohl(e->off);
    assert(fnamePos >= 0);
    assert(fnamePos < dl);
    memcpy(&p->h.fsize, (char *) (begin + il) + fsizePos, 4);
    p->h.fsize = ntohl(p->h.fsize);
}

static void zdie(const char *from, const char *func, const char *err[2])
{
    if (strcmp(err[0], func) == 0)
	die("%s: %s: %s", from, err[0], err[1]);
    else
	die("%s: %s: %s: %s", from, func, err[0], err[1]);
}

struct prevout *prevout_open(const char *from)
{
    // Open pkglist.
    int fd = open(from, O_RDONLY);
    if (fd < 0)
	die("%s: %m", from);
    // Feed it to zpkglistReader.
    struct zpkglistReader *z;
    const char *err[2];
    int rc = zpkglistFdopen(&z, fd, err);
    if (rc < 0)
	zdie(from, "zpkglistFdopen", err);
    if (rc == 0)
	return warn("%s: empty input", from), NULL;
    // Try to read the first blob.
    void *blob;
    ssize_t blobSize = zpkglistNextMalloc(z, &blob, NULL, false, err);
    if (rc < 0)
	zdie(from, "zpkglistNextMalloc", err);
    if (rc == 0)
	return warn("%s: empty input", from), zpkglistClose(z), NULL;
    // Allocate the structure.
    size_t len = strlen(from);
    struct prevout *p = xmalloc(sizeof *p + len + 1);
    p->z = z;
    memcpy(p->from, from, len + 1);
    p->h.blob = blob;
    p->h.blobSize = blobSize;
    prevout_parse(p);
    p->has = true;
    p->eof = false;
    return p;
}

void prevout_close(struct prevout *p)
{
    if (!p)
	return;
    zpkglistClose(p->z);
    if (p->has)
	free(p->h.blob);
    free(p);
}

void prevout_rewind(struct prevout *p)
{
    const char *err[2];
    if (p->has) {
	p->has = false;
	free(p->h.blob);
    }
    if (!zpkglistRewind(p->z, err))
	zdie(p->from, "zpkglistRewind", err);
}

struct prevhdr *prevout_next(struct prevout *p)
{
    if (p->eof)
	return NULL;
    if (p->has) {
	p->has = false;
	return &p->h;
    }
    const char *err[2];
    ssize_t blobSize = zpkglistNextMalloc(p->z, &p->h.blob, NULL, false, err);
    if (blobSize < 0)
	zdie(p->from, "zpkglistNextMalloc", err);
    if (blobSize == 0)
	return p->eof = true, NULL;
    p->h.blobSize = blobSize;
    prevout_parse(p);
    return &p->h;
}

static inline struct prevhdr *prevout_find(struct prevout *p, const char *rpm, bool sorted)
{
    while (1) {
	struct prevhdr *h = prevout_next(p);
	if (!h)
	    return NULL;
	int cmp = strcmp(h->rpm, rpm);
	if (cmp == 0)
	    return h;
	if (sorted && cmp > 0) {
	    p->has = true;
	    return NULL;
	}
	free(h->blob);
    }
}

struct prevhdr *prevout_find_src(struct prevout *p, const char *rpm)
{
    return prevout_find(p, rpm, true);
}

struct prevhdr *prevout_find_pkg(struct prevout *p, const char *rpm)
{
    return prevout_find(p, rpm, false);
}

// ex:set ts=8 sts=4 sw=4 noet:
