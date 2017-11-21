// Copyright (c) 2008, 2017 Alexey Tourbin
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

#include <assert.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>

static Header readHeader(const char *rpm, FD_t FD)
{
    static rpmts ts;
    if (ts == NULL) {
	//rpmReadConfigFiles(NULL, NULL);
	ts = rpmtsCreate();
	assert(ts);
	rpmtsSetVSFlags(ts, (rpmVSFlags) -1);
    }
    Header h = NULL;
    int rc = rpmReadPackageFile(ts, FD, rpm, &h);
    if (rc == RPMRC_OK || rc == RPMRC_NOTTRUSTED || rc == RPMRC_NOKEY)
	return h;
    return NULL;
}

static void copyTag(Header h1, Header h2, int tag)
{
    struct rpmtd_s td;
    // Copy raw entry, so that internationalized strings
    // will get copied correctly.
    int rc = headerGet(h1, tag, &td, HEADERGET_MINMEM | HEADERGET_RAW);
    if (rc == 1) {
	rc = headerPut(h2, &td, HEADERPUT_DEFAULT);
	assert(rc == 1);
	rpmtdFreeData(&td);
    }
}

static void copyTags(Header h1, Header h2, const int tags[], int ntag)
{
    for (int i = 0; i < ntag; i++)
	copyTag(h1, h2, tags[i]);
}

static void addStringTag(Header h, int tag, const char *str)
{
    struct rpmtd_s td = { .tag = tag, .type = RPM_STRING_TYPE,
			  .data = (char *) str, .count = 1 };
    int rc = headerPut(h, &td, HEADERPUT_DEFAULT);
    assert(rc == 1);
}

static void addUint32Tag(Header h, int tag, unsigned val)
{
    struct rpmtd_s td = { .tag = tag, .type = RPM_INT32_TYPE,
			  .data = &val, .count = 1 };
    int rc = headerPut(h, &td, HEADERPUT_DEFAULT);
    assert(rc == 1);
}

// ex:set ts=8 sts=4 sw=4 noet:
