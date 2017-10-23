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
#include <dirent.h>
#include <errno.h>
#include "qsort.h"

// Source rpm filenames are stored in the string tab.
static char strtab[64<<20];
static size_t strtabPos = 1;

// Source rpms which will be processed.
static char *srpms[1<<20];
static size_t nsrpm;

// Load srpms[] from SRPMS.comp dirfd.
static void loadDir(int dirfd)
{
    DIR *dirp = fdopendir(dirfd);
    assert(dirp);
    while (1) {
	errno = 0;
	struct dirent *d = readdir(dirp);
	if (!d)
	    break;
	if (*d->d_name == '.')
	    continue;
	size_t len = strlen(d->d_name);
	if (len <= 8 || memcmp(d->d_name + len - 8, ".src.rpm", 8))
	    continue;
	assert(strtabPos + len + 1 < sizeof strtab);
	memcpy(strtab + strtabPos, d->d_name, len + 1);
	srpms[nsrpm++] = strtab + strtabPos;
	strtabPos += len + 1;
    }
    assert(errno == 0);
    closedir(dirp);
    char *tmp;
#define srpms_less(i, j) strcmp(srpms[i], srpms[j]) < 0
#define srpms_swap(i, j) tmp = srpms[i], srpms[i] = srpms[j], srpms[j] = tmp
    QSORT(nsrpm, srpms_less, srpms_swap);
}

// ex:set ts=8 sts=4 sw=4 noet:
