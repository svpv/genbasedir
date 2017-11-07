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

#include <getopt.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include "errexit.h"

enum {
    OPT_FLAT = 256,
};

static int flat;

static const struct option longopts[] = {
    { "help", no_argument, NULL, 'h' },
    { "flat", no_argument, &flat, 1 },
    { NULL },
};

int main(int argc, char **argv)
{
    int c;
    while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
	switch (c) {
	case 0:
	    break;
	default:
usage:	    fprintf(stderr, "Usage: %s [OPTIONS...] [ARGS...]\n", PROG);
	    return 1;
	}
    }
    argc -= optind, argv += optind;
    if (argc < 2) {
	warn("not enough arguments");
	goto usage;
    }

    // Open the repo dir.  I don't want to mess with snprintf or strcat
    // to make full paths, I would rather use openat(2) with dirfd.
    const char *dir = argv[0];
    int dirfd = open(dir, O_RDONLY | O_NONBLOCK | O_DIRECTORY);
    if (dirfd < 0)
	die("%s: %m", dir);

    // Check the component name.
    const char *comp = argv[1];
    size_t complen = strlen(comp);
    assert(complen + sizeof "srclist..zst" - 1 < NAME_MAX);

    // Make SRPMS.comp name.
    char srpmdir[complen + sizeof "../SRPMS." - flat];
    memcpy(srpmdir, "../SRPMS." + flat, sizeof "../SRPMS." - 1 - flat);
    memcpy(srpmdir + sizeof "../SRPMS." - 1 - flat, comp, complen + 1);
    // Open SRPMS.comp dir.
    int srpmdirfd = openat(dirfd, srpmdir, O_RDONLY | O_NONBLOCK | O_DIRECTORY);
    if (srpmdirfd < 0)
	die("%s/%s: %m", dir, srpmdir);

    // Make srclist.comp.zst name.
    char srclist[complen + sizeof "base/srclist..zst"];
    memcpy(srclist, "base/srclist.", sizeof "base/srclist." - 1);
    memcpy(srclist + sizeof "base/srclist." - 1, comp, complen);
    memcpy(srclist + sizeof "base/srclist." - 1 + complen, ".zst", sizeof ".zst");
    // Support inplace update.
    unlinkat(dirfd, srclist, 0);
    // Open srclist.comp.zst for writing.
    int outfd = openat(dirfd, srclist, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (outfd < 0)
	die("%s/%s: %m", dir, srclist);

    // Repo dirfd no longer needed.
    close(dirfd);

    // Chdir to SRPMS.comp.
    if (fchdir(srpmdirfd) < 0)
	die("%s/%s: %m", dir, srpmdir);

    // Load srpms (srpmdirfd will be closed).
    loadDir(srpmdirfd);

    return 0;
}

// ex:set ts=8 sts=4 sw=4 noet:
