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

#include "depfiles.h"

#include <getopt.h>
#include <fcntl.h>
#include "errexit.h"

enum {
    OPT_BLOAT = 256,
    OPT_USEFUL_FILES_FROM,
    OPT_USEFUL_FILES0_FROM,
};

static int bloat;

static const struct option longopts[] = {
    { "help", no_argument, NULL, 'h' },
    { "bloat", no_argument, &bloat, 1 },
    { "useful-files", required_argument, NULL, OPT_USEFUL_FILES_FROM },
    { "useful-files-from", required_argument, NULL, OPT_USEFUL_FILES_FROM },
    { "useful-files0-from", required_argument, NULL, OPT_USEFUL_FILES0_FROM },
    { NULL },
};

int main(int argc, char **argv)
{
#define USEFUL_FILES_MAX 8
    size_t usefulFilesCount = 0;
    const char *usefulFilesFrom[USEFUL_FILES_MAX];
    char usefulFilesDelim[USEFUL_FILES_MAX];
    int c;
    while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
	switch (c) {
	case 0:
	    break;
	case OPT_USEFUL_FILES_FROM:
	    if (usefulFilesCount < USEFUL_FILES_MAX) {
		usefulFilesFrom[usefulFilesCount] = optarg,
		usefulFilesDelim[usefulFilesCount] = '\n';
	    }
	    usefulFilesCount++;
	    break;
	case OPT_USEFUL_FILES0_FROM:
	    if (usefulFilesCount < USEFUL_FILES_MAX) {
		usefulFilesFrom[usefulFilesCount] = optarg,
		usefulFilesDelim[usefulFilesCount] = '\0';
	    }
	    usefulFilesCount++;
	    break;
	default:
	    fprintf(stderr, "Usage: %s [OPTIONS...] [ARGS...]\n", PROG);
	    return 1;
	}
    }

    argc -= optind, argv += optind;

    if (usefulFilesCount) {
	if (bloat)
	    warn("--useful-files redundant with --bloat");
	else if (usefulFilesCount > USEFUL_FILES_MAX)
	    die("too may --useful-files options");
	else {
	    for (size_t i = 0; i < usefulFilesCount; i++)
		readDepFiles(usefulFilesFrom[i], usefulFilesDelim[i]);
	}
    }

    return 0;
}

// ex:set ts=8 sts=4 sw=4 noet:
