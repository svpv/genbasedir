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
#include <sys/stat.h> // mkdir
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
}

// ex:set ts=8 sts=4 sw=4 noet:
