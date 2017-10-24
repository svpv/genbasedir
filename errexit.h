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

#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define PROG program_invocation_short_name
#define warn(fmt, args...) fprintf(stderr, "%s: " fmt "\n", PROG, ##args)
#define die(fmt, args...) warn(fmt, ##args), exit(128) // like git

static inline void *xmalloc_(size_t n,
	const char *func, const char *file, int line)
{
    void *buf = malloc(n);
    if (buf == NULL)
	die("cannot allocate %zu bytes in %s() at %s line %d",
	    n, func, file, line);
    return buf;
}

#define xmalloc(n) xmalloc_(n, __func__, __FILE__, __LINE__)

// ex:set ts=8 sts=4 sw=4 noet:
