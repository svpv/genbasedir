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

// ex:set ts=8 sts=4 sw=4 noet:
