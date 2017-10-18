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

bool usefulFile1(const char *d, size_t dlen, const char *b)
{
    // Compare a string to a string literal.
#define strLen(ss) (sizeof(ss "") - 1)
#define memEq(s, ss) (memcmp(s, ss, strLen(ss)) == 0)
#define strEq(s, ss) (s##len == strLen(ss) && memEq(s, ss))
#define startsWith(s, ss) (s##len >= strLen(ss) && memEq(s, ss))
#define endsWith(s, ss) (s##len >= strLen(ss) && memEq(s + s##len - strLen(ss), ss))

    // Trying to compare only 4-byte and 8-byte pieces.
    bool usr = startsWith(d, "/usr");

    // Skip /usr/lib/debug/ which has false bindirs, along with /usr/src/debug/.
    if (usr && dlen >= strLen("/usr/lib/debug/") && memEq(d + 11, "bug/"))
	if ((memEq(d + 4, "/lib/deb") || memEq(d + 4, "/src/deb")))
	    return false;

    // PATH-like directories - /bin/ and /sbin/.
    if (endsWith(d, "bin/")) {
	const char *pre = d + dlen - strLen("/bin/");
	if (*pre == '/' || memEq(pre - 1, "/s"))
	    return true;
    }

    // Only /usr/share/ and /usr/games/ are left of interest.
    if (!usr || dlen < strLen("/usr/share/"))
	return false;
    if (memEq(d + strLen("/us"), "r/games/"))
	return true;
    if (memEq(d + strLen("/us"), "r/share/") == false)
	return false;

    // Handle files under /usr/share/.
    d += strLen("/usr/share/"), dlen -= strLen("/usr/share/");
    // Java jars.
    if (startsWith(d, "java/")) {
	size_t blen = strlen(b);
	return endsWith(b, ".jar");
    }
    // ttf and otf fonts.
    if (startsWith(d, "fonts/")) {
	size_t blen = strlen(b);
	return endsWith(b, ".ttf") || endsWith(b, ".otf");
    }

    return false;
}

// ex:set ts=8 sts=4 sw=4 noet:
