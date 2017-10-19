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

    // Trying to compare only 4-byte pieces.
    bool usr = startsWith(d, "/usr");
    if (usr)
	d += strLen("/usr"), dlen -= strLen("/usr");

    if (endsWith(d, "bin/")) {
	const char *pre = d + dlen - strLen("/bin/");
	if (*pre == '/') {
	    // Either /bin/ or /usr/bin/.
	    if (dlen == strLen("/bin/"))
		return true;
	    // Starts with /usr/lib/k*.
	    if (usr && startsWith(d, "/lib/k"))
		goto kde;
	}
	else if (memEq(pre - 1, "/s")) {
	    // Either /sbin/ or /usr/sbin/.
	    if (dlen == strLen("/sbin/"))
		return true;
	}
	return false;
    }

    // The estimable /usr/games/ shall not be forgotten.
    if (usr && strEq(d, "/games/"))
	return true;
    return false;
kde:
    // Handle /usr/lib/k*/bin/, /usr already stripped off.
    d += strLen("/lib/k"), dlen -= strLen("/lib/k");
    // Either /usr/lib/kde3/bin/ or /usr/lib/kde4/bin/.
    if (dlen == strLen("de3/bin/") && memEq(d, "de"))
	return (unsigned char) d[strLen("de")] - '3' <= 1U;
    // Either /usr/lib/kf5/bin/ or /usr/lib/kf6/bin/.
    if (dlen == strLen("f5/bin/") && (memEq(d, "f5") || memEq(d, "f6")))
	return true;
    return false;
}

// ex:set ts=8 sts=4 sw=4 noet:
