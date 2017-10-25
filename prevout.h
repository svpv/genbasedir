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

// The previous output written by genpkglist/gensrclist can be reused as a
// cache for the next run of the program - that is, most of the headers can
// be picked up from the existing pkglist/srclist rather than re-read from
// rpms/srpms.  In order for this to work, a few conditions must be met:
// 1) The previous output must be valid and must be provided in good faith.
// The program makes various assumptions such as that the headers on pkglist
// are in the right order.  The program would rather die than try to handle
// gracefully various kinds of defective pkglists.
// 2) Packages are identified by CRPMTAG_FILENAME - therefore, packages
// must not be overwritten (otherwise, the program will pick up the header
// that does not match the disk package).  This condition holds for the
// pkglist.classic files written by girar-builder, which rejects packages
// with the same filename early on.  (Furthermore, if a package makes its
// way into pkglist, but the task is rejected, then pkglist is discarded.)
// This is unlike hasher, which overwrites packages routinely.  Therefore,
// pkglist.task files do not meet the criteria and cannot be reused as a
// cache.  Technically, pkglists provide CRPMTAG_FILESIZE, which is only
// useful as the last bastion of protection against overwrites.  FILESIZE
// is not enough to detect overwrites properly, mtime must also be checked.
// I even thought of adding the new CRPMTAG_MTIME tag, but then all the
// packages in a task are scanned with sisyphus_check anyway, so re-reading
// the headers from the filesystem cache should be just as fast or faster
// than trying to deal with pkglist.task.
// 3) Only bloated pkglists (i.e. with a full list of packaged files for
// each header, generated with the --bloat or --bloater option) can be
// reused.  Stripped headers cannot be reused to form a new package list,
// because the list of files kept in a header essentially depends on every
// other header on the list.  Thus reusing stripped pkglists will likely
// result in unmet dependencies.

// Headers from the previous output are exposed through this structure.
// It is part of a larger internal structure and is reused as the return
// value on each iteration.
struct prevhdr {
    // Once the structure is exposed as the return value, ownership over
    // the malloc'd blob is transferred to the caller.  The caller should
    // typically either load the blob with headerImport (which will retake
    // ownership) or free the blob - eventually, not necessarily before
    // retrieving the next blob.
    void *blob;
    size_t blobSize;
    // Header credentials, as discussed above.
    const char *rpm; // CRPMTAG_FILENAME, points somewhere into the blob.
    unsigned fsize; // CRPMTAG_FILESIZE
};

// Create a handle for the previous output.
// Dies on error, returns NULL on empty, er, input.
struct prevout *prevout_open(const char *from);
void prevout_close(struct prevout *p);

// It is possible to implement two-pass algorithms.
void prevout_rewind(struct prevout *p);

// Iterate the headers.  Returns NULL on EOF.
struct prevhdr *prevout_next(struct prevout *p);

// Iterate the headers until a package is found by its .rpm filename.
// This only works for srclists, where headers are sorted by filename.
// Returns NULL on EOF, or when a package is not found.
struct prevhdr *prevout_find_src(struct prevout *p, const char *rpm);

// In pkglists, headers are grouped by src.rpm.  Sorting them out requires
// a separate first pass.  This function implements "unbounded search" for
// the second pass.
struct prevhdr *prevout_find_pkg(struct prevout *p, const char *rpm);
