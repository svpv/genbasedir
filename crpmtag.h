// The list of special RPM tags used by APT.
// The C in CRPMTAG apparently stands for Conectiva,
// the company behind the original apt-rpm port.

// Package credentials.
#define CRPMTAG_FILENAME          1000000
#define CRPMTAG_FILESIZE          1000001
#define CRPMTAG_MD5               1000005
#define CRPMTAG_SHA1              1000006 // was never used

// Package location relative to the repo, e.g. RPMS.classic or ../SRPMS.hasher.
#define CRPMTAG_DIRECTORY         1000010
// Maps src.rpm to its subpackages, e.g. foo.src.rpm => [foo, libfoo, libfoo-devel].
#define CRPMTAG_BINARY            1000011

// The following tags were apparently designed to deliver updates in separate
// small repos, stacked atop of the "release" repo.  Actually these tags have
// not been used in APT since 0.5.5cnc1.
#if 0
#define CRPMTAG_UPDATE_SUMMARY    1000020
#define CRPMTAG_UPDATE_IMPORTANCE 1000021
#define CRPMTAG_UPDATE_DATE       1000022
#define CRPMTAG_UPDATE_URL        1000023
#endif
