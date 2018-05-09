#ifndef PWALK_H
#define PWALK_H 1

#include <sys/param.h>

// @@@ Portabiity tidbits ...
// See also: http://sourceforge.net/p/predef/wiki/OperatingSystems/

typedef unsigned long long count_64;

#if !defined(TRUE)
#define TRUE 1
#endif
#if !defined(FALSE)
#define FALSE 0
#endif

#if __APPLE__ && __MACH__
#define __OSX__ 1
#include <mach/mach.h>
#include <mach/mach_time.h>
#endif

#if defined(LINUX)
#define __LINUX__ 1
#define HAVE_STRUCT_STAT_ST_FLAGS 0
#else
#define HAVE_STRUCT_STAT_ST_FLAGS 1
#endif

#if (defined(__FreeBSD__) || defined(__OSX__)) && !defined(BSD)
#define BSD 1
#endif

#if defined(BSD) || defined(__LINUX__)
#define BSDLINUX 1
#endif

#if defined(OneFS_ABI_version) || defined(OneFS_ABI_version_v1) || defined(OneFS_ABI_version_v2)
#define __ONEFS__ 1
#include <ifs/ifs_types.h>
#endif

// @@@ Platform dependencies ...

#if defined(SOLARIS)
#define PWALK_PLATFORM "Solaris"
#elif defined(__LINUX__)
#define PWALK_PLATFORM "Linux"
#elif defined(__OSX__)
#define PWALK_PLATFORM "OSX"
#elif defined(__ONEFS__)
#define PWALK_PLATFORM "OneFS"
#else
#define PWALK_PLATFORM "?Unknown Platform?"
#endif

#if defined(__LINUX__)
#define PWALK_ACLS 1		// NOTE: Some ACL-related code is merely dormant or innocuous
static int CLK_TCK;
#if !defined(PTHREAD_MUTEX_ERRORCHECK)
#define PTHREAD_MUTEX_ERRORCHECK PTHREAD_MUTEX_ERRORCHECK_NP
#endif // !defined(PTHREAD_MUTEX_ERRORCHECK)
#if !defined(CLOCK_MONOTONIC_RAW)
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif // !defined(CLOCK_MONOTONIC_RAW)
#ifdef TIMESPEC_HACK // klooge: only OLD Linux
#define st_atimespec st_atim
#define st_mtimespec st_mtim
#define st_ctimespec st_ctim
#define st_birthtimespec st_ctim
#define st_birthtime st_ctime
#endif // TIMESPEC_HACK
#else // -> !defined(__LINUX__)
#define PWALK_ACLS 0
#endif // defined(__LINUX__)

#if defined(__ONEFS__)
#define PWALK_AUDIT 1		// PWALK_AUDIT enables OneFS-only SmartLock audit functionality
#define USE_VTIMES 1
#include <sys/extattr.h>
#include <sys/isi_enc.h>	// for real lvtimes()/vtimes() (OneFS private)
#else				// use 'stub' versions of these to reduce inline conditional code
#define O_OPENLINK 0		// klooge: also for native BSD?
#define PWALK_AUDIT 0
#define USE_VTIMES 0
#include <sys/xattr.h>
#define VT_ATIME 1
#define VT_MTIME 2
#define VT_BTIME 4
#endif // defined(__ONEFS__)

// @@@ Global defines and shared global data ...

// Mask bits for metadata to gather during treewalk (in PWget_MASK) ...
#define PWget_STAT	0x001		// Basic stat()
#define PWget_OWNER	0x002        	// Owner name
#define PWget_GROUP	0x004        	// Group name
#define PWget_STUB	0x008		// (not implemented)
#define PWget_ACLP	0x010		// Linux only: POSIX ACL
#define PWget_ACL4	0x020		// NFS4 ACL (not implemented)
#define PWget_WORM	0x040		// OneFS only: WORM state
#define PWget_SD	0x080        	// OneFS only: Security Descriptor

typedef struct {
   void *ptr;		// point to area
   unsigned size;	// size of area
   void *copy;		// known-good copy of area
   char msg[256];	// utility buffer
} PWALK_DEBUG_BLOCK;

#if defined(PWALK_SOURCE)
int PWget_MASK = PWget_STAT;		// Mask of PWget_* bits (always stat(), at least)
int VERBOSE = 0;			// -v (verbosity) 1, 2, 3, ... more and more verbose
int PWdebug = 0;			// -d (debug) level
int PWquiet = 0;			// -q (quiet) flag
int PWdryrun = 0;			// -dryrun flag
PWALK_DEBUG_BLOCK PBLK;
#else
extern int PWget_MASK;
extern int VERBOSE;
extern int PWdebug;
extern int PWquiet;
extern int PWdryrun;
extern void abend(char *str);
extern PWALK_DEBUG_BLOCK PBLK;
#endif

#endif
