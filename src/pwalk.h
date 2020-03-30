#ifndef PWALK_H
#define PWALK_H 1

#include <sys/param.h>

// @@@ Portabiity tidbits ...
// See also: http://sourceforge.net/p/predef/wiki/OperatingSystems/

typedef unsigned long long count_64;
typedef enum {EMBRYONIC=0, IDLE, BUSY} wstatus_t;	// Worker operational status

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
#include <ifs/ifs_types.h>
#include <ifs/ifs_syscalls.h>
#include <ifs/bam_pctl.h>
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

#define MAX_WORKERS 128				// Max -dop= value
#define MAX_MKDIR_RETRIES 32			// ????
#define MAXPATHS 64				// Arbitrary limit for [source] or [target] multi-paths
#define MAX_PATH_DEPTH 128			// Max pathname components
#define PROGRESS_TIME_INTERVAL 3600/4		// Seconds between progress outputs to log file
#define TALLY_BUCKETS_MAX 64                    // MUST be a #define!

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

// -tally scoreboard (for WS and GS) ...
typedef struct {				// Only used in WS and GS (not DS)
   count_64 count[TALLY_BUCKETS_MAX];
   count_64 size[TALLY_BUCKETS_MAX];
   count_64 space[TALLY_BUCKETS_MAX];
} TALLY_BUCKET_COUNTERS;

#if defined(PWALK_SOURCE)
FILE *Plog = NULL;			// Main logfile output (pwalk.log)
int PWget_MASK = PWget_STAT;		// Mask of PWget_* bits (always stat(), at least)
int VERBOSE = 0;			// -v (verbosity) 1, 2, 3, ... more and more verbose
int PWdebug = 0;			// -d (debug) level
int PWquiet = 0;			// -q (quiet) flag
int PWdryrun = 0;			// -dryrun flag
PWALK_DEBUG_BLOCK PBLK;
#else
extern FILE *Plog;
extern int PWget_MASK;
extern int VERBOSE;
extern int PWdebug;
extern int PWquiet;
extern int PWdryrun;
extern void abend(char *str);
extern PWALK_DEBUG_BLOCK PBLK;
#endif

// @@@ WorkerData is array of structures that contains most worker-indexed private DATA ...
#if defined(PWALK_SOURCE)
struct {                         	// Thread-specific data (WorkerData[i]) ...
#else
extern struct {
#endif
   // Worker-related ...
   int                  w_id;			// Worker's unique index
   wstatus_t            status;			// Worker status
   FILE                 *wlog;			// WLOG output file for this worker
   FILE                 *werr;			// WERR output file for this worker
   // Co-process & xacls support ...
   FILE                 *PYTHON_PIPE;		// Pipe for -audit Python symbiont
   FILE                 *WACLS_PIPE;		// Pipe for +wacls= process
   FILE                 *XACLS_BIN_FILE;	// File for +xacls=bin output
   FILE                 *XACLS_CHEX_FILE;	// File for +xacls=chex output
   FILE                 *XACLS_NFS_FILE;	// File for +xacls=nfs output
   FILE                 *XACLS_ONEFS_FILE;	// File for +xacls=onefs output
   // Pointers to runtime-allocated buffers ...
   char                 *DirPath;		// Fully-qualified directory to process
   struct dirent        *Dirent;		// Buffer for readdir_r()
   void                 *SOURCE_BUF_P;		// For -cmp source
   void                 *TARGET_BUF_P;		// For -cmp source
} WorkerData[MAX_WORKERS+1];			// klooge: s/b dynamically-allocated f(N_WORKERS) */

// @@@ Statistics blocks ...
//
// Statistics are generaly collected in three phases to avoid locking operations;
//	1. At the per-directory level (DS) - during each directory scan
//		- We need per-directory subtotals in some outputs (but not for +tally)
//	2. At the per-worker level (WS) - sub-totaled at the end of each directory scan
//		- We do not want lock competition between workers while scanning
//	3. At the pwalk global level (GS) - grand-total summed from worker subtotals at the very end
//		- Aggregating the grand totals is a lock-less operation because all workers are done

// Statistics: cascades from directory (DS) to worker (WS) to grand total (GS) summary ...
typedef struct {
   // Accumulated per-directory ...
   count_64 NOpendirs;				// Number of opendir() calls
   count_64 NScanned;				// Files scanned (superset of selected files)
   count_64 NSelected;				// Files selected (when selection option(s) given)
   count_64 NRemoved;				// Files removed (with -rm)
   count_64 NACLs;				// +acls, +xacls=, or +wacls= # files & dirs w/ ACL processed
   count_64 NStatCalls;				// Number of lstatat() calls on dirents
   count_64 NDirs;				// ... # that were directories
   count_64 NFiles;				// ... # that were files
   count_64 NSymlinks;				// ... # that were symlinks
   count_64 NOthers;				// ... # that were others
   count_64 NStatErrs;				// ... # that were errors
   count_64 NWarnings;				// Scan issues other than stat() failures
   count_64 NZeroFiles;				// Number of ordinary files of size 0
   count_64 NHardLinkFiles;			// Number of non-directories with link count > 1
   count_64 NHardLinks;				// Sum of hard link counts > 1
   off_t NBytesPhysical;			// Sum of allocated space
   off_t NBytesLogical;				// Sum of nominal file sizes
   // Accumulated per-worker for selected() files ...
   count_64 READONLY_Zero_Files;		// READONLY zero-length files
   count_64 READONLY_Opens;			// READONLY file opens
   count_64 READONLY_Errors;			// READONLY open/read errors
   count_64 READONLY_CRC_Bytes;			// READONLY CRC bytes read
   count_64 READONLY_DENIST_Bytes;		// READONLY DENIST bytes read
   count_64 NPythonCalls;			// Python calls
   count_64 NPythonErrors;			// Python errors
   count_64 MAX_inode_Value_Seen;		// Cheap-to-keep (WS, GS) stats
   count_64 MAX_inode_Value_Selected;
   TALLY_BUCKET_COUNTERS TALLY_BUCKET;		// +tally counters
} PWALK_STATS_T;

#if defined(PWALK_SOURCE)
PWALK_STATS_T GS;				// 'GS' is 'Global Stats', only referenced in main code
PWALK_STATS_T *WS[MAX_WORKERS+1];		// 'WS' is 'Worker Stats', calloc'd (per-worker)
char *PYTHON_COMMAND = NULL;			// For OneFS -audit operation
#else
extern PWALK_STATS_T GS;
extern PWALK_STATS_T *WS[];
extern char *PYTHON_COMMAND;
#endif

// Convenience MACROs for worker's thread-specific values ...
// ... so 'fprintf(WLOG' becomes 'fprintf(WorkerData[w_id].wlog' ...
// ... which of course requires a context in which 'w_id' is defined.
#define WDAT WorkerData[w_id]		// Coding convenience for w_id's worker data
#define WLOG WDAT.wlog			// Coding convenience for w_id's output FILE*
// Per-worker .err files get created only when needed ...
#define WERR (WDAT.werr ? WDAT.werr : worker_err_create(w_id))  // Coding convenience for w_id's error FILE*

#endif
