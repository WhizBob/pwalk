// pwalk.c - by Bob Sneed (Bob.Sneed@dell.com) - FREE CODE, based on prior work whose source
// was previously distributed as FREE CODE.

#define PWALK_VERSION "pwalk 2.07--"	// See also: CHANGELOG
#define PWALK_SOURCE 1

// --- DISCLAIMERS ---
//
// This is FREE CODE, intended for instructional and non-production purposes only. There
// are no warranties, express or implied of any sort whatsoever, including any warrantees
// of correctness or suitability for any particular purpose. Use at your own risk. This
// code is explicitly not a supported product of Dell EMC.
//
// The coding style is unapologetically ad-hoc, with lots of global variables, an occassional
// 'goto' and occassionally crude (but semi-thorough) error-handling.  Coding strategies
// prioritize speed over elegance.
//
// --- DESCRIPTION ---
//
// This program does a multithreaded directory tree walk with a variable degree of concurrency,
// optionally spreading the work across multiple 'equivalent paths' which represent the same
// exported NAS directory structure. It is implemented using POSIX pThreads for portability.
// Program outputs vary depending on the command-line options specified.  This code is intended
// to be a reusable template for constructing diverse tactical solutions requiring a high-speed
// concurrent treewalk foundation.
//
// This code has been developed and tested on Linux, Solaris, OSX, and OneFS - but not all build
// targets have been tested for each iteration of the code. Some functionality is coded such that
// it is only supported on specific build platforms, such as ACL-related features only supported
// on Linux, or SmartLock auditing features only supported natively on OneFS.
//
// For walking large directory structures on OneFS, better performance has been observed when
// running the code over NFS or SMB NAS protocols versus direct execution on OneFS. With NFS,
// this is presumeably due to the benefits of READIRPLUS more-efficiently collecting file attribute
// data than single per-file stat()-family calls used natively on OneFS. Beware that high rates of
// READIRPLUS calls targeting a single OneFS initiator node within a OneFS cluster can cause high
// CPU usage on that initiator node. It is advised to test first with moderate levels of concurrency
// per-initiator-node, and to leverage the multi-pathing feature to distribute the burden of pwalk's
// queries across multiple OneFS initiator nodes.
//
// --- HISTORY ---
//
// Since 2013; See CHANGELOG
//
// --- CODING NOTES ---
//
// To compile & build -- see Makefile.<platform>
//
// Linux:   	gcc -DLINUX pwalk.c pwalk_acls.c pwalk_report.h -o pwalk -lm -lrt -lpthread
//	NOTE: -dH enables core dumps, may require 'ulimit -c unlimited'
//	NOTE: debug with 'gdb pwalk core.<pid>' ... 'bt'
// OSX:     	cc pwalk.c pwalk_acls.c pwalk_report.c -o pwalk
// OneFS:	cc pwalk.c pwalk_report.c -o pwalk -lm -lthrthread		// 7.1
//		cc pwalk.c pwalk_report.c -o pwalk -lm -lrt -lpthread		// 7.2
//		TBD								// 8.0
// Solaris: 	gcc -m64 -DSOLARIS pwalk.c -o pwalk -lm -lrt -lpthread
// ? Solaris:	cc -mt pwalk.c pwalk_report.c -o pwalk -lpthread		// w/ Workshop Compiler ?
// ? Windows:	// maybe some day ...
//
// NOTE: 'klooge' comments mark opportunities for further refinement; either future
// desireable features or places where increased robustness might be added.
//
// --- DESIGN NOTES ---
//
// pwalk writes all of its outputs to a directory that is named according to the time
// pwalk is run. The output consists of;
//
//	- pwalk.log - an actvity log with timestamps
//	- pwalk.fifo - FIFO of files and directories (command-line dirs plus discovered dirs)
//	- worker_$N.{xml,ls,etc} - one output file per worker
//
// pwalk pushes each directory enocuntered onto a file-based FIFO, and each worker thread
// pops the FIFO for more work as long it is not empty.
//
// The worst-case performance for this algorithm would be to encounter a directory
// hierarchy in which the last entry in each directory was another directory.  In that
// case, no processing concurrency will ever be developed.
//
// We choose not to use a re-entrant design in this program, because we want to maximize
// scalability without being dependent of the process stack size. We maintain a FIFO of
// directory pathnames in a file that is retained as part of the output, and that file
// could grow as large as the aggregate size of all the directory pathnames encountered.
//
// The runtime environment must allow enough open files to have one-per-worker-thread.
//
// --- NOTES ON THE DENIST ('+denist') FEATURE ---
//
// BACKGROUND: The US National Institute for Science and Technology (NIST) maintains a database of
// common files that are know to be non-malicious, such as common operating system files (think
// COMMAND.COM).  E-discovery applications exclude analysis of such well-known files.  The process
// of identifying and excluding such files is called 'de-NISTing'.
//
// One technique for identifying such files is to read the first 128 bytes of a file and calculate
// its MD5 checksum. The resulting I/O workload is characteristically small-random-read in nature.
//
// When '+denist' specified, pwalk will read() the 1st 128 bytes of each ordinary file encountered.
// This feature is for the sole purpose of benchmarking how long de-NISTing logic might run on a
// given data set with a given degree on concurrency applied.

// @@@ SECTION: Declarations @@@

// @@@ Basic #includes ...

// RE: http://docs.oracle.com/cd/E19683-01/806-6867/compile-74765/index.html
#ifdef SOLARIS
#define _GNU_SOURCE
#define _POSIX_PTHREAD_SEMANTICS
#define _LARGEFILE64_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <assert.h>

// Additional modules ...
#include "pwalk.h"		// Global data and forward declarations
#include "pwalk_onefs.h"	// OneFS-specific logic
#include "pwalk_report.h"	// Generic reporting
#include "pwalk_sums.h"		// Checksum generators

#if PWALK_ACLS			// POSIX ACL-handling logic only on Linux
#include "pwalk_acls.h"
#endif // PWALK_ACLS

// @@@ Program initializers & compile-time constraints ...

// Shorthand MACROs for casting printf args ...
#define UL(x) ((unsigned long) x)

#define PROGNAME "pwalk"		// Our program basename only

#if defined(SOLARIS)			// Platform name
#define PWALK_PLATFORM "Solaris"
#elif defined(__LINUX__)
#define PWALK_PLATFORM "Linux"
#elif defined(__OSX__)
#define PWALK_PLATFORM "OSX"
#include <execinfo.h>
#elif defined(__ONEFS__)
#define PWALK_PLATFORM "OneFS"
#else
#define PWALK_PLATFORM "?Unknown Platform?"
#endif

#define MAX_DEPTH 128
#define MAX_WORKERS 128
#define MAX_MKDIR_RETRIES 32

#ifdef SOLARIS
#define MAX_NAMELEN _PC_NAME_MAX
#define MAX_PATHLEN MAXPATHLEN
#else
#define MAX_NAMELEN 256
#define MAX_PATHLEN 1024
#endif

#define WORKER_OBUF_SIZE 32*1024	// Output buffer, per-worker
#define NUL '\0';
#define PATHSEPCHR '/'			// Might make conditional for Windoze
#define PATHSEPSTR "/"			// Might make conditional for Windoze
#define SECS_PER_DAY 86400		// 24*60*60 = 86400

// @@@ Forward declarations ...
void fifo_push(char *p, struct stat *sb, int w_id);
int fifo_pop(char *p);
void directory_scan(int w_id);
void abend(char *msg);
void *worker_thread(void *parg);

// @@@ Worker operational status ...
typedef enum {EMBRYONIC=0, IDLE, BUSY} wstatus_t;	// Worker status

// @@@ Global variables written *only* by the main controlling thread ...
static int N_WORKERS = 1;		// <N> from "-dop=<N>" defaults to 1
static int MAX_OPEN_FILES = 0;		// Calculated to compare with getrlimit(NOFILES)
static int ABSPATH_MODE = 0;		// True when absolute paths used (FUTURE: eliminate)
static int Opt_SKIPSNAPS = 1;		// Skip .snapshot[s] dirs unless '+.snapshot' specified
static int Opt_TSTAT = 0;		// Show timed statistics when +tstat used
static int Opt_GZ = 0;			// gzip output streams when '-gz' used
static int Opt_REDACT = 0;		// Redact output (hex inodes instead of names)
static int Opt_MODE = 1;		// Show mode bits unless -pmode suppresses
static int Opt_SPAN = 0;		// Include dirs that cross filesystems unless '+span'
static int P_ACL_P = 0;			// Show ACL as '+'
static int P_CRC32 = 0;			// Show CRC32 for -ls, -xml
static int P_MD5 = 0;			// Show MD5 for -ls, -xml
static int ST_BLOCK_SIZE = 1024;	// Units for statbuf->st_blocks (-bs=512 option to change)
static char *PYTHON_COMMAND = NULL;	// For OneFS -audit operation
static struct {				// UID and EUID are different when pwalk is setuid root
   uid_t uid;
   uid_t euid;
   gid_t gid;
   uid_t egid;
} USER;

// Primary operating modes ...
static int Cmd_LS = 0;
static int Cmd_LSD = 0;
static int Cmd_LSC = 0;
static int Cmd_CMP = 0;
static int Cmd_CSV = 0;
static int Cmd_AUDIT = 0;
static int Cmd_RM = 0;
static int Cmd_FIXTIMES = 0;
static int Cmd_TRASH = 0;
static int Cmd_XML = 0;

// Secondary modes ...
static int Cmd_DENIST = 0;			// +denist
static int Cmd_RM_ACLS = 0;			// +rm_acls (OneFS only)
static int Cmd_TALLY = 0;			// +tally
static int Cmd_WACLS = 0;			// +wacls=
static int Cmd_XACLS = 0;			// +xacls= (Linux only) bitmask combo of ...
#define Cmd_XACLS_BIN 1
#define Cmd_XACLS_CHEX 2
#define Cmd_XACLS_NFS 4
#define Cmd_XACLS_ONEFS 8

// Path-related arguments & related globals ...
static char *CWD;	 			// Initial CWD; default source and output directory context
static ino_t CWD_INODE;				// For -redact
static char *SOURCE_ARG = NULL;  		// For -source= arg
static char *TARGET_ARG = NULL;  		// For -target= arg
static char *OUTPUT_ARG = ".";  		// For -output= arg
static char OUTPUT_DIR[MAX_PATHLEN+1];		// Directory we'll create for output files
static char *WACLS_CMD = NULL;  		// For +wacls= arg

// For -cmp ...
#define CMP_BUFFER_SIZE 128*1024		// -cmp buffer sizes

// For -select (klooge: criteria are implictly OR'd for now) ...
static time_t SELECT_T_SINCE = 0;		// mtime of -since=<file>
static int SELECT_SINCE = 0;			// -since= specified
static int SELECT_FAKE = 0;			// -select=fake specified
static int SELECT_HARDCODED = 0;		// Bare -select specified

// Multipath variables ...
#define MAXPATHS 64
static int   N_SOURCE_PATHS = 0;		// == 1 when -source= or default CWD, or >1 w/ [source]
static int   N_TARGET_PATHS = 0;
static char *SOURCE_PATHS[MAXPATHS];		// for assembling full pathnames
static char *TARGET_PATHS[MAXPATHS];
static ino_t SOURCE_INODES[MAXPATHS];		// all equivalent paths must repesent same inode
static ino_t TARGET_INODES[MAXPATHS];
static int   SOURCE_DFDS[MAXPATHS];		// directory fd's for fstatat(), openat(), etc al
static int   TARGET_DFDS[MAXPATHS];

// @@@ Multipath MACROS for source & target path or dfd values as f(w_id) ...
// When we call these, we are assured that N_SOURCE_PATHS and N_TARGET_PATHS are >= 1
#define SOURCE_DFD(x)  (SOURCE_DFDS[x % N_SOURCE_PATHS])
#define SOURCE_PATH(x) (SOURCE_PATHS[x % N_SOURCE_PATHS])
#define SOURCE_INODE   (SOURCE_INODES[0])
#define TARGET_DFD(x)  (TARGET_DFDS[x % N_TARGET_PATHS])
#define TARGET_PATH(x) (TARGET_PATHS[x % N_TARGET_PATHS])
#define TARGET_INODE   (TARGET_INODES[0])

// @@@ Global parameters for +tally  ...

#define TALLY_BUCKETS_MAX 64			// MUST be a #define!
// Args that drive +tally (klooge: runtime parameterize these!) ...
static char *TALLY_TAG = "tally";               // Default '+tally=<tag>' value
static char *TALLY_COLUMN_HEADING[] = {
   "Tag[i]","Bucket","Count","Count%","sum(Size)","Size%","sum(Space)","Space%","Inflation%",NULL
};
static int TALLY_BUCKETS = 27;			// Number of TALLY buckets
static count_64 TALLY_BUCKET_SIZE[TALLY_BUCKETS_MAX] = {
   0, 1024, 2048, 4096, 8192, 2*8192, 3*8192, 4*8192, 5*8192, 6*8192, 7*8192, 8*8192,
   9*8192, 10*8192, 11*8192, 12*8192, 13*8192, 14*8192, 15*8192, 16*8192,
   256*1024, 512*1024, 1024*1024, 2048*1024, 4096*1024, 8192*1024, 0
};

// Accumulators ...
typedef struct {				// Only used in WS and GS
   count_64 count[TALLY_BUCKETS_MAX];
   count_64 size[TALLY_BUCKETS_MAX];
   count_64 space[TALLY_BUCKETS_MAX];
} TALLY_BUCKET_COUNTERS;

// parse [tally] args ...

// @@@ Globals foundational to the treewalk logic per se ...
static FILE *Fpop = NULL, *Fpush = NULL;	// File-based FIFO pointers
static FILE *Plog = NULL;			// Main logfile output (pwalk.log)
static count_64 T_START_hires, T_FINISH_hires;	// For Program elapsed time (hi-res)
static struct timeval T_START_tv;		// Program start time as timeval ...

#define MAXPATHS 64				// Arbitrary limit for [source] or [target] multi-paths
#define PROGRESS_TIME_INTERVAL 3600/4		// Seconds between progress outputs to log file

// @@@ Statistics blocks ...
//
// Statistics are generaly collected in three phases to avoid locking operations;
//	1. At the per-directory level (DS) - during each directory scan
//		- We need per-directory subtotals in some outputs (but not for +tally)
//	2. At the per-worker level (WS) - sub-totaled at the end of each directory scan
//		- We do not want lock competition between workers while scanning
//	3. At the pwalk global level (GS) - grand-total summed from worker subtotals at the very end
//		- Aggregating the grand totals is a lock-less operation because all workers are done

// Statistics: cascades from directory to worker to grand total (global) summary ...
typedef struct {
   // Accumulated per-directory ...
   count_64 NOpendirs;				// Number of opendir() calls
   count_64 NACLs;				// +acls, +xacls=, or +wacls= # files & dirs w/ ACL processed
   count_64 NRemoved;				// Files removed (with -rm)
   count_64 NStatCalls;				// Number of calls to lstatat() during scans
   count_64 NDirs;				// ... # that were directories
   count_64 NFiles;				// ... # that were files
   count_64 NSymlinks;				// ... # that were symlinks
   count_64 NOthers;				// ... # that were others
   count_64 NStatErrors;			// ... # that were errors
   count_64 NWarnings;				// Scan issues other than stat() failures
   count_64 NZeroFiles;				// Number of ordinary files of size 0
   count_64 NHardLinkFiles;			// Number of non-directories with link count > 1
   count_64 NHardLinks;				// Sum of hard link counts > 1
   off_t NBytesAllocated;			// Sum of allocated space
   off_t NBytesNominal;				// Sum of nominal file sizes
   // Accumulated per-worker ...
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
static PWALK_STATS_T GS;			// 'GS' is 'Global Stats'
static PWALK_STATS_T *WS[MAX_WORKERS+1];	// 'WS' is 'Worker Stats', calloc'd (per-worker) on worker startup

// MP mutex for MP-coherency of worker status and FIFO state ...
static pthread_mutex_t	MP_mutex;
#define MP_LOCK(msg) { if (pthread_mutex_lock(&MP_mutex)) abend(msg); }			// MP lock macro
#define MP_UNLOCK { if (pthread_mutex_unlock(&MP_mutex)) abend("unlock(MP_mutex)"); }	// MP unlock macro
unsigned Workers_BUSY = 0;			// Also WDAT.status uses this mutex
count_64 FIFO_PUSHES = 0;			// # pushes (increments in fifo_push())
count_64 FIFO_POPS = 0;				// # pops (increments in fifo_pop())
count_64 FIFO_DEPTH = 0;			// # FIFO_PUSHES - FIFO_POPS

// LOGMSG mutex for serializaing access to pwalk.log (in LogMsg()) ...
static pthread_mutex_t	LOGMSG_mutex;

// MANAGER CV & mutex for MANAGER wakeup logic ...
static pthread_cond_t	MANAGER_cond;
static pthread_mutex_t	MANAGER_mutex;

// WORKER CVs & mutexes for WORKER wakeup logic ...
static pthread_cond_t	WORKER_cond[MAX_WORKERS];
static pthread_mutex_t	WORKER_mutex[MAX_WORKERS];

// pThreads ...
pthread_t		WORKER_pthread[MAX_WORKERS];

// @@@ WorkerData is array of structures that contains most worker-indexed private DATA ...
static struct {				// Thread-specific data (WorkerData[i]) ...
   // Worker-related ...
   int			w_id;			// Worker's unique index
   wstatus_t		status; 		// Worker status
   FILE			*wlog;			// WLOG output file for this worker
   FILE			*werr;			// WERR output file for this worker
   // Co-process & xacls support ...
   FILE 		*PYTHON_PIPE;		// Pipe for -audit Python symbiont
   FILE 		*WACLS_PIPE;		// Pipe for +wacls= process
   FILE 		*XACLS_BIN_FILE;	// File for +xacls=bin output
   FILE 		*XACLS_CHEX_FILE;	// File for +xacls=chex output
   FILE 		*XACLS_NFS_FILE;	// File for +xacls=nfs output
   FILE 		*XACLS_ONEFS_FILE;	// File for +xacls=onefs output
   // Pointers to runtime-allocated buffers ...
   char			*DirPath;		// Fully-qualified directory to process
   struct dirent	*Dirent;		// Buffer for readdir_r()
   void			*SOURCE_BUF_P;		// For -cmp source
   void			*TARGET_BUF_P;		// For -cmp source
} WorkerData[MAX_WORKERS+1];			// klooge: s/b dynamically-allocated f(N_WORKERS) */

// Convenience MACROs for worker's thread-specific values ...
// ... so 'fprintf(WLOG' becomes 'fprintf(WorkerData[w_id].wlog' ...
// ... which of course requires a context in which 'w_id' is defined.
#define WDAT WorkerData[w_id]		// Coding convenience for w_id's worker data
#define WLOG WDAT.wlog			// Coding convenience for w_id's output FILE*
// Per-worker .err files get created only when needed ...
#define WERR (WDAT.werr ? WDAT.werr : worker_err_create(w_id))	// Coding convenience for w_id's error FILE*

void
dump_thread(char *name, pthread_mutex_t *mutex)
{
   void *ptr;

   ptr = mutex;
   fprintf(stderr, "= %s\n", name);
   fprintf(stderr, "%llx\n", (count_64) ptr);
   fprintf(stderr, "%llx\n", (count_64) ptr + 1);
   fprintf(stderr, "%llx\n", (count_64) ptr + 2);
   fprintf(stderr, "%llx\n", (count_64) ptr + 3);
   fprintf(stderr, "%llx\n", (count_64) ptr + 4);
   fprintf(stderr, "%llx\n", (count_64) ptr + 5);
   fprintf(stderr, "%llx\n", (count_64) ptr + 6);
   fprintf(stderr, "%llx\n", (count_64) ptr + 7);
}

// @@@ SECTION: Portable hi-resolution timing support  @@@

// gethrtime(void) - return nanoseconds, monotonically ascending, platform-independent.

// See also:
// http://nadeausoftware.com/articles/2012/04/c_c_tip_how_measure_elapsed_real_time_benchmarking#machabsolutetimenbsp
// http://stackoverflow.com/questions/12392278/measure-time-in-linux-getrusage-vs-clock-gettime-vs-clock-vs-gettimeofday
// ... all interesting, but OSX case remains troublesome.

#if defined(BSDLINUX)
long long
gethrtime(void)
{
   struct timespec ts;

#if defined(__OSX__)
   // Get the timebase info ...
   mach_timebase_info_data_t info;
   static int pass1 = 1;
   static double conversion;

   if (pass1) {
      mach_timebase_info(&info);
      conversion = (double) info.numer / (double) info.denom;
      pass1 = 0;
   }
   return (long long) trunc((mach_absolute_time() * conversion));
#elif defined(BSD)
   clock_gettime(CLOCK_REALTIME_PRECISE, &ts);
   return ts.tv_sec * 1000000000LL + ts.tv_nsec;
#elif defined(__LINUX__)
   clock_gettime(CLOCK_MONOTONIC_RAW, &ts);             // NOTE: CLOCK_PROCESS_CPUTIME_ID gets %sys only
   return ts.tv_sec * 1000000000LL + ts.tv_nsec;
#endif
}
#endif // BSDLINUX

// @@@ SECTION: Simple support functions @@@

char *
format_ns_delta_t(char *ostr, count_64 ns_start, count_64 ns_end)
{
   count_64 t_elapsed_ns;
   double t_elapsed_sec, t_s;
   int t_day, t_h, t_m;

   t_elapsed_ns = ns_end - ns_start;
   t_elapsed_sec = t_elapsed_ns / 1000000000.;		// convert nanoseconds to floating seconds
   if (t_elapsed_ns < 1000000) {
      sprintf(ostr, "%lluns", t_elapsed_ns);
   } else if (t_elapsed_ns < 1000000000) {
      sprintf(ostr, "%5.3fms", t_elapsed_ns/1000000.);
   } else if (t_elapsed_sec < 60) {
      sprintf(ostr, "%5.3fsec", t_elapsed_sec);
   } else {
      t_day = trunc(t_elapsed_sec / 86400);
      if (t_day >= 1.) t_elapsed_sec -= t_day * 86400;
      t_h = trunc(t_elapsed_sec / 3600.);
      t_m = trunc(t_elapsed_sec - t_h*3600) / 60;
      t_s = fmod(t_elapsed_sec, 60.);
      if (t_day)
         sprintf(ostr, "%dd+%d:%02d:%06.3f", t_day, t_h, t_m, t_s);
      else
         sprintf(ostr, "%d:%02d:%06.3f", t_h, t_m, t_s);
   }
   return(ostr);
}

// usage() - command line instructions

void
usage(void)
{
   printf("%s %s\nUsage: pwalk [<primary_mode>] [<secondary_mode> ...] [<option> ...] <directory> [<directory> ...]\n",
      PWALK_VERSION, PWALK_PLATFORM);
   printf(" Where:\n");
   printf("   <directory> ...		// one or more directories to traverse (REQUIRED)\n");
   printf("      NOTE: Must be relative to any source or target relative root path(s) specifed.\n");
   printf("   <primary_mode> is at most ONE of:\n");
   printf("	-ls			// creates .ls outputs (similar to 'ls -l' outputs)\n");
   printf("	-lsd			// creates .ls outputs (like -ls), but only reports directory summaries\n");
   printf("	-lsc			// creates .ls outputs (compact)\n");
   printf("	-xml			// creates .xml outputs\n");
   printf("	-csv  (COMING SOON!)	// creates .csv outputs based on -pfile= [csv] parms\n");
   printf("	-cmp[=<keyword_list>]	// creates .cmp outputs based on stat(2) and binary compares\n");
#if PWALK_AUDIT // OneFS only
   printf("	-audit			// creates .audit files based on OneFS SmartLock status\n");
#endif // PWALK_AUDIT
   printf("	-fix_times		// creates .fix outputs (CAUTION: changes timestamps unless -dryrun!)\n");
   printf("	-rm			// creates .sh outputs (CAUTION: deletes files unless -dryrun!)\n");
   printf("	-trash  (COMING SOON!)	// creates .sh outputs (CAUTION: moves files unless -dryrun!)\n");
   printf("	NOTE: When no <primary_mode> is specified, pwalk creates .out outputs.\n");
   printf("   <secondary_mode> is zero or more of:\n");
   printf("	+denist			// also ... read first 128 bytes of every file encountered\n");
   printf("	+tally[=<tag>]		// also ... output file/space counts in pwalk_tally.csv file [DEVELOPMENTAL!]\n");
#if defined(__ONEFS__)
   printf("	+rm_acls		// DEVELOPMENTAL: also ... remove non-inherited ACEs in ACLs\n");
#endif
#if PWALK_ACLS // ACL-related commandline options ...
   printf("	+wacls=<command>	// also ... write derived binary NFS4 ACLs to <command>\n");
   printf("	+xacls=[bin|nfs|chex]	// also ... create .acl4bin, .acl4nfs, .acl4chex outputs\n");
#endif // PWALK_ACLS
   printf("   <option> values are:\n");
   printf("	-dop=<n>		// specifies the Degree Of Parallelism (max number of workers)\n");
   printf("	-pfile=<pfile>		// specify parameters for [source|target|output|select|csv]\n");
   printf("	-output=<output_dir>	// output directory; location for output directory (default is CWD)\n");
   printf("	-source=<source_dir>	// source directory; must be absolute path (default is CWD)\n");
   printf("	-target=<target_dir>	// target directory; optional w/ -fix_times, required w/ -cmp!\n");
   printf("	-bs=512			// interpret st_block_size units as 512 bytes rather than 1024\n");
   printf("	-redact			// output hex inode #'s instead of names\n");
   printf("	-select[=<keyword>]	// DEVELOPMENTAL: apply selected() logic\n");
   printf("	-since=<file>		// DEVELOPMENTAL: -select files having mtime or ctime > mtime(<file>)\n");
   printf("	-gz			// gzip primary output files\n");
   printf("	-dryrun			// suppress making any changes (with -fix_times & -rm)\n");
   printf("	-pmode			// suppress showing formatted mode bits (with -ls and -xml)\n");
   printf("	+acls			// show ACL info in some outputs, eg: '+' with -ls\n");
   printf("	+crc			// show CRC for each file (READS ALL FILES!)\n");
   printf("	+md5  (COMING SOON!)	// show MD5 for each file (READS ALL FILES!)\n");
   printf("	+tstat			// show hi-res timing statistics in some outputs\n");
   printf("	+.snapshot		// include .snapshot[s] directories (OFF by default)\n");
   printf("	+span			// include directories that span filesystems (OFF by default)\n");
   printf("	-v			// verbose; verbosity increased by each 'v'\n");
   printf("	-d			// debug; verbosity increased by each 'd'\n");
   exit(-1);
}

// @@@ SECTION: Worker management helpers @@@

// poke_manager() - Wakeup manager loop.

void
poke_manager(char *tag)
{
   if (PWdebug) fprintf(stderr, "= poke_manager: %s\n", tag);
   assert(pthread_cond_signal(&MANAGER_cond) == 0);
}

// worker_status() - Return read-consistent worker and FIFO accounting ...

// NOTE: Once worker threads are running, the number IDLE plus the number BUSY will
// sum to N_WORKERS -- but until they are running, they will sum to something less,
// because some threads will still have the status of being EMBRYONIC.

void
worker_status(unsigned *nw_idle, unsigned *nw_busy, count_64 *fifo_depth)
{
   int w_id;
   unsigned idle = 0, busy = 0;
   count_64 depth;

   MP_LOCK("MP lock in worker_status()");				// +++ MP lock +++
   for (w_id=0; w_id < N_WORKERS; w_id++) {
      if (WDAT.status == IDLE) idle++;
      if (WDAT.status == BUSY) busy++;
   }
   assert(busy == Workers_BUSY);	// sanity check
   depth = FIFO_DEPTH;
   MP_UNLOCK;								// --- MP lock ---

   if (nw_idle) *nw_idle = idle;
   if (nw_busy) *nw_busy = busy;
   if (fifo_depth) *fifo_depth = depth;
}

// LogMsg() - write to main output log stream (Plog); serialized by mutex, with a timestamp
// being generated anytime more than a second has passed since the last output, with optional
// force-flush of the log stream.
//
// Generate a progress report if the PROGRESS_TIME_INTERVAL has elapsed since the last 
// progress report.
//
// NOTE: Use LogMsg(NULL, 0); to just poll for a progress report.

void
LogMsg(char *msg, int force_flush)
{
   static time_t last_time = 0, progress_time = 0;
   time_t time_now;
   int show_timestamp = FALSE, show_progress = FALSE;
   char timestamp[32];		// ctime() only needs 26 bytes
   char ebuf[64];		// for elapsed time
   count_64 fifo_depth;		// for progress report
   unsigned nw_busy;

   assert (Plog != 0);		// Fail fast if Plog is not initialized!
   time_now = time(NULL);	// Determine current time ...

   pthread_mutex_lock(&LOGMSG_mutex);				// +++ LOGMSG lock +++

   // Shall we emit a progress line?
   if (progress_time == 0) {
      progress_time = time_now;
   } else if ((time_now - progress_time) >= PROGRESS_TIME_INTERVAL) {
      show_progress = TRUE;
      progress_time = time_now;
   }

   // Shall we emit a timestamp?
   if ((msg != NULL || show_progress) && (time_now > last_time)) {
      last_time = time_now;
      show_timestamp = TRUE;
   }

   // Output: [timestamp] ...
   if (show_timestamp) {
      ctime_r(&time_now, timestamp);
      fputs(timestamp, Plog);
   }

   // Output: [progress] ...
   if (show_progress) {
      worker_status(NULL, &nw_busy, &fifo_depth);
      fprintf(Plog, "PROGRESS: ELAPSED %s, %u workers BUSY, FIFO depth=%llu\n",
         format_ns_delta_t(ebuf, T_START_hires, gethrtime()), nw_busy, fifo_depth);
   }

   // Output: [msg] ...
   if (msg) fputs(msg, Plog);

   pthread_mutex_unlock(&LOGMSG_mutex);				// --- LOGMSG lock ---

   // Output: [flush] ... optional force flush ...
   if (force_flush) fflush(Plog);
}

// close_all_outputs() - Shutdown Python and +wacls pipes, and close +xacls= files ...

void
close_all_outputs(void)
{
   char pw_acls_emsg[128] = "";
   int pw_acls_errno = 0;
   int w_id, rc;

   // Output trailer[s] ...
   if (Cmd_XML)
      for (w_id=0; w_id<N_WORKERS; w_id++)
         fprintf(WLOG, "\n</xml-listing>\n");

   // Close per-worker outputs ...
   for (w_id=0; w_id<N_WORKERS; w_id++) {
      // Close per-worker primary output WLOG file (iff open) ...
      if (WLOG) {
         if (Opt_GZ) {			// Close log stream ...
#if defined(__OSX__)			// OSX pclose() hangs for unwritten streams!
            fflush(WLOG);		// pwalk exit will tidy up the gzips
            fclose(WLOG);
#else
            if ((rc = pclose(WDAT.wlog)))
               fprintf(stderr, "pclose(WLOG) w_id=%d rc=%d\n", w_id, rc);
#endif
         } else {
            fclose(WLOG);
         }
      }

      // Close per-worker error output WERR file (iff open) ...
      // NOTE: Can't use 'WERR' macro here!  It would try to create the file!
      if (WDAT.werr)
         fclose(WDAT.werr);

#if PWALK_AUDIT // OneFS only
      // Close active per-worker Python symbiont ...
      if (WDAT.PYTHON_PIPE) {
         fprintf(WDAT.PYTHON_PIPE, "-1\n");	// Signal script to exit()
         pclose(WDAT.PYTHON_PIPE);
      }
#endif // PWALK_AUDIT

#if PWALK_ACLS // ACL-related file & pipe closing (up to five) ...
      if (WDAT.WACLS_PIPE) {
         pw_acl4_fwrite_binary(NULL, NULL, &(WDAT.WACLS_PIPE), 'p', pw_acls_emsg, &pw_acls_errno);
      }
      if (WDAT.XACLS_BIN_FILE) {
         pw_acl4_fwrite_binary(NULL, NULL, &(WDAT.XACLS_BIN_FILE), 'o', pw_acls_emsg, &pw_acls_errno);
      }
      if (WDAT.XACLS_CHEX_FILE) {
         fclose(WDAT.XACLS_CHEX_FILE);
      }
      if (WDAT.XACLS_NFS_FILE) {
         fclose(WDAT.XACLS_NFS_FILE);
      }
      if (WDAT.XACLS_ONEFS_FILE) {
         fclose(WDAT.XACLS_ONEFS_FILE);
      }
#endif // PWALK_ACLS
   }
}

// abend() - Rude, abrupt exit.

// THIS ws not as useful as I had hoped ...
//	   void* callstack[512];
//	#if defined(__OSX__)
//	   backtrace_symbols_fd(callstack, 512, fileno(stderr));
//	#endif
// OSX: ulimit -c unlimited // dumps to /core

void
abend(char *msg)
{

   fprintf(stderr, "%d: FATAL: %s\n", getpid(), msg);
   LogMsg(msg, 1);
   //perror("");
   //close_all_outputs();
   kill(getpid(), SIGQUIT);	// dump core
   assert(0);
}

// yield_cpu() - Wrapper around platform-dependent CPU yield.

void
yield_cpu(void)
{
#ifdef SOLARIS
   yield();	
#else
   sched_yield();
#endif
}

// format_mode_bits() - translate passed mode into 'rwx' format in passed buffer

void
format_mode_bits(char *str, mode_t mode)
{
   str[0] = '\0';			// default NUL string
   if (!Opt_MODE) return;

   switch (mode & S_IFMT) {
   case S_IFIFO:  str[0] = 'p'; break;
   case S_IFCHR:  str[0] = 'c'; break;
   case S_IFDIR:  str[0] = 'd'; break;
   case S_IFBLK:  str[0] = 'b'; break;
   case S_IFREG:  str[0] = '-'; break;
   case S_IFLNK:  str[0] = 'l'; break;
   case S_IFSOCK: str[0] = 's'; break;
#ifdef S_IFDOOR
   case S_IFDOOR: str[0] = 'D'; break;
#endif
   default:       str[0] = '?';
   }

   str[1] = (mode & S_IRUSR) ? 'r' : '-';
   str[2] = (mode & S_IWUSR) ? 'w' : '-';
   str[3] = (mode & S_IXUSR) ? 'x' : '-';
   if (mode & S_ISUID) str[3] = (str[3] == '-') ? 'S' : 's';

   str[4] = (mode & S_IRGRP) ? 'r' : '-';
   str[5] = (mode & S_IWGRP) ? 'w' : '-';
   str[6] = (mode & S_IXGRP) ? 'x' : '-';
   if (mode & S_ISGID) str[6] = (str[6] == '-') ? 'S' : 's';

   str[7] = (mode & S_IROTH) ? 'r' : '-';
   str[8] = (mode & S_IWOTH) ? 'w' : '-';
   str[9] = (mode & S_IXOTH) ? 'x' : '-';
   if (mode & S_ISVTX) str[9] = (str[9] == '-') ? 'T' : 't';

   str[10] = '\0';
}

// get_owner_group() - Return names for owner & group from passed stat buf.
// Returned owner and group strings must be non-NULL and will at least be
// set to empty string values.
//
// klooge: Not much error-checking here
// klooge: Would be nice to cache previous values, per-worker, to avoid
//	iterated lookups of same values. For now, we do 'root' translation
//	explicitly as a peephole optimization.
//
// NOTE: Must be MT-safe!
// NOTE: Call unconditionally. Conditions are embedded here.

void
get_owner_group(struct stat *sb, char *owner, char *group, char *owner_sid, char *group_sid)
{
   int rc;
   char buf64k[64*1024];
   struct passwd pwd, *pwd_p;
   struct group grp, *grp_p;;

   owner[0] = group[0] = owner_sid[0] = group_sid[0] = '\0';

   if (PWget_MASK & PWget_OWNER) {
      if (sb->st_uid != 0) {
         errno = 0;
         rc = getpwuid_r(sb->st_uid, &pwd, buf64k, sizeof(buf64k), &pwd_p);
         strcpy(owner, pwd_p ? pwd.pw_name : "");
      } else {
         strcpy(owner, "root");
      }
   }

   if (PWget_MASK & PWget_GROUP) {
      if (sb->st_gid != 0) {
         errno = 0;
         rc = getgrgid_r(sb->st_gid, &grp, buf64k, sizeof(buf64k), &grp_p);
         strcpy(group, grp_p ? grp.gr_name : "");
      } else {
         strcpy(group, "root");
      }
   }
}

void
pwalk_format_time_t(const time_t *date_p, char *output, const int output_size, const char *format)
{
   struct tm tmp_tm;

   if (*date_p == 0) {
      strcpy(output, "0");
   } else if (format) {
      localtime_r(date_p, &tmp_tm);
      strftime(output, output_size - 1, format, &tmp_tm);
   } else {
      sprintf(output, "%ld", *date_p);
   }
}

// @@@ SECTION: Worker files open & close @@@

// fix_owner() - In case we are running setuid or setgid, change ownership of output
// streams to that of the program invoker ... so they can, y'know, delete them.

void
fix_owner(FILE *file)
{

   if (file == NULL) return;
   if ((USER.uid == USER.euid) && (USER.gid == USER.egid)) return;
   fchown(fileno(file), USER.uid, USER.gid);
}

// worker_aux_create() - creates per-worker auxillary output files.
// Passed-in ftype is filename suffix, eg: ".bin"

void
worker_aux_create(int w_id, FILE **pFILE, char *ftype)
{
   char ofile[MAX_PATHLEN+64];
   char emsg[128];

   sprintf(ofile, "%s%cworker-%03d.%s", OUTPUT_DIR, PATHSEPCHR, w_id, ftype);
   *pFILE = fopen(ofile, "wx");					// O_EXCL create
   if (*pFILE == NULL) {
      sprintf(emsg, "Cannot create worker %d's \"%s\" output file!\n", w_id, ftype);
      abend(emsg);
   }
   fix_owner(*pFILE);
   // Give output stream a decent buffer size ...
   setvbuf(*pFILE, NULL, _IOFBF, WORKER_OBUF_SIZE);		// Fully-buffered
}

// worker_err_create() - create worker-specific error file ... or DIE!
// NOTE: .err files are line-buffered, like stderr, so writes are flushed line-by-line.

FILE *
worker_err_create(int w_id)
{
   char strbuf[MAX_PATHLEN+64];

   sprintf(strbuf, "%s%cworker-%03d.err", OUTPUT_DIR, PATHSEPCHR, w_id);
   WDAT.werr = fopen(strbuf, "wx");			// O_EXCL create
   if (WDAT.werr == NULL)
      abend("Cannot create worker's .err file!");
   fix_owner(WDAT.werr);
   setvbuf(WDAT.werr, NULL, _IOLBF, 0);			// Line-buffered
   sprintf(strbuf, "@ Worker %d created %s%cworker-%03d.err\n", w_id, OUTPUT_DIR, PATHSEPCHR, w_id);
   LogMsg(strbuf, 1);

   return(WDAT.werr);
}

// worker_log_create() - creates per-worker <primary_mode> output file.

// Create a buffered output stream WDAT.wlog, which will be referred to by the macro
// WLOG in most contexts.
// NOTE: ulimits in the environment need to allow a few more than MAX_WORKERS open files.

void
worker_log_create(int w_id)
{
   char ofile[MAX_PATHLEN+64];
   char *ftype;

   // Create ${OUTPUT_DIR}/worker%03d.{ls,xml,cmp,audit,fix,rm,csv}[.gz] ...
   // Output type is determined by <primary_mode>, or '.out' otherwise
   if (Cmd_LS | Cmd_LSD | Cmd_LSC) ftype = "ls";
   else if (Cmd_XML) ftype = "xml";
   else if (Cmd_CMP) ftype = "cmp";
   else if (Cmd_AUDIT) ftype = "audit";
   else if (Cmd_FIXTIMES) ftype = "fix";
   else if (Cmd_RM) ftype = "rm";
   else if (Cmd_CSV) ftype = "csv";
   else return;			// Nothing to do!

   if (Opt_GZ) {		// WARNING: gzip-piped output hangs on OSX!
      sprintf(ofile, "gzip > %s%cworker-%03d.%s.gz", OUTPUT_DIR, PATHSEPCHR, w_id, ftype);
      WLOG = popen(ofile, "w");
   } else {
      sprintf(ofile, "%s%cworker-%03d.%s", OUTPUT_DIR, PATHSEPCHR, w_id, ftype);
      WLOG = fopen(ofile, "wx");				// O_EXCL create
   }
   if (WLOG == NULL)
      abend("Cannot create worker's output file!");
   fix_owner(WLOG);

   // Give each output stream a decent buffer size ...
   setvbuf(WLOG, NULL, _IOFBF, WORKER_OBUF_SIZE);		// Fully-buffered

   // Output headings ...
   if (Cmd_XML) {
      fprintf(WLOG, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\" ?>\n\n");
      fprintf(WLOG, "<!DOCTYPE xml-listing [\n");
      fprintf(WLOG, "	<!ELEMENT directory (path,(file,error,warning)*,summary)>\n");
      fprintf(WLOG, "	<!ELEMENT path (#PCDATA)>\n");
      fprintf(WLOG, "	<!ELEMENT file (#PCDATA)>\n");
      fprintf(WLOG, "	<!ELEMENT error (#PCDATA)>\n");
      fprintf(WLOG, "	<!ELEMENT warning (#PCDATA)>\n");
      fprintf(WLOG, "	<!ELEMENT summary (#PCDATA)>\n");
      fprintf(WLOG, "]>\n\n");
      fprintf(WLOG, "<xml-listing>\n\n");
   }
}

// @@@ SECTION: Initializations @@@

// init_main_mutexes() - 1st initialization.

void
init_main_mutexes(void)
{
   int i, rc, w_id;
   pthread_mutexattr_t mattr;

   // PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_RECURSIVE, PTHREAD_MUTEX_ERRORCHECK, PTHREAD_MUTEX_DEFAULT

   // Mutexes have attribute of returning -1 rather than deadlockiing if a thread does extra lock tries ...
   assert(pthread_mutexattr_init(&mattr) == 0);
   assert(pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK) == 0);
//   assert(pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED) == 0);
#if defined(__OSX__)
   assert(pthread_mutexattr_setprotocol(&mattr, PTHREAD_PRIO_INHERIT) == 0);	// === OSX
#endif

   if (PWdebug) fprintf(stderr, "sizeof(pthread_mutex_t) = %lu\n", sizeof(pthread_mutex_t));
   if (PWdebug) fprintf(stderr, "sizeof(pthread_cond_t) = %lu\n", sizeof(pthread_cond_t));

   // ------------------------------------------------------------------------

   // MP mutex for MP-coherent global data access ...
   if (pthread_mutex_init(&MP_mutex, &mattr)) abend("Can't init MP mutex!");

   // LOGMSG mutex for serializing logfile messages ...
   if (pthread_mutex_init(&LOGMSG_mutex, &mattr)) abend("Can't init LOGMSG mutex!");

   // MANAGER CV for keeping workers BUSY ...
   if (pthread_cond_init(&MANAGER_cond, NULL)) abend("Can't init MANAGER cv!");
   if (pthread_mutex_init(&MANAGER_mutex, &mattr)) abend("Can't init MANAGER cv mutex!");

   // Initialize WORKERs' condition variables and associated mutexes ...
   for (w_id=0; w_id < N_WORKERS; w_id++) {
      assert(pthread_mutex_init(&(WORKER_mutex[w_id]), &mattr) == 0);
      assert(pthread_cond_init(&(WORKER_cond[w_id]), NULL) == 0);
   }

   // Our main thread holds the MANAGER_mutex at all times past here except during our condition
   // wait in manager_workers().  We must hold this lock before any worker thread tries to set
   // the associated MANAGER_cv.
   assert(pthread_mutex_lock(&MANAGER_mutex) == 0);	// +++ MANAGER cv lock +++

   // Cleanup ...
   pthread_mutexattr_destroy(&mattr);
}

// init_main_outputs() - 2nd initialization.

// From the main control thread, create the directory to contain the worker outputs.

void
init_main_outputs(void)
{
   char ofile[2048];
   int rc, try;
   time_t clock;
   struct tm tm_now;
   char msg[256];

   // Create ${OUTPUT_DIR} output directory based on current time ...
   // Retry logic here is to cope with multiple pwalk processes being started at the same time
   // and colliding on their output directory name which is unique with one-second granularity.
   for (try=0; try < MAX_MKDIR_RETRIES; try++) {
      time(&clock);
      localtime_r(&clock, &tm_now);
      sprintf(OUTPUT_DIR, "%s%c%s-%04d-%02d-%02d_%02d_%02d_%02d", OUTPUT_ARG, PATHSEPCHR, PROGNAME,
         tm_now.tm_year+1900, tm_now.tm_mon+1, tm_now.tm_mday, tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec);
      rc = mkdir(OUTPUT_DIR, 0777);
      if (rc == 0) break;			// Success!
      if (errno != EEXIST)			// Only retry on EEXIST errors ...
         abend("Cannot create output directory!");
      if (try == (MAX_MKDIR_RETRIES-1))		// ... but do not retry forever.
         abend("Cannot create output directory after MAX_MKDIR_RETRIES attempts!");
      sleep(1);					// 1 second wait between retries
   }
   assert (rc == 0);
   // fix_owner() equivalent for output directory ...
   lchown(OUTPUT_DIR, USER.uid, USER.gid);

   // Create ${OUTPUT_DIR}/${PROGNAME}.log as our primary (shared, buffered) output log ...
   sprintf(ofile, "%s%c%s.log", OUTPUT_DIR, PATHSEPCHR, PROGNAME);
   fclose(Plog);
   Plog = fopen(ofile, "w");
   if (Plog == NULL) abend("Cannot open Plog!");
   fix_owner(Plog);

   // Fully buffer the shared log (though LogMsg will flush it as needed while holding a lock) ...
   setvbuf(Plog, NULL, _IOFBF, 8192);

   // Start being chatty (we should use LogMsg() henceforth) ...
   sprintf(msg, "NOTICE: +++ %s Begins +++\n", PWALK_VERSION);
   LogMsg(msg, 1);

   // Create ${OUTPUT_DIR}/${PROGNAME}.fifo as file-based FIFO, with distinct push and pop streams ...
   sprintf(ofile, "%s%c%s.fifo", OUTPUT_DIR, PATHSEPCHR, PROGNAME);
   Fpush = fopen(ofile, "w");
   if (Fpush == NULL) abend("Cannot create Fpush!");
   fix_owner(Fpush);

   // Make our FIFO writes line-buffered ...
   setvbuf(Fpush, NULL, _IOLBF, 2048);
   Fpop = fopen(ofile, "r");
   if (Fpop == NULL) abend("Cannot open Fpop!");
}

// init_worker_pool() - 3rd initialization; all worker-pool and WorkerData inits here ...

// NOTE: Even though variable accesses are uncontended here, they are wrapped by their
// respective mutexes in case that helps flush them to globally-coherent memory.
// NOTE: Only outputs here are via abend(), because Plog may not yet be initialized.

void
init_worker_pool(void)
{
   int w_id;
   unsigned nw_idle, nw_busy;

   pthread_attr_t pthread_attr;
   size_t stacksize;

   // Per-thread stacksize setting ...
   // ... foundational to future worker stack depth checks ...
   // assert(pthread_attr_getstacksize(&pthread_attr, &stacksize) == 0);
   // fprintf(stderr, "+ stacksize=%lu\n", stacksize);
   assert(pthread_attr_init(&pthread_attr) == 0);
   stacksize = 800*1024;
   assert(pthread_attr_setstacksize(&pthread_attr, stacksize) == 0);

   // Initialize each worker's thread-specific data and start their pThreads ...
   bzero(&WorkerData, sizeof(WorkerData));				// Start with all zeroes

   for (w_id=0; w_id<N_WORKERS; w_id++) {
      WDAT.w_id = w_id;
      WDAT.werr = NULL;
      WDAT.status = EMBRYONIC;
      WDAT.PYTHON_PIPE = NULL;						// Explicit but redundant ...
      WDAT.WACLS_PIPE = NULL;
      WDAT.XACLS_BIN_FILE = NULL;
      WDAT.XACLS_CHEX_FILE = NULL;
      WDAT.XACLS_NFS_FILE = NULL;
      WDAT.XACLS_ONEFS_FILE = NULL;
      WDAT.DirPath = malloc(MAX_PATHLEN+2);				// Pathname buffer
      // On Solaris, struct dirent does not include full d_name[] space ...
#if defined(SOLARIS)
      WDAT.Dirent = malloc(sizeof(struct dirent) + MAX_NAMELEN);	// Directory buffer
#else
      WDAT.Dirent = malloc(sizeof(struct dirent));			// Directory buffer
#endif
      // Worker's statistics ...
      WS[w_id] = calloc(1, sizeof(PWALK_STATS_T));			// Worker statistics

      // Start the worker's pThread ...
      assert(pthread_create(&(WORKER_pthread[w_id]), &pthread_attr, worker_thread, &(WDAT.w_id)) == 0);
      yield_cpu();		// Give new thread a running start
   }
   LogMsg("@ All workers STARTED\n", 1);

   // Wait for all workers to get out of their initial EMBRYONIC status ...
   while (1) {
      worker_status(&nw_idle, &nw_busy, NULL);			// +/- MP lock +/-
      if ((nw_idle + nw_busy) == N_WORKERS) break;		// All spun-up ...
      yield_cpu();						// give things more chance to change
   }
   LogMsg("@ All workers READY\n", 1);
}

// @@@ SECTION: Misc helper functions @@@

// str_normalize() - Remove traiiing whitespace in-situ in passed string, and return pointer
// to first non-whitespace character or NUL byte if resulting string is empty.

char *
str_normalize(char *line, char **next)
{
   char *p, *result;
   int len;

   len = strlen(line);
   *next = line + len + 1;
   for (p=line; *p; p++) if (*p && isgraph(*p)) break;				// trim front
   result = p;
   for (p=line+len; p>result; ) if (isgraph(*p)) break; else *p-- = '\0';	// trim end
   return result;
}

// str_ends_with() - helper function.

int
str_ends_with(char *str, char ch)
{
   int len;
   char *plast;

   if (str == NULL) return(0);
   if (str[0] == '\0') return(0);
   plast = str + strlen(str) - 1;
   if (*plast == ch) return(1);
   return(0);
}

// str_dump() - formats passed string into buffer with non-printables escaped in octal ...
char *
str_dump(char *str, char *dump)
{
   char *ps = str, *pd = dump;

   while (*ps) {
      if (*ps == '\n' || *ps < ' ' || *ps & 0200) {
         sprintf(pd, "\\%04o", *ps++); pd += 5;
      } else {
         *pd++ = *ps++;
      }
   }
   return (dump);
}

// skip_this_directory() - TRUE iff passed directory path should be skipped (ignored).

// klooge: IMPLEMENT [include_dir] and [exclude_dir] sections in parameter file to override or augment.
// NOTE: ONLY to be called from fifo_push(), so ONLY directory paths are passed-in!

int
skip_this_directory(char *dirpath, struct stat *sb, int w_id)
{
   char *fname_p;
   char *skip = NULL;

   // @@@ Name-based skips ... by default, skip these directories ...
   //	.snapshot[s] - unless +snapshot was specified
   //	.isi-compliance - OneFS SmartLock Compliance-mode -audit mode.
   //	.ifsvar - OneFS internal file space

   // Isolate filename ...
   fname_p = rindex(dirpath, PATHSEPCHR);
   if (fname_p == NULL) fname_p = dirpath;
   else fname_p += 1;

   // Directories we skip by name all begin with a '.' ...
   if (fname_p[0] == '.') {
      if (strcmp(dirpath, ".ifsvar") == 0)
         skip = "Skipping .ifsvar";
      else if (Cmd_AUDIT && strcmp(fname_p, ".isi-compliance") == 0)
         skip = "Skipping .isi-compliance";
      else if (Opt_SKIPSNAPS) {
         if (strcmp(fname_p, ".snapshot") == 0) skip = "Skipping .snapshot";
         if (strcmp(fname_p, ".snapshots") == 0) skip = "Skipping .snapshots";
      }
      if (skip) goto out;
   }

   // @@@ Quality-based skips ...

   // NOTE: +span enforcement is not here because it requires knowledge of the
   // parent directory which is not visible in this context.

   // FUTURE: Under OSX, some /dev/fd/<n> files will appear to be directories,
   // but they cannot be opened by opendir() and will generate an error.

out:
   if (skip) {
      fprintf(WERR, "NOTICE: %s @ \"%s\"\n", skip, dirpath);
      return TRUE;
   } else {
      return FALSE;
   }
}

// catpath3() - Create concatenation of 3 passed args.

void
catpath3(char *fullpath, char *path1, char *path2, char *path3)
{
   int len1, len2, len3;
   char *p, *s;

   len1 = path1 ? strlen(path1) : 0;
   len2 = path2 ? strlen(path2) : 0;
   len3 = path3 ? strlen(path3) : 0;
   assert ((len1 + len2 + len3 + 1) < MAX_PATHLEN);

   p = fullpath;
   *p = '\0';
   if (len1) {
      strcpy(p, path1);
      p += len1;
      if (*(p-1) == PATHSEPCHR) *(--p) = '\0';			// No trailing '/'
   }
   if (len2) {
      if (p > fullpath) *(p++) = PATHSEPCHR;			// concat ...
      s = path2; if (s[0] == '.' && s[1] == PATHSEPCHR) s += 2;	// skip '^./' ...
      strcpy(p, s); p += strlen(s);
      if (*(p-1) == PATHSEPCHR) *(--p) = '\0';			// No trailing '/'
   }
   if (len3) {
      if (p > fullpath) *(p++) = PATHSEPCHR;			// concat ...
      s = path3; if (s[0] == '.' && s[1] == PATHSEPCHR) s += 2;	// skip '^./' ...
      strcpy(p, s); p += strlen(s);
      if (*(p-1) == PATHSEPCHR) *(--p) = '\0';			// No trailing '/'
   }
   if (PWdebug > 2) fprintf(stderr, "@ %s\n", fullpath);
}

// @@@ SECTION: Multi-path Support @@@

// setup_root_path() - Open passed-in directory and capture its directory fd (dfd) and inode values.
// Old logic was ...
//         if (stat(line, &sb) != 0)			// Get st_mode from stat()
//            { errstr = "Cannot stat (%s)!\n"; goto error; }
//         if (!S_ISDIR(sb.st_mode))			// Must be a dir
//            { errstr = "%s is not a directory!\n"; goto error; }
//         if (access(line, R_OK|X_OK) != 0)		// Must be readsble+traversable
//            { errstr = "%s must be an existing traversible directory!\n"; goto error; }
//
// Root paths are required to be absolute, so we call realpath() before the opendir() to assure
// we are using an unambiguous absolute path.

void
setup_root_path(char **dirpath_p, int *dfd_out, ino_t *inode_out)
{
   DIR *dir;						// NOTE: These paths stay open forever!
   int dfd;
   struct stat st;
   char *dirpath, *dirpath_real;

   // Resolve passed-in directory name, and overwrite passed-in value if its realpath() is different  ...
   dirpath = *dirpath_p;
   dirpath_real = realpath(dirpath, NULL);		// NOTE: called only once, and never free()'d
   assert (dirpath_real != NULL);
   if (strcmp(dirpath, dirpath_real)) {
      // fprintf(Plog, "NOTICE: \"%s\" -> \"%s\"\n", dirpath, dirpath_real);
      dirpath = dirpath_real;
      *dirpath_p = dirpath;
   }

   // Must be a directory ...
   dir = opendir(dirpath);
   if (dir == NULL) {
      fprintf(Plog, "FATAL: Cannot opendir(\"%s\") as a relative root!\n", dirpath);
      exit(-1);
   }

   // Directory fd's (dfd's) are subsequently used as the relative root paths for all openat()
   // and fstatat() multipath logic.
   // NOTE: For opendir(2) operations, since there is no opendirat() variant, those must all be
   // performed using ABSOLUTE pathnames.
#if SOLARIS
   dfd = dir->dd_fd;
#else
   dfd = dirfd(dir);
#endif
   assert (fstat(dfd, &st) == 0);
   if (dfd_out) *dfd_out = dfd;
   if (inode_out) *inode_out = st.st_ino;
   if (PWdebug) fprintf(Plog, "DEBUG: setup_root_path(\"%s\") inode=%lld\n", dirpath, st.st_ino);
}

// @@@ Parser for -pfile= contents @@@

#define RELOP_NULL 0
#define RELOP_EQ   1
#define RELOP_NE   2
#define RELOP_LT   3
#define RELOP_LE   4
#define RELOP_GT   5
#define RELOP_GE   6

static struct {
   char *str;
   int relop;
} RELOP_TABLE[] = {
   { "==", RELOP_EQ},
   { "!=", RELOP_NE},
   { "<>", RELOP_NE},
   { "<",  RELOP_LT},
   { "<=", RELOP_LE},
   { ">",  RELOP_GT},
   { ">=", RELOP_GE},
   { "",  RELOP_NULL},
   { NULL, RELOP_NULL}
};

static struct {
   char *str;
   count_64 multiplier;
} VALUE_SUFFIX[] = {
   { "", 1 },
   { "K", 1000 },                       // kilo
   { "M", 1000000 },                    // mega
   { "G", 1000000000 },                 // giga
   { "T", 1000000000000 },              // tera 
   { "P", 1000000000000000 },           // peta
   { "E", 1000000000000000000 },        // exa
   { "KI", 0x0000000000000400 },
   { "MI", 0x0000000000100000 },
   { "GI", 0x0000000040000000 },
   { "TI", 0x0000010000000000 },
   { "PI", 0x0004000000000000 },
   { "EI", 0x1000000000000000 },
   { NULL, 0 }
};

// parse_relop() - Return relational operator (RELOP_?? constants).
// Returns 0 on success, with *relop set.

int
parse_relop(char *str, int *relop)
{
   int i;

   assert (str);
   *relop = RELOP_NULL;
   for (i=0; RELOP_TABLE[i].str; i++) {
      if (strcmp(str, RELOP_TABLE[i].str) == 0) {
         *relop = RELOP_TABLE[i].relop;
         return(0);
      }
   }
   return(-1);
}

// parse_64u() - Extract 64-bit unsigned value from passed string. 
// Numbers may be octal, decimal, or hex and include suffixes which are case-insensitive.
// CAUTION: 'k' is 1000, 'ki' is 1024, etc!
// Returns 0 on success.
//
// TEST: 
// TEST: void
// TEST: test(char *str)
// TEST: {
// TEST:    count_64 value;
// TEST:    int rc;
// TEST: 
// TEST:    rc = parse_64u(str, &value);
// TEST:    printf("\"%s\" -> ", str);
// TEST:    if (rc == 0) printf("0x%016llx %llu\n", value, value);
// TEST:    else printf("rc=%d\n", rc);
// TEST: }
// TEST: 
// TEST: test("0");
// TEST: test("1k");
// TEST: test("1ki");
// TEST: test("0x40ki");
// TEST: test("0x400");
// TEST: test("010ki");
// TEST: test("4ki");
// TEST: test("64ki");
// TEST: test("64k");
// TEST: test("8.125ki");		// -3
// TEST: test("1mi");
// TEST: test("128ki");
// TEST: test("4ti");
// TEST: test("1pi");
// TEST: test("1ei");
// TEST: test("42kb");			// -3
// TEST: test("0xffffffffffffffff");	// Top bit cleared!
// TEST: test("0x7fffffffffffffff");
// TEST: test("0x1fffffffffffffff");


int
parse_64u(char *str, count_64 *val)
{
   char *p;
   int i, len, nb, rc;

   if (str == NULL) return(-1);
   len = strlen(str);
   rc = sscanf(str, "%lli%n", (unsigned long long *) val, &nb);
   if (rc != 1) return(rc);
   if (nb == len) return(0);	// Success w/ no suffix
   // What remains MUST be a VALUE_SUFFIX ...
   p = &str[nb];
   for (i=0; VALUE_SUFFIX[i].str; i++) {
      if (strcasecmp(p, VALUE_SUFFIX[i].str) == 0) {
         *val *= VALUE_SUFFIX[i].multiplier;
         return(0);		// Success w/ suffix
      }
   }
   return(-3);
}

// parse_pfile() - Parse -pfile= parameter file ...

void
parse_pfile(char *parfile)
{
   int fd, fsize, i, len, rc;
   char *p, *buf, *line, *next, *errstr = "";
   struct stat sb;
   int got_target = 0, got_source = 0, got_output = 0, got_select = 0, got_tally = 0;;
   int dfd;	// directory file descriptor
   enum { NONE, TARGET, SOURCE, SELECT, OUTPUT, TALLY } section = NONE;

   // Read -pfile=<file> and process entirely into memory ...
   assert ((fd = open(parfile, O_RDONLY)) >= 0);
   assert (fstat(fd, &sb) == 0);			// get st_size from stat()
   assert ((fsize = sb.st_size) <= 8191);		// arbitrary sanity check
   assert ((buf = calloc(1, fsize+1)));
   assert ((rc = read(fd, buf, fsize)) == fsize);
   close (fd);

   // Convert buffer to NUL-terminated strings ...
   for (p=buf; p<(buf+fsize); p++) if (*p == '\n') *p = '\0';

   // Process lines directly in-memory ...
   for (line=buf; line < (buf+fsize); line=next) {
      line = str_normalize(line, &next);
      if (line[0] == '\0' || strchr("#@*%", line[0])) {		// empty line or comment
         continue;
      } else if (line[0] == '[') {				// section?
         if (strcasecmp(line, "[source]") == 0) {
            if (got_source) { errstr = "Only one %s allowed!\n"; goto error; }
            got_source = 1; section = SOURCE;
         } else if (strcasecmp(line, "[target]") == 0) {
            if (got_target) { errstr = "Only one %s allowed!\n"; goto error; }
            got_target = 1; section = TARGET;
         } else if (strcasecmp(line, "[output]") == 0) {
            if (got_output) { errstr = "Only one %s allowed!\n"; goto error; }
            got_output = 1; section = OUTPUT;
         } else if (strcasecmp(line, "[select]") == 0) {
            if (got_select) { errstr = "Only one %s allowed!\n"; goto error; }
            got_select = 1; section = SELECT;
         } else if (strcasecmp(line, "[tally]") == 0) {
            if (got_tally) { errstr = "Only one %s allowed!\n"; goto error; }
            got_tally = 1; section = TALLY;
         } else {
            { errstr = "Invalid syntax: %s\n";  goto error; }
         }
         continue;
      } else {							// must be a parameter
         switch(section) {
         case NONE: {
            { errstr = "%s appears outside of a [section] context!\n"; goto error; }
            }
         case SOURCE: {
            assert (N_SOURCE_PATHS < MAXPATHS);
            SOURCE_PATHS[N_SOURCE_PATHS++] = line;
            break;
            }
         case TARGET: {
            assert (N_TARGET_PATHS < MAXPATHS);
            TARGET_PATHS[N_TARGET_PATHS++] = line;
            break;
            }
         case OUTPUT: {
            OUTPUT_ARG = line;
            break;
            }
         case SELECT: {						// -select enables *using* these criteria
            if (VERBOSE) fprintf(stderr, "NOTE: -select criteria present!\n");
            }
         case TALLY: {
            }
         }
      }
   }

   return;

error:
   fprintf(stderr, "ERROR: -pfile= : ");
   fprintf(stderr, errstr, line);
   exit(-1);
}


// @@@ SECTION: pwalk -fix_times support @@@

// NOTE: w_id is passed-in for WLOG macro, as this operates in an MT context ...
// If no target paths specified, return 0
// If target exists and has value mtime, return 1 and populate passed statbuf struct.

int
target_time(char *relpath, struct stat *pssb, int w_id)
{

   // Should only come here if target path[s] were specified.
   if (N_TARGET_PATHS < 1) return 0;

   if (fstatat(TARGET_DFD(w_id), relpath, pssb, AT_SYMLINK_NOFOLLOW)) return 0;
   if (pssb->st_mtime == 0) return 0;	// target time is zero

   return 1;					// valid target time exists
}

int
bad_timespec(struct timespec * tsp)
{
   // Bad timestamps are those which are outside the 32-bit epoch range of [0-0x7fffffff]
   // or those which have an invalid tv_nsec value.
   // NOTE: 64-bit timestamps are compared as SIGNED long int values.
   // NOTE: For timestamps corrupted by -1 values in OneFS
   // 	OSX NFS sees some of these bad values as 3373865674 (0xc9191aca).
   // 	In some contexts, st_birthtime will show as 1833029933770 (0x1aac0191aca),
   //	apparently after they have been mangled by SMB.
   // NOTE: As 64-bit signed values, these two cases are such that any real time will be
   // 	'less than' the corrupted timestamp.
   // NOTE: From OSX NFS, st_birthtime is INFERRED to be the same as st_ctime. NFSv3 has
   //	no way of conveying an actual birthtime.
   if ((tsp->tv_sec < 0) || (tsp->tv_sec > 0x7fffffff)) return 1;
   if ((tsp->tv_nsec < 0) || (tsp->tv_nsec > 999999999)) return 1;
   // if (timestamp == 3373865674) return 1;
   // if (timestamp == 1833029933770) return 1;
   // if (timestamp > 0xffffffff) return 1;
   return 0;
}

void
printf_stat(struct stat *sb)
{
   printf("     st_dev=%d\n", sb->st_dev);
   printf("     st_ino=%llu\n", sb->st_ino);
   printf("    st_mode=%07o\n", sb->st_mode);
   printf("   st_nlink=%d\n", sb->st_nlink);
   printf("     st_uid=%d\n", sb->st_uid);
   printf("     st_gid=%d\n", sb->st_gid);
   printf("    st_rdev=%d\n", sb->st_rdev);
   printf("    st_size=%lld\n", sb->st_size);
   printf(" st_blksize=%d\n", sb->st_blksize);
   printf("  st_blocks=%llu\n", sb->st_blocks);
#if !defined(__LINUX__)
   printf("   st_flags=%o\n", sb->st_flags);
#endif
}

// format_epoch_ts() - compactly express a full-precision timespec in a format that
// is acceptable to 'touch3' utility.  NON RE-ENTRANT!

char *
format_epoch_ts(struct timespec *tsp)
{
   static char buf[64];		// CAUTION: NOT re-entrant!!
   char mantissa[16], *p;	// Mantissa trimmed of trailing zeroes for compactness
				// ... and left off completely when zero
   int nsec;			// [0 .. 999999999] or 'corrected'

   sprintf(buf, "%ld", tsp->tv_sec);			// 64-bit signed value
   if (tsp->tv_nsec != 0) {				// SHOULD be in [0 .. 999999999] range
      nsec = tsp->tv_nsec < 0 ? 0 : tsp->tv_nsec;	// klooge: shows as "." with nothing after
      if (nsec > 999999999) nsec = 999999999;		// klooge: cope with bad values
      sprintf(mantissa, "%0.9f", nsec/1000000000.);
      for (p = mantissa + 9; *p == '0'; --p) *p = '\0';	// trim trailing zeroes
      strcat(buf, mantissa + 1);			// skip leading zero
   }
   return buf;
}

// pwalk_fix_times() - the guts of the -fix_times command-line option
// We come here for every node traversed, just after its lstat() has been obtained ...

void
pwalk_fix_times(char *filename, char *filepath, struct stat *ssbp, int w_id)
{
   struct timespec ts_ttime[3];	// touch times [atime=0, mtime=1, btime=2] for OneFS vtimes() call (sec+nsec)
   struct timeval tv_ttime[2];	// touch times [atime=0, mtime=1] for utimes() call (sec+usec)
   char touch_strategy[8];	// character-coded touch strategy [amcb\0]
   char mtime_strategy;
   char btime_strategy;
   char touch_t_str[32];	// mtime formatted for touch(1) (YYYYMMDDhhmm.ss)
   struct tm touch_t_tm;
   char atime_epoch_str[32];	// times formatted for touch3 utility (nsec)
   char mtime_epoch_str[32];
   char ctime_epoch_str[32];
   char btime_epoch_str[32];
   time_t time_now;		// for localtime() -now
   struct stat tfsb;		// target file stat buf
   int bad_time_mask;		// bitwise; atime.mtime.ctime.birthtime
   char bad_time_str[8];	// represent 'amcb' times's badness with 0 for OK, 1 for BAD
   int atime_OK, mtime_OK, ctime_OK, btime_OK;	// convenience booleans
   int vtimes_mask;		// for OneFS-private vtimes() calls
   char ftype;			// '[-bcdpls]' letter type shown by 'ls -l'
   int rc;

   // Check for bad times ....
   atime_OK = mtime_OK = ctime_OK = btime_OK = 1;	// assume all OK to start
   bad_time_mask = 0;
   strcpy(bad_time_str, "0000");			// "amcb" string of 0's and 1's
   if (bad_timespec(&(ssbp->st_atimespec))) { bad_time_mask |= 8; bad_time_str[0] = '1'; atime_OK = 0; }
   if (bad_timespec(&(ssbp->st_mtimespec))) { bad_time_mask |= 4; bad_time_str[1] = '1'; mtime_OK = 0; }
   if (bad_timespec(&(ssbp->st_ctimespec))) { bad_time_mask |= 2; bad_time_str[2] = '1'; ctime_OK = 0; }
   if (bad_timespec(&(ssbp->st_birthtimespec))) { bad_time_mask |= 1; bad_time_str[3] = '1'; btime_OK = 0; }
   if (bad_time_mask == 0) return;			// No trouble found!

   // Encode file type ...
   if (S_ISREG(ssbp->st_mode)) ftype = '-';
   else if (S_ISDIR(ssbp->st_mode)) ftype = 'd';
   else if (S_ISBLK(ssbp->st_mode)) ftype = 'b';
   else if (S_ISCHR(ssbp->st_mode)) ftype = 'c';
   else if (S_ISLNK(ssbp->st_mode)) ftype = 'l';
   else if (S_ISSOCK(ssbp->st_mode)) ftype = 's';
   else if (S_ISFIFO(ssbp->st_mode)) ftype = 'p';
   else ftype = '?';

   // mtime_strategy coding scheme ...
   //    Target cases ...
   //    's' - use target mtime, because source mtime is BAD
   //    'S' - use target mtime, because it's newer than source mtime (unlikely)
   //    'M' - use source mtime, because it's newer than target mtime (likely)
   //    Non-Target cases ...
   //    'm' - use source mtime, because it's OK
   //    'c' - use source ctime, because it's OK
   //    'n' - use 'now' time, because no other option was selected
   //    'R' - Revert good btime to earlier mtime
   //    'C' - Change good btime to earlier ctime
   // NOTE: for mtime_strategy of 'm' or 'M', touch_strategy[mtime] = '-' (ie: no change) ... however,
   // if utimes() is used to set atime, mtime value must also be set.

   // First, determine mtime_strategy ...
   mtime_strategy = '-';						// Initially undecided ...
   if (N_TARGET_PATHS && target_time(filepath, &tfsb, w_id)) {		// Nonzero target mtime exists ...
      if (!mtime_OK) mtime_strategy = 's';				// Use target mtime (source mtime BAD)
      else if (ssbp->st_mtimespec.tv_sec < tfsb.st_mtimespec.tv_sec) mtime_strategy = 'S';	// Use target mtime (> source mtime (unlikely))
      else mtime_strategy = 'M';					// Use source mtime (>= target mtime (likely))
   } else if (mtime_OK) {
      mtime_strategy = 'm';						// 1st choice: use OK source mtime.
   } else if (ctime_OK) {
      mtime_strategy = 'c';						// 2nd choice: use OK source ctime.
   } else {
      mtime_strategy = 'n';						// 3rd choice: use 'now' time as last resort.
   }

   // Put chosen mtime value in ts_time[1] ...
   switch (tolower(mtime_strategy)) {
   case 'c':	// Use source ctime ...
      ts_ttime[1].tv_sec = ssbp->st_ctimespec.tv_sec;
      ts_ttime[1].tv_nsec = ssbp->st_ctimespec.tv_nsec;
      break;
   case 's':	// Use target mtime ...
      ts_ttime[1].tv_sec = tfsb.st_mtimespec.tv_sec;
      ts_ttime[1].tv_nsec = tfsb.st_mtimespec.tv_nsec;
      break;
   case '-':	// Carry forward source mtime ...
   case 'm':
      ts_ttime[1].tv_sec = ssbp->st_mtimespec.tv_sec;
      ts_ttime[1].tv_nsec = ssbp->st_mtimespec.tv_nsec;
      break;
   case 'n':	// Use 'now' ...
      localtime(&time_now);
      ts_ttime[1].tv_sec = time_now;
      ts_ttime[1].tv_nsec = 0;
      break;
   default:
      assert("Logic Error" == NULL);
   }

   // Now figure out touch_strategy for all of [amcb]time values ...
   strcpy(touch_strategy, "----");

   // -----------------------------------------------------------------------------------------
   // For atime: If BAD, use the mtime per mtime_strategy.  If OK, use source atime in case
   // utimes() is called to set mtime.
   // WARNING: Over SMB or NFS, server may apply its own atime instead of passed value.
   // In other words if atime strategy shows 'no change' ('-') it may still be changed.
   // If atime is applied via vtimes() native to OneFS, it should match mtime precisely.
   if (atime_OK) {
      ts_ttime[0].tv_sec = ssbp->st_atimespec.tv_sec;
      ts_ttime[0].tv_nsec = ssbp->st_atimespec.tv_nsec;
   } else {
      ts_ttime[0].tv_sec = ts_ttime[1].tv_sec;
      ts_ttime[0].tv_nsec = ts_ttime[1].tv_nsec;
      touch_strategy[0] = mtime_strategy;
   }

   // -----------------------------------------------------------------------------------------
   // For mtime: If BAD, it will get the value we have just selected according to our
   // mtime_strategy, and that value is already set in ts_ttime[1].
   if (!mtime_OK) touch_strategy[1] = mtime_strategy;

   // -----------------------------------------------------------------------------------------
   // For ctime: It ALWAYS gets changed to 'now' (actual server/system time) no matter what
   // we do -- but if the source value was BAD, then we set 'n' for 'now' in the strategy string
   // to convey that fact.  There is no API means available for setting ctime explicitly to any
   // value of our choosing.
   if (!ctime_OK) touch_strategy[2] = 'n';

   // -----------------------------------------------------------------------------------------
   // For birthtime: If BAD, we will apply the EARLIER of our chosen mtime or a good source ctime.
   // If the source birthtime is OK but greater than our chosen mtime, we will apply our chosen mtime,
   // -- which is EXACTLY what utimes() is SUPPOSED to do.
   // WARNING: utimes() over NFS and SMB do NOT correct future btime values on OneFS.
   // WARNING: The OneFS-local utimes() call corrects a future btime, but does not require
   // another utimes() call to set the atime and mtime. HOWEVER, on OneFS, we may just use the
   // OneFS-private vtimes() call to explciitly set the btime.
   // WARNING: A OneFS birthtime can ONLY be explicitly set via the OneFS-private vtimes().
   btime_strategy = '-';
   if (!btime_OK) {		// Use the earlier of chosen mtime or the valid source ctime
      if (ctime_OK && (ssbp->st_ctimespec.tv_sec < ts_ttime[1].tv_sec))
         btime_strategy = 'C';			// 'Change' to ctime which predates chosen mtime ...
      else
         btime_strategy = mtime_strategy;	// Chosen mtime might be any of [mMsSnc] ...
   } else {
      if (ssbp->st_birthtimespec.tv_sec > ts_ttime[1].tv_sec)
         btime_strategy = 'R';			// 'Revert' to chosen mtime ...
   }

   // Prepare to apply the btime_strategy ...
   if (btime_strategy != '-') {
      touch_strategy[3] = btime_strategy;
      btime_OK = 0;		// It may be 'OK', but this triggers our adjustment logic later.
      switch (tolower(btime_strategy)) {
      case 'c':			// Use source ctime ...
         ts_ttime[2].tv_sec = ssbp->st_ctimespec.tv_sec;
         ts_ttime[2].tv_nsec = ssbp->st_ctimespec.tv_nsec;
         break;
      default:			// Use chosen mtime ...
         ts_ttime[2].tv_sec = ts_ttime[1].tv_sec;
         ts_ttime[2].tv_nsec = ts_ttime[1].tv_nsec;
         break;
      }
   }
   // -----------------------------------------------------------------------------------------

   // Primary -fix_times OUTPUT here ... comment(s) followed by action(s) ...

   // NOTE: This code assumes that OneFS does not need to call utimes(2) twice in the event
   // mtime < birthtime ... because (a) OneFS does not require two calls, and (b) as of 
   // when this was written, client utimes() calls of NFS or SMB were determined to have no
   // impact on birthtimes in the future.

   // COMMENT: show all existing timestamps with full precision ....
   strcpy(atime_epoch_str, format_epoch_ts(&(ssbp->st_atimespec)));
   strcpy(mtime_epoch_str, format_epoch_ts(&(ssbp->st_mtimespec)));
   strcpy(ctime_epoch_str, format_epoch_ts(&(ssbp->st_ctimespec)));
   strcpy(btime_epoch_str, format_epoch_ts(&(ssbp->st_birthtimespec)));
   fprintf(WLOG, "# %c%s %s \"%s\" a=%s m=%s c=%s b=%s%s\n",
      ftype, touch_strategy,
      bad_time_str,
      filename,
      atime_epoch_str,
      mtime_epoch_str,
      ctime_epoch_str,
      btime_epoch_str,
      (ssbp->st_birthtime != ssbp->st_ctime) ? " NOTE: B!=C" : ""
      );

   // COMMANDs: These emitted commands are for native execution on OneFS, assuming;
   // (1) user scripts the OneFS commands by selecting either 'touch' or 'touch3' commands, and
   // (2) user corrects the pathsnames in each command to reflect the actual OneFS absolute paths.

   // COMMAND #1: touch [-A [-][[hh]mm]SS] [-acfhm] [-r file] [-t [[CC]YY]MMDDhhmm[.SS]] file ...
   localtime_r((time_t *) &(ts_ttime[0].tv_sec), &touch_t_tm);
   strftime(touch_t_str, sizeof (touch_t_str) - 1, "%G%m%d%H%M.%S", &touch_t_tm);
   fprintf(WLOG, "touch -%s -t %s \"%s\"\n", atime_OK ? "mc" : "amc", touch_t_str, filepath);

   // COMMAND #2: touch3 <info> <atime> <mtime> <btime> <ifs_pathname> ...
   // NOTE: pwalk_create_target depends on these 'touch3' commands ...
   strcpy(atime_epoch_str, atime_OK ? "-" : format_epoch_ts(&ts_ttime[0]));
   strcpy(mtime_epoch_str, mtime_OK ? "-" : format_epoch_ts(&ts_ttime[1]));
   strcpy(btime_epoch_str, btime_OK ? "-" : format_epoch_ts(&ts_ttime[2]));
   fprintf(WLOG, "touch3 %c%s %s %s %s \"%s\"\n",
      ftype, touch_strategy,
      atime_epoch_str,
      mtime_epoch_str,
      btime_epoch_str,
      filepath);

   // ACTION: -fix_times ACTION here ...
   if (!PWdryrun) {
      if (USE_VTIMES) {
         vtimes_mask = 0;
         if (!atime_OK) vtimes_mask |= VT_ATIME;
         if (!mtime_OK) vtimes_mask |= VT_MTIME;
         if (!btime_OK) vtimes_mask |= VT_BTIME;
         rc = lvtimes(filepath, ts_ttime, vtimes_mask);
      } else {
         // Get timeval_t equivalents for [am]times in case we end up using utimes() ...
         // NOTE: *nix stat() returns timespec values (tv_sec, tv_nsec), while utimes() uses an array
         // of two timeval values (tv_sec, tv_usec) -- so appropriate conversions are made here.
         tv_ttime[0].tv_sec = ts_ttime[0].tv_sec;
         tv_ttime[0].tv_usec = ts_ttime[0].tv_nsec/1000;
         tv_ttime[1].tv_sec = ts_ttime[1].tv_sec;
         tv_ttime[2].tv_usec = ts_ttime[1].tv_nsec/1000;
         if (ftype != 'l') rc = utimes(filepath, tv_ttime);
         else		rc = lutimes(filepath, tv_ttime);
      }
      if (rc) fprintf(WLOG, "# FAILED!\n");
   }
}


// @@@ SECTION: pwalk -audit support @@@

// The bulk of the pwalk -audit logic is conditionally included inline here.

#if PWALK_AUDIT // OneFS only
#include "pwalk_audit.h"
#endif

// @@@ SECTION: pwalk -cmp support @@@

// KEYWORD   C  MASK VALUE
// -------------------------
// <always>  -  CMP_equal
// <always>  !  CMP_error
// <always>  E  CMP_notfound
// <always>  T  CMP_type
// mode      M  CMP_mode
// flags     F  CMP_flags
// owner     o  CMP_uid
// group     g  CMP_gid
// size      s  CMP_size
// space     S  CMP_blocks
// atime     a  CMP_atime
// mtime     m  CMP_mtime
// birthtime b  CMP_birthtime
// content   C  CMP_content

#define CMP_equal     0x00000000
#define CMP_error     0x00000001
#define CMP_notfound  0x00000002
#define CMP_type      0x00000004
#define CMP_mode      0x00000008
#define CMP_flags     0x00000010
#define CMP_uid       0x00000020
#define CMP_gid       0x00000040
#define CMP_size      0x00000080
#define CMP_blocks    0x00000100
#define CMP_atime     0x00000200
#define CMP_mtime     0x00000400
#define CMP_birthtime 0x00000800
#define CMP_content   0x00001000

static int cmp_Check = CMP_notfound | CMP_type;	// Always check existence and type
static struct {					// For -cmp= keyword parse into cmp_Check
   char *keyword;
   int code;
   unsigned maskval;
} cmp_Keywords[] = {
   { "",          '!', CMP_error     },
   { "",          'E', CMP_notfound  },
   { "",          'T', CMP_type      },
   { "mode",      'M', CMP_mode      },
#if HAVE_STRUCT_STAT_ST_FLAGS
   { "flags",     'F', CMP_flags     },
#endif
   { "owner",     'o', CMP_uid       },
   { "group",     'g', CMP_gid       },
   { "size",      's', CMP_size      },
   { "space",     'S', CMP_blocks    },
   { "atime",     'a', CMP_atime     },
   { "mtime",     'm', CMP_mtime     },
   { "birthtime", 'b', CMP_birthtime },
   { "content",   'C', CMP_content   },
   { NULL,        0,   0             }
};

// cmp_arg_parse() - Validate -cmp= keyword list into global cmp_Check bitmask.

void
cmp_arg_parse(char *argstr)
{
   int i, len;
   char words[256], msg[1024], *p, *p0;

   // Copy args into stack buffer and replace ',' with NUL...
   len = strlen(argstr);
   assert (len < sizeof(words));
   strcpy(words, argstr);
   for (i=0; i<len; i++) if (words[i] == ',') words[i] = 0;

   p = p0 = words;
   while ((p-p0) < len) {		// for each passwd kw
      for (i=0; ; i++) {		// for each value kw
         if (cmp_Keywords[i].keyword == NULL) {
            fprintf(Plog, "FATAL: Invalid -cmp= keyword: \"%s\"\n", p);
            exit(-1);
         } else if (strcmp(p, cmp_Keywords[i].keyword) == 0) {
            cmp_Check |= cmp_Keywords[i].maskval; break;
         }
      }
      p += strlen(p) + 1;
   }
}

// cmp_files() - Open SOURCE and TARGET versions of pathname to do READONLY compare.

int
cmp_files(int w_id, char *relpath)
{
   int fds = -1, fdt = -1;
   int rc = -1;		// Default is "files not equal"
   int src_bytes, tgt_bytes;
   char *src_buf, *tgt_buf;
   struct stat source_sb, target_sb;
   char *relpath_str;

   if (PWdebug) {
      relpath_str = relpath;								// default
      if (relpath[0] == '.' && relpath[1] == PATHSEPCHR) relpath_str = relpath + 2;	// strip '.', if present)
      fprintf(WLOG, "cmp_files(s): %s%c%s\n", SOURCE_PATH(w_id), PATHSEPCHR, relpath_str);
      fprintf(WLOG, "cmp_files(t): %s%c%s\n", TARGET_PATH(w_id), PATHSEPCHR, relpath_str);
   }

   // Open both files ...
   if ((fds = openat(SOURCE_DFD(w_id), relpath, O_RDONLY|O_NOFOLLOW|O_OPENLINK)) < 0) goto out;
   if ((fdt = openat(TARGET_DFD(w_id), relpath, O_RDONLY|O_NOFOLLOW|O_OPENLINK)) < 0) goto out;

   // ==== klooge: test to assure source and target not same file?

   // Optimize sequential reading and page cache usage (klooge: would OSX fcntl() help?) ...
#if !defined(__OSX__)
   posix_fadvise(fds, 0L, 0L, POSIX_FADV_SEQUENTIAL|POSIX_FADV_DONTNEED);
   posix_fadvise(fdt, 0L, 0L, POSIX_FADV_SEQUENTIAL|POSIX_FADV_DONTNEED);
#endif

   // Allocate read buffers (if not previously allocated) ...
   // NOTE: These buffers will NEVER BE FREE'D!  The pointers to these buffers are persisted in the WorkerData[]
   // data structure.
#if defined(__LINUX__) || defined(__ONEFS__)
   // Where possible, use well-aligned allocations ...
   //	int posix_memalign(void **memptr, size_t alignment, size_t size);
   if (WorkerData[w_id].SOURCE_BUF_P == NULL)
      assert (posix_memalign(&WorkerData[w_id].SOURCE_BUF_P, 4096, CMP_BUFFER_SIZE) == 0);
   if (WorkerData[w_id].TARGET_BUF_P == NULL)
      assert (posix_memalign(&WorkerData[w_id].TARGET_BUF_P, 4096, CMP_BUFFER_SIZE) == 0);
#else
   assert ((WorkerData[w_id].SOURCE_BUF_P = malloc(CMP_BUFFER_SIZE)) != NULL);
   assert ((WorkerData[w_id].TARGET_BUF_P = malloc(CMP_BUFFER_SIZE)) != NULL);
#endif

   src_buf = WorkerData[w_id].SOURCE_BUF_P;
   tgt_buf = WorkerData[w_id].TARGET_BUF_P;

   // Read and compare files ...
   while (1) {
       src_bytes = read(fds, src_buf, CMP_BUFFER_SIZE);
       tgt_bytes = read(fdt, tgt_buf, CMP_BUFFER_SIZE);
       if ((src_bytes == 0) && (tgt_bytes == 0)) { rc = 0; goto out; }	// Both @ EOF w/ zero difference!
       if (src_bytes != tgt_bytes) goto out;				// WTF?
       if (src_bytes <= 0) goto out;					// WTF?
       if (memcmp(src_buf, tgt_buf, src_bytes)) goto out;		// Explicitly different!
   }
   // Close files as we leave ...
out:
   if (fds >= 0) close(fds);
   if (fdt >= 0) close(fdt);
   return rc;
}

// cmp_source_target() - Compare SOURCE with TARGET dir or file. w_id is needed to drive multi-pathing
// logic for compare operations. We assume output cmp_compare_result_str is at least 16 bytes.

void
cmp_source_target(int w_id, char *relpath, struct stat *src_sb_p, char *cmp_compare_result_str)
{
   int i, rc;
   struct stat target_sb;
   struct stat *tgt_sb_p = &target_sb;;
   char *pstr = cmp_compare_result_str;
   unsigned cmp_result = CMP_equal;	// Start with 0

   rc = fstatat(TARGET_DFD(w_id), relpath, &target_sb, AT_SYMLINK_NOFOLLOW);

   // Construct result mask ...
   if (rc != 0) {
      cmp_result |= CMP_notfound;
      if (errno != ENOENT) {		// ==== klooge: add WARNING to worker's count!
          fprintf(Plog, "WARNING: fstatat(target, \"%s\") errno=%d\n", relpath, errno);
          cmp_result |= CMP_error;
      }
   } else {
      if ((src_sb_p->st_mode&S_IFMT) != (tgt_sb_p->st_mode&S_IFMT)) cmp_result |= CMP_type;
      if ((cmp_Check&CMP_mode) && ((src_sb_p->st_mode&07777) != (tgt_sb_p->st_mode&07777))) cmp_result |= CMP_mode;
#if HAVE_STRUCT_STAT_ST_FLAGS
      if ((cmp_Check&CMP_flags) && (src_sb_p->st_flags != tgt_sb_p->st_flags)) cmp_result |= CMP_flags;
#endif
      if ((cmp_Check&CMP_uid) && (src_sb_p->st_uid != tgt_sb_p->st_uid)) cmp_result |= CMP_uid;
      if ((cmp_Check&CMP_gid) && (src_sb_p->st_gid != tgt_sb_p->st_gid)) cmp_result |= CMP_gid;
      if ((cmp_Check&CMP_atime) && (src_sb_p->st_atime != tgt_sb_p->st_atime)) cmp_result |= CMP_atime;
      if ((cmp_Check&CMP_mtime) && (src_sb_p->st_mtime != tgt_sb_p->st_mtime)) cmp_result |= CMP_mtime;
      if ((cmp_Check&CMP_birthtime) && (src_sb_p->st_birthtime != tgt_sb_p->st_birthtime)) cmp_result |= CMP_birthtime;
      if (!(cmp_result&CMP_type) && S_ISREG(src_sb_p->st_mode)) {	// Only for regular files ...
         if ((cmp_Check&CMP_size) && (src_sb_p->st_size != tgt_sb_p->st_size)) cmp_result |= CMP_size;
         if ((cmp_Check&CMP_blocks) && (src_sb_p->st_blocks != tgt_sb_p->st_blocks)) cmp_result |= CMP_blocks;
         if (cmp_Check&CMP_content) {
            if (cmp_result&(CMP_size|CMP_type)) {
               cmp_result |= CMP_content;	// Inferred diffence
            } else {
               if (cmp_files(w_id, relpath))	// Exhaustive compare
                  cmp_result |= CMP_content;
            }
         }
      }
   }

   // Construct result string from mask ...
   memset(cmp_compare_result_str, 0, 16);	// Start w/ all NULs
   for (i=0; cmp_Keywords[i].keyword; i++)
      if (cmp_result&cmp_Keywords[i].maskval) *pstr++ = cmp_Keywords[i].code;
   if (cmp_result == CMP_equal) strcpy(cmp_compare_result_str, "-");
}

// @@@ SECTION: pwalk +tally support @@@

// @@@ #tally accumulate - per-worker subtotals ...

// pwalk_tally_file() - Accumulate per-worker +tally subtotals.
// NOTE: Bucket[TALLY_BUCKETS] catches files that did not fall into previous buckets.

void
pwalk_tally_file(struct stat *sb, int w_id)
{  
   int i;
   
   // Probably-redundant check ...
   if (!Cmd_TALLY) return;

   // We only tally regular files here ...
   if (!S_ISREG(sb->st_mode)) return;
   
   // @@@ Accumulate WS subtotals from per-file contributions ...
   for (i=0; i<TALLY_BUCKETS; i++) {
      if ((sb->st_size <= TALLY_BUCKET_SIZE[i]) || (i+1 == TALLY_BUCKETS)) {
         WS[w_id]->TALLY_BUCKET.count[i] += 1;
         WS[w_id]->TALLY_BUCKET.size[i] += sb->st_size;
         WS[w_id]->TALLY_BUCKET.space[i] += sb->st_blocks * ST_BLOCK_SIZE;
         return;
      }
   }
}

// @@@ #tally output - calculate & output ...

void
pwalk_tally_output()
{
   FILE *TALLY;
   char ofile[MAX_PATHLEN+2];
   char *relop;
   int i, w_id;

   // @@@ Create output file ...
   sprintf(ofile, "%s%cpwalk_tally.csv", OUTPUT_DIR, PATHSEPCHR);
   TALLY = fopen(ofile, "w");
   if (TALLY == NULL) abend("Cannot create .tally file!");

   count_64 tally_total_count = 0;
   count_64 tally_total_size = 0;
   count_64 tally_total_space = 0;
   double tally_pct_count[TALLY_BUCKETS_MAX];
   double tally_pct_size[TALLY_BUCKETS_MAX];
   double tally_pct_space[TALLY_BUCKETS_MAX];
   double tally_inflation[TALLY_BUCKETS_MAX];

   // @@@  Calculate: Grand totals ...
   for (i=0; i<TALLY_BUCKETS; i++) {
      tally_total_count += GS.TALLY_BUCKET.count[i];
      tally_total_size += GS.TALLY_BUCKET.size[i];
      tally_total_space += GS.TALLY_BUCKET.space[i];
   }

   // @@@  Calculate: Bucket percentages of grand totals ...
   for (i=0; i<TALLY_BUCKETS; i++) {
      tally_pct_count[i] = 100. * (tally_total_count ? GS.TALLY_BUCKET.count[i] / (double) tally_total_count : 0.);
      tally_pct_size[i] = 100. * (tally_total_size ? GS.TALLY_BUCKET.size[i] / (double) tally_total_size : 0.);
      tally_pct_space[i] = 100. * (tally_total_space ? GS.TALLY_BUCKET.space[i] / (double) tally_total_space : 0.);
      tally_inflation[i] = (GS.TALLY_BUCKET.size[i] ? GS.TALLY_BUCKET.space[i] / (double) GS.TALLY_BUCKET.size[i] : 0.);
   }
   
   // @@@  Output: Headings ...
   for (i=0; TALLY_COLUMN_HEADING[i]; i++) {
      fprintf(TALLY, "%s", TALLY_COLUMN_HEADING[i]);
      if (TALLY_COLUMN_HEADING[i+1]) fprintf(TALLY, ",");
   }
   fprintf(TALLY, "\n");
   
   // @@@  Output: Buckets with percentages ...
   for (i=0; i<TALLY_BUCKETS; i++) {
      if (TALLY_BUCKET_SIZE[i] == 0) {
         if (i == 0) relop = "=";
         else relop = ">";
      } else relop = "<=";
      fprintf(TALLY, "%s[%02d],\"%s %llu KiB\",%llu,%04.02f,%llu,%04.02f,%llu,%04.02f,%06.04f\n",
         TALLY_TAG, i, relop,
         (i+1 == TALLY_BUCKETS) ? TALLY_BUCKET_SIZE[i-1]/1024 : TALLY_BUCKET_SIZE[i]/1024,
         GS.TALLY_BUCKET.count[i], tally_pct_count[i],
         GS.TALLY_BUCKET.size[i], tally_pct_size[i],
         GS.TALLY_BUCKET.space[i], tally_pct_space[i],
         tally_inflation[i]);
   }

   // @@@  Output: Grand totals ...
   fprintf(TALLY, "%s[%d],\"%s\",%llu,%04.02f,%llu,%04.02f,%llu,%04.02f,%06.04f\n",
      TALLY_TAG, TALLY_BUCKETS,
      "TOTALS",
      tally_total_count, 100.,
      tally_total_size, 100.,
      tally_total_space, 100.,
      tally_total_size ? tally_total_space / tally_total_size : 0.);

   fclose(TALLY);
}

// selected() is a TEMPORARY placeholder for file-selection logic. Files and directories which return
// FALSE will not be output.
//
// NOTE: st_birthtime will NOT be accurate on NFS client! It will probably be a copy of ctime! So, avoid
// trying to select on it unless native to OneFS.

int
selected(char *filename, struct stat *sb)
{
   if (SELECT_HARDCODED) {
      // Blacklist / exclude ...
      // if (S_ISDIR(sb->st_mode)) return (0);		// Skip dirs
   
      // Whitelist / includes ..
      // if (!S_ISREG(sb->st_mode)) return (1);		// Include all non-ordinary files
      // if (strstr(filename, "|")) return (1);		// Include names with '|'
      // if (sb->st_uid == 0) return (1);		// Include only root-owned files
   
      // regexp() example ...
   }

   // Include only files changed (ctime or mtime) since mtime of -since=<file> ...
   if (SELECT_SINCE) {
       if ((sb->st_ctimespec.tv_sec > SELECT_T_SINCE) || (sb->st_mtimespec.tv_sec > SELECT_T_SINCE))
          return (1);
   }

#if defined(__ONEFS__)
   if (SELECT_FAKE) {
   }
#endif

   // Default is to exclude ...
   return (0);
}

// @@@ SECTION: ascii_fy & de_ascii_fy @@@
// klooge: FUTURE

// @@@ SECTION: FIFO management @@@

// FIFO logic must be re-entrant because multiple workers may be trying to push newly-discovered
// directory paths at the same time.  FIFO access is serialized by MP_mutex. These push and pop
// routines are atomic as far as the rest of the program logic is concerned; so the depth of the
// FIFO is never ambiguous for even an instant.

// fifo_push() - Push passed directory path onto file-based FIFO (pwalk.fifo).

void
fifo_push(char *pathname, struct stat *sb, int w_id)
{
   char ascii_path[8192];
   char *pi, *po;
   int nw_busy;

   // ASCII-fy: Pathnames might be in a non-ASCII character set, so for file and pathnames
   // that must be externally represented (in pwalk.fifo or other pwalk outputs), we make
   // an 'ASCII-fied' copy. Readers of these values, such as fifo_pop(), must reverse this
   // transformation.
   //
   // We use the byte translations marked as YES in this table, which should show what 'ls -lbd' would show;
   // 
   // YES	\a 		07 	Alert (Beep, Bell) (added in C89)[1]
   // YES	\b 		08 	Backspace
   // YES	\t 		09 	Horizontal Tab
   // YES	\n 		0A 	Newline (Line Feed); see notes below
   // YES	\v 		0B 	Vertical Tab
   // YES	\f 		0C 	Formfeed
   // YES	\r 		0D 	Carriage Return
   // YES	\" 		22 	Double quotation mark
   // YES	\' 		27 	Single quotation mark
   // YES	\? 		3F      Question mark
   // YES	\\ 		5C 	Backslash
   // YES	\xhh 		any 	The byte whose numerical value is given by hh… interpreted as a hexadecimal number
   // NO	\e 		1B 	Escape character
   // NO	\nnn 		any 	The byte whose numerical value is given by nnn interpreted as an octal number
   // NO	\Uhhhhhhhh 	none 	Unicode code point where h is a hexadecimal digit
   // NO	\uhhhh 		none 	Unicode code point below 10000 hexadecimal
   //
   // NOTE: (Table derived from: https://en.wikipedia.org/wiki/Escape_sequences_in_C)
   // 
   for (pi=pathname, po=ascii_path; *pi; pi++) {
      if (isgraph(*pi)) {
         if (*pi == '\'' || *pi == '"' || *pi == '?' || *pi == '\\') *po++ = '\\';
         *po++ = *pi;
      } else {
         *po++ = '\\';
         if (*pi >= '\a' && *pi <= '\r') {
            *po++ = "abtnvfr"[*pi - '\a'];
         } else {
            *po++ = 'x';
            *po++ = "0123456789abcdef"[(*pi & 0xf0) >> 4];
            *po++ = "0123456789abcdef"[(*pi & 0xf)];
         }
      }
      assert (po < ascii_path+8100);
   }
   *po = NUL;

   // We usually skip .snapshot and .isi-compliance directories entirely ...
   if (skip_this_directory(pathname, sb, w_id))
      return;

   // Here's the PUSH and associated coherent accounting ...
   MP_LOCK("fifo_push()");					// +++ MP lock +++
   fprintf(Fpush, "%s\n", ascii_path);				// push ascii_path
   FIFO_PUSHES += 1;
   FIFO_DEPTH += 1;
   if (Workers_BUSY < N_WORKERS) poke_manager("fifo_push()");
   MP_UNLOCK;							// --- MP lock ---
}

// Always returns current (pre-pop) depth of the FIFO (ie: 0 -> FIFO is empty).
// If passed pathname is NULL, do not actually pop the FIFO; just determine its depth.
// If passed pathname is not NULL, pop FIFO into the passed buffer.

char
hex_cval(char ch)
{
   if (ch >= '0' && ch <= '9') return (ch - '0');
   else if (ch >= 'a' && ch <= 'f') return (ch - 'a' + 10);
   else if (ch >= 'A' && ch <= 'F') return (ch - 'A' + 10);
   else assert("hex_cval() badarg!"==NULL);
}

// fifo_pop() - Pop FIFO into passed pathname, returning pre-pop FIFO depth.

int
fifo_pop(char *pathname)
{
   char *pi, *po;;
   char ch;
   int rc;
   count_64 fifo_depth;
   char ascii_path[8192];

   assert(Fpop != NULL);	// File handle for FIFO pops

   MP_LOCK("fifo_pop()");						// +++ MP lock +++
   fifo_depth = FIFO_DEPTH;
   if (fifo_depth == 0 || pathname == NULL) {
      MP_UNLOCK;							// --- MP lock ---
      return(fifo_depth);
   } else { // Still holding MP lock ...
      pathname[0] = '\0';
      if (fgets(ascii_path, sizeof(ascii_path)-1, Fpop) == NULL)	// pop ascii_path (or die!)
         abend("fifo_pop() read failure!");
      FIFO_POPS += 1;
      FIFO_DEPTH -= 1;
      MP_UNLOCK;							// --- MP lock ---
   }

   // De-ASCII-fy: Copy ascii_path to outpt pathname, de-ASCII-fying as we go ...
   // FUTURE: This logic assumes PATHSEPCHR is '/', not '\\'! (klooge)
   // FUTURE: functionally encapsulate ASCII-fy and de-ASCII-fy operations
   // YES	\a 		07 	Alert (Beep, Bell) (added in C89)[1]
   // YES	\b 		08 	Backspace
   // YES	\t 		09 	Horizontal Tab
   // YES	\n 		0A 	Newline (Line Feed); see notes below
   // YES	\v 		0B 	Vertical Tab
   // YES	\f 		0C 	Formfeed
   // YES	\r 		0D 	Carriage Return
   // YES	\" 		22 	Double quotation mark
   // YES	\' 		27 	Single quotation mark
   // YES	\? 		3F      Question mark
   // YES	\\ 		5C 	Backslash
   // YES	\xhh 		any 	The byte whose numerical value is given by hh… interpreted as a hexadecimal number
   for (pi=ascii_path, po=pathname; *pi; ) {
      if (pi[0] == '\\') {				// Escape ...
         if (pi[1] == 'x') {				// NEXT 2 are hex digits -- or DIE!
            *po++ = (hex_cval(pi[2]) << 4) | (hex_cval(pi[3]));
            pi += 4;
         } else {
            if      (pi[1] == 'a') *po++ = 0x07;	// ANSI special character exceptions ...
            else if (pi[1] == 'b') *po++ = 0x08;
            else if (pi[1] == 't') *po++ = 0x09;
            else if (pi[1] == 'n') *po++ = 0x0A;
            else if (pi[1] == 'v') *po++ = 0x0B;
            else if (pi[1] == 'f') *po++ = 0x0C;
            else if (pi[1] == 'r') *po++ = 0x0D;
            else                   *po++ = pi[1];	// <whatever>, raw
            pi += 2;
         }
      } else {						// Plain, non-escape ...
         *po++ = *pi++;
      }
      assert (po < (pathname+MAX_PATHLEN-1));
   }
   assert (po > pathname);		// MUST be non-empty string!
   assert (*(po-1) == '\n');		// MUST have newline from fgets()!
   *(po-1) = NUL;			// Over-write trailing newline ...
   // strlen(pathname) will be (po - pathname)

   return(fifo_depth);
}

// @@@ SECTION: worker_thread() @@@

// worker_thread() - Worker pThread ...

// N_WORKERS of these worker_thread() functions will always be running concurrently,
// until program termination criteria is determined in manage_workers(), and the threads
// are shut down from main().
//
// State transition model;
//	- When first started, a worker's status (wstatus) is EMBRYONIC; the thread-starter
//		waits until all workers have escaped that status before manager_workers()
//		("the manager") is called.
//	- At the top of the loop, workers transition to BUSY, and remain BUSY for as long
//		as they can pop more work from the FIFO.
//	- When a worker runs out of work, it transitions itself from BUSY to IDLE and waits
//		to be re-awakened by the manager.
// IDLE/BUSY accounting is crucial to pwalk's exit criteria of ("FIFO empty and all workers
// are IDLE").

void *
worker_thread(void *parg)
{
   int w_id = *((int *) parg);	// Unique to our thread & passed on to subordinate functions
   sigset_t sigmask;
   count_64 w_fifo_pops = 0, w_fifo_pops_0;
   unsigned w_wakeups = 0;
   char msg[256], *dp;		// *dp - dynamic; should be freed, but only used to abend!
   int rc, status_change;
   pthread_mutexattr_t mattr;	// klooge: TINY one-time memory leak

   if (PWdebug) fprintf(stderr, "= Worker %d -> START ...\n", w_id);

   // Disable *most* signals in our thread ...
//   sigemptyset(&sigmask);
//   sigaddset(&sigmask, SIGBUS);
//   sigaddset(&sigmask, SIGSEGV);
//   assert(pthread_sigmask(SIG_SETMASK, &sigmask, NULL) == 0);

   // We hold our own cv lock at all times past here except during our condition wait ...
   if (( rc = pthread_mutex_lock(&(WORKER_mutex[w_id])) )) {	// +++ WORKER cv lock +++
     asprintf(&dp, "pthread_mutex_lock(&(WORKER_mutex[%d])) = rc=%d\n", w_id, rc);
     abend(dp);
   }

   //### if we cannot get a worker lock, it must be BUSY, skip it
   //### if we can get a worker lock, it must be in a condition wait state, so ...
   //### 	release the lock and signal the worker to return to BUSY

   // Start off IDLE (ends our EMBRYONIC status) ...
   if (PWdebug) fprintf(stderr, "= Worker %d -> IDLE ...\n", w_id);
   MP_LOCK("start off IDLE");					// +++ MP lock +++
   WDAT.status = IDLE;
   MP_UNLOCK;							// --- MP lock ---

   // Stay in this loop forever -- until our thread is SHUT DOWN by management ...
   while (1) {
      // Wait for starting gun ...
      if (PWdebug) fprintf(stderr, "= Worker %d -> WAIT ...\n", w_id);
      rc = pthread_cond_wait(&(WORKER_cond[w_id]), &(WORKER_mutex[w_id]));
      if (rc) {
         fprintf(stderr, "WAIT ERROR: w_id=%d rc=%d\n", w_id, rc);
         assert("WAIT" == NULL);
      }

      // We're back active again!!!
      w_wakeups += 1;
      if (PWdebug) {
         sprintf(msg, "@ Worker %d -> WAKES (#%u) ...\n", w_id, w_wakeups);
         fputs(msg, stderr);
         LogMsg(msg, 1);
      }

      // Track if we do anything on this wake cycle ...
      w_fifo_pops_0 = w_fifo_pops;

      // Stay BUSY as long as FIFO can be popped ...
      while (fifo_pop(WDAT.DirPath)) {
         w_fifo_pops += 1;
         // Transition to BUSY busy after FIRST successful pop ...
         if (w_fifo_pops == (w_fifo_pops_0 + 1)) {
            if (PWdebug) fprintf(stderr, "= Worker %d ->BUSY ...\n", w_id);
            MP_LOCK("MP mutex transition to BUSY");		// +++ MP lock +++
            WDAT.status = BUSY;
            Workers_BUSY += 1;
            MP_UNLOCK;						// --- MP lock ---
            sprintf(msg, "@ Worker %d busy after wakeup %d\n", w_id, w_wakeups);
            if (PWdebug) fputs(msg, stderr);
            LogMsg(msg, 1);
         }
         directory_scan(w_id);					// $$$ WORKER'S MISSION $$$
         // Give other workers a chance push or pop FIFO!
         yield_cpu();
      }

      // If we were BUSY, transition to IDLE ...
      MP_LOCK("transition to IDLE?");				// +++ MP lock +++
      status_change = 0;
      if (WDAT.status == BUSY) {
         status_change = 1;
         WDAT.status = IDLE;
         Workers_BUSY -= 1;
      }
      MP_UNLOCK;						// --- MP lock ---

      if (status_change) {
         sprintf(msg, "@ Worker %d idle after %llu FIFO pops\n", w_id, (w_fifo_pops - w_fifo_pops_0));
         if (PWdebug) fputs(msg, stderr);
         LogMsg(msg, 1);
      }

      // Poke manager if we transitioned to IDLE ...
      if (status_change) {
         poke_manager("transition to IDLE");			// +/- MANAGER lock +/-
         yield_cpu();
      }
   }
}

// @@@ SECTION: manage_workers() @@@

// manage_workers() - Manage worker threads. Only called once; this loop lasts for
// the duration of the 'workers active' phase of pwalk operation. Returns when all
// workers are IDLE *and* the FIFO is empty.

void
manage_workers()
{
   int w_id = 0, last_w_id_woken = -1;
   unsigned nw_to_wake, nw_wakeups, nw_idle, nw_busy;
   count_64 fifo_depth;
   wstatus_t wstatus;
   char msg[256];

   while (1) {
      if (PWdebug) fprintf(stderr, "= manage_workers; get worker_status() ...\n");
      worker_status(&nw_idle, &nw_busy, &fifo_depth);		// +++ MP lock ---
      if (PWdebug) fprintf(stderr, "= manage_workers: nw_idle=%d nw_busy=%d fifo_depth=%llu\n",
                      nw_idle, nw_busy, fifo_depth);

      // Are we there yet?
      if ((nw_busy == 0) && (fifo_depth == 0)) break;			// All done!

      // Any chance we're gonna poke any workers?
      if (nw_busy == N_WORKERS) goto loop;	// "I'm givin' ya all we got, Captain!" ...

      // Is there unattended work in the FIFO?
      if (fifo_depth == 0) goto loop;		// Nope ...

      // Wakeup workers as needed by signalling them to transition from IDLE to BUSY.
      // Workers transition themselves from BUSY back to IDLE.
      //
      // Determine how many workers to wake. We might wake a worker that subsequently
      // finds no work to do and rapidly returns to IDLE, but that's OK. Indeed, a newly-
      // woken worker may well find the FIFO has already been emptied by some already-BUSY
      // worker thread, in which case it will simply revert to being IDLE.
      //
      // Note that a worker's status may have transitioned since we took our inventory
      // above, so we inquire in a lock-protected way here. We do not care if an IDLE
      // worker was one from our inventory above; only that it's IDLE now. No worker can
      // transition back from IDLE to BUSY until and unless we wake them.
      //
      nw_to_wake = (fifo_depth < nw_idle) ? fifo_depth : nw_idle;
      if (PWdebug) fprintf(stderr, "= manage_workers: wanna wake %d worker(s)\n", nw_to_wake);
      if (nw_to_wake > 0) {
         // Round-robin/LRU worker assign logic ...
         w_id = last_w_id_woken;
         for (nw_wakeups=0; nw_wakeups < nw_to_wake; ) {
            w_id = ((w_id+1) < N_WORKERS) ? w_id+1 : 0;
            MP_LOCK("probe wstatus");					// +++ MP lock +++
            wstatus = WDAT.status;
            MP_UNLOCK;							// --- MP lock ---
            if (wstatus == IDLE) {
               // Signal worker to wakeup ...
               if (PWdebug) fprintf(stderr, "= manage_workers: waking worker %d\n", w_id);
               assert(pthread_cond_signal(&(WORKER_cond[w_id])) == 0);
               nw_wakeups += 1;
               last_w_id_woken = w_id;
            }
         }
      }
loop:
      // Block until re-awakened by any worker signaling our condition variable ...
      if (PWdebug) fprintf(stderr, "= manage_workers: waits\n");
      if (pthread_cond_wait(&MANAGER_cond, &MANAGER_mutex))
         abend("MANAGER cv wait error!");
      if (PWdebug) fprintf(stderr, "= manage_workers: wakes\n");
   }
   if (PWdebug) fprintf(stderr, "= manage_workers: exits\n");
}

// @@@ SECTION: PathName Redaction @@@

// redact_path() - Create a redacted relative pathname from the passed-in relpath (directory) and its
// inode number.  We will stat() each partial path up to the final directory to get its inode number.
// The passed-in w_id is used both for multipathing the stat() calls and for the WLOG and WERR macros.
//
// If the relpath is ".", the redacted_relpath will just be the inode for ".". Otherwise, all other output
// values will begin with "./", representing the relative root of the source tree, even if pwalk is in
// absolute path mode.

void
redact_path(char *relpath_redacted, char *relpath, ino_t relpath_inode, int w_id)
{
   struct stat sb;
   int i, rc, np, errs = 0;
   char *p, *pi, *po, *p_sep[128];
   ino_t inode[128];

   // Use output relpath_redacted as temp storage for cleansed copy of the input relpath.
   // We'd like to use realpath() here to clean up the relpath, but realpath() always returns an
   // absolute path, which is not what we want here. Result should be '<inode>[/<inode>]'
   pi = relpath;
   if (*pi == PATHSEPCHR) pi += 1;			// Skip absolute prefix
   if (strncmp(pi, "./", 2) == 0) pi += 2;		// Skip initial "./"
   for (po = relpath_redacted; *pi; pi++) {		// Reduce "/./" and "//"
      while ((strncmp(pi, "/./", 3) == 0 && (pi += 2)) ||
             (strncmp(pi, "//", 2) == 0 && (pi += 1))) ;
      if (*pi != PATHSEPCHR || po > relpath_redacted) *po++ = *pi;
   }
   *po = '\0';
   if (relpath_redacted[0] == '\0') strcpy(relpath_redacted, ".");

   // Count PATHSEPCHRs, collecting pointers to them ...
   for (np=0, pi = relpath_redacted; *pi; pi++) {
      if (*pi == PATHSEPCHR) p_sep[np++] = pi;
      assert (np < MAX_DEPTH);							// klooge: crude
   }
   inode[np] = relpath_inode;
   //DEBUG fprintf(stderr, "@@ \"%s\" (ino=%llx)\n-> \"%s\" (np=%d)\n", relpath, relpath_inode, relpath_redacted, np);

   // Collect inode #'s for partial paths up to current dir ...
   for (i=0; i<np; i++) {
      *p_sep[i] = '\0';		// Temporarily replace PATHSEPCHR with a NUL
      if (fstatat(SOURCE_DFD(w_id), relpath_redacted, &sb, AT_SYMLINK_NOFOLLOW)) {
         errs++;
         inode[i] = 0;
      } else {
         inode[i] = sb.st_ino;
      }
      //DEBUG fprintf(stderr, "...\"%s\" (inode=%llx)\n", relpath_redacted, sb.st_ino);
      *p_sep[i] = PATHSEPCHR;	// Put the PATHSEPCHR back
   }

   // Output into our relpath_redacted a concatenation of the inode numbers ...
   p = relpath_redacted;
   for (i=0; i<=np; i++) {
      p += sprintf(p, "%s%llx", (np && i>0 ? "/" : ""), inode[i]);
      assert ((p - relpath_redacted) < (MAX_PATHLEN - 18));			// klooge: crude
   }
   *p = '\0';

   if (errs)									// klooge: crude
      fprintf(WERR, "ERROR: %d error(s) redacting \"%s\"\n", errs, relpath);

   return;
}

// @@@ SECTION: directory_scan() @@@

// directory_scan() - Thread-safe directory-scanner.

// Process WDAT.DirPath with reentrant stdlib readdir_r() calls to walk directories.

// NOTE: It would be tempting to cwd to the directory we are scanning to avoid having to
// concatenate the pathname and filename before each stat(), but the cwd is process-wide,
// and we are just one on many threads in this process.

// struct stat { // Cribsheet ...
//    dev_t    st_dev;    /* device inode resides on */
//    ino_t    st_ino;    /* inodes number */
//    mode_t   st_mode;   /* inode protection mode */
//    nlink_t  st_nlink;  /* number of hard links to the file */
//    uid_t    st_uid;    /* user-id of owner */
//    gid_t    st_gid;    /* group-id of owner */
//    dev_t    st_rdev;   /* device type, for special file inode */
//    struct timespec st_atimespec;  /* time of last access */
//    struct timespec st_mtimespec;  /* time of last data modification */
//    struct timespec st_ctimespec;  /* time of last file status change */
//    off_t    st_size;   /* file size, in bytes */
//    quad_t   st_blocks; /* blocks allocated for file */
//    u_long   st_blksize;/* optimal file sys I/O ops blocksize */
//    u_long   st_flags;  /* user defined flags for file */
//    u_long   st_gen;    /* file generation number */
// };
//
// NOTE: All stat() calls here must use fstatat(2) to employ multipathing.

void
directory_scan(int w_id)		// CAUTION: MT-safe and RE-ENTRANT!
{	// +++++ BREAK UP THIS SPAGHETTI CODE: START @@@
   DIR *dir;
   int fd, dfd, dirent_type;
   int i, rc, have_stat, acl_present, acl_supported = TRUE;
   int openit;				// Flag indicates we must open files for READONLY purposes
   int pathlen, namelen;
   unsigned long long rm_path_hits;	// Count files rm'd within directory ===== klooge/globalize?
   char *p, *pend;
   struct dirent *pdirent, *result;
   struct stat curdir_sb, dirent_sb;

   // Assorted buffers ...
   char errstr[256];			// For strerror_r()
   char dump_str[8192];
   char owner_sid[128], group_sid[128];
   char owner_name[64], group_name[64];
   char rm_rc_str[16];			// For "%s rm ..." -> '#' == dryrun, <n> == errno

   // @@@ Implement -redact as macros ...
   char RedactedRelPathDir[MAX_PATHLEN+2];	// For -redact
   char RedactedFileName[32];
   char RedactedPathName[MAX_PATHLEN+2];
   #define REDACT_RelPathDir (Opt_REDACT ? RedactedRelPathDir : RelPathDir)
   #define REDACT_FileName (Opt_REDACT ? RedactedFileName : FileName)
   #define REDACT_PathName (Opt_REDACT ? RedactedPathName : PathName)
   
   // For -cmp ...
   int cmp_target_dir_exists;		// In -cmp mode, report all files as 'E' if target dir non-existant
   char cmp_dir_result_str[32];		// Concatenation of -cmp letter codes ('[-ET]' or '[MFogsSambC]*') for dir
   char cmp_file_result_str[32];	// Concatenation of -cmp letter codes ('[-ET]' or '[MFogsSambC]*') for file
   int cmp_dir_reported = FALSE;	// Set when directory cmp line has been reported
   // Locals ...
   unsigned crc_val;			// +crc results
   char crc_str[16];			// ... formatted as hex
   unsigned long md5_val;		// +md5 results
   char md5_str[32];			// ... formatted as hex
   long long t0, t1, t2;		// For high-resolution timing samples
   long long ns_stat, ns_getacl;	// ns for stat() and get ACL calls
   char ns_stat_s[32], ns_getacl_s[32];	// Formatted timing values
   char mode_str[16];			// Formatted mode bits
   off_t bytes_allocated;		// Cumulative per-file allocated space

   char *FileName;			// Pointer to filename (dirent)
   char *RelPathDir;			// Pointer to WDAT.DirPath (value popped from FIFO)
   char AbsPathDir[MAX_PATHLEN+1];	// Absolute directory path (value prepended by source/target relative root)
   char RelPathName[MAX_PATHLEN+1];	// Relative pathname (relative to source/target relative roots)
   char AbsPathName[MAX_PATHLEN+1];	// Absolute pathname (value prepended by AbsPathDir)

   unsigned char rbuf[128*1024];	// READONLY buffer for +crc and +denist (cheap, on-stack, should be dynamic)
   size_t nbytes;			// READONLY bytes read

   PWALK_STATS_T DS;			// Per-directory counters
   char emsg[MAX_PATHLEN+256];
   char rc_msg[64] = "";
   // void *directory_acl = NULL;		// For +rm_acls functionality #####

#if PWALK_ACLS // POSIX ACL-related local variables ...
   // Interface to pwalk_acls module ...
   int aclstat;        		        // 0 == none, &1 == acl, &2 == trivial, &4 == dacl
   acl4_t acl4;
   char pw_acls_emsg[128] = "";
   int pw_acls_errno = 0;
   char acl4OUTmode;			// 'o' (file) or 'p' (pipe)
#endif // PWALK_ACLS

   // Make sure output file is ready ...
   if (!WDAT.wlog) worker_log_create(w_id);

   // @@@ ACCESS (directory): opendir() just-popped directory ...
   RelPathDir = WDAT.DirPath;
   if (VERBOSE) {
      sprintf(emsg, "@ Worker %d popped %s\n", w_id, RelPathDir);
      LogMsg(emsg, 1);
      if (VERBOSE > 2) { fprintf(WLOG, "@%s\n", RelPathDir); fflush(WLOG); }
      if (VERBOSE > 2) { fprintf(WLOG, "@opendir\n"); fflush(WLOG); }
   }

   // Calculate AbsPathDir for directory we are entering ...
   p = RelPathDir;
   if (p[0] == '.') {
      if (p[1] == '\0') p = "";			// dir == "."
      else if (p[1] == PATHSEPCHR) p += 2;	// ignore "./" initial string
   }

   // Previously-stored path strings may be superceded here ...
   if (ABSPATH_MODE)
      strcpy(AbsPathDir, p);						// No multi-pathing ...
   else if ((p[0] == PATHSEPCHR) || str_ends_with(SOURCE_PATH(w_id), PATHSEPCHR))
      sprintf(AbsPathDir, "%s%s", SOURCE_PATH(w_id), p);		// Just concatenate ...
   else
      sprintf(AbsPathDir, "%s%c%s", SOURCE_PATH(w_id), PATHSEPCHR, p);	// Concatenate with PATHSEPCHR ...

   // @@@ Here's the opendir() ...
   dir = opendir(AbsPathDir);	// No opendirat() exists  :-(  !
   if (PWdebug >2) fprintf(Plog, "@ opendir(\"%s\") errno=%d\n", AbsPathDir, dir == NULL ? errno : 0);
   if (dir == NULL) {							// @@ <warning> ...
      // Directory open errors (ENOEXIST, !ISDIR, etc) just provoke WARNING output.
      // klooge: want to skip ENOEXIST, EPERM, EBUSY, but otherwise process non-directory FIFO entry
      rc = errno;
      WS[w_id]->NWarnings += 1;
      assert(strerror_r(rc, errstr, sizeof(errstr)) == 0);
      fprintf(WERR, "WARNING: Cannot opendir(\"%s\") (%s)\n", AbsPathDir, errstr);
      if (Cmd_XML) fprintf(WLOG, "<warning> Cannot opendir(\"%s\") (%s) </warning>\n", AbsPathDir, errstr);
      goto exit_scan; // Skip to summary for this popped entry ...
   } else if (VERBOSE > 1) {
      sprintf(emsg, "VERBOSE: Worker %d diropen(\"%s\") errno=%d)\n", w_id, AbsPathDir, rc);
      LogMsg(emsg, 1);
   }
   WS[w_id]->NOpendirs += 1;

   // @@@ GATHER (directory): Get directory's metadata via fstatat() ...
   // Get fstatat() info on the now-open directory (not counted with the other stat() calls) ...
#if SOLARIS
   dfd = dir->dd_fd;
#else
   dfd = dirfd(dir);
#endif
   ns_stat_s[0]='\0';
   if (Opt_TSTAT) t0 = gethrtime();
   fstat(dfd, &curdir_sb);		// klooge: assuming success because it's open	+++++
   if (Opt_TSTAT) { t1 = gethrtime(); ns_stat = t1 - t0; sprintf(ns_stat_s," (%lldus) ", ns_stat/1000); }
   if (VERBOSE > 2) { fprintf(WLOG, "@stat\n"); fflush(WLOG); }
   format_mode_bits(mode_str, curdir_sb.st_mode);
   if (Opt_REDACT)
      redact_path(RedactedRelPathDir, RelPathDir, curdir_sb.st_ino, w_id);

   // Re-Initialize Directory Subtotals (DS) ...
   bzero(&DS, sizeof DS);
   DS.NBytesNominal = curdir_sb.st_size;
   DS.NBytesAllocated = bytes_allocated = curdir_sb.st_blocks * ST_BLOCK_SIZE;

   // @@@ GATHER & OUTPUT (directory): -cmp mode ...
   if (Cmd_CMP) {
      cmp_source_target(w_id, RelPathDir, &curdir_sb, cmp_dir_result_str);
      // If TARGET dir does not exist, save scan time by just reporting 'E' for all dir contents.
      cmp_target_dir_exists = (strpbrk(cmp_dir_result_str, "ET!") == NULL);	// 'E' or 'T' or '!'  means 'no'
      if (strcmp(cmp_dir_result_str, "-")) {		// Maybe defer this until a file difference is found
         if (ftell(WDAT.wlog)) fprintf(WLOG, "\n");	// Blank line before each new directory
         fprintf(WLOG, "@ %s %s\n", cmp_dir_result_str, RelPathDir);
         cmp_dir_reported = TRUE;
      }
   }

   // @@@ GATHER & PROCESS (directory): ACL ...
   // directory_acl = pwalk_acl_get_fd(dfd);	// DEVELOPMENTAL for +rm_acls
#if defined(__ONEFS__)
   acl_present = (curdir_sb.st_flags & SF_HASNTFSACL);
#else
   acl_present = 0;	// It's a flag on OneFS, but another metadata call otherwise (for later)
#endif
#if PWALK_ACLS		// POSIX-to-NFS4 ACL logic (Linux only) ...
   ns_getacl_s[0]='\0';
   if (P_ACL_P || Cmd_XACLS || Cmd_WACLS) {
      // INPUT & TRANSLATE: Translate POSIX ACL plus DACL to a single ACL4 ...
      pw_acl4_get_from_posix_acls(AbsPathDir, 1, &aclstat, &acl4, pw_acls_emsg, &pw_acls_errno);
      if (PWdebug > 2) fprintf(Plog, "$ AbsPathDir=\"%s\" aclstat=%d pw_acls_errno=%d\n", AbsPathDir, aclstat, pw_acls_errno);
      if (Opt_TSTAT) { t2 = gethrtime(); ns_getacl = t2 - t1; sprintf(ns_getacl_s," (%lldus) ", ns_getacl/1000); }
      if (pw_acls_errno == EOPNOTSUPP) {	// If no support on directory, no point asking for files!
         acl_supported = FALSE;
      } else if (pw_acls_errno) {
         assert(strerror_r(pw_acls_errno, errstr, sizeof(errstr)) == 0);
         DS.NWarnings += 1;
         fprintf(WERR, "WARNING: \"%s\": %s [%d - \"%s\"]\n", RelPathDir, pw_acls_emsg, pw_acls_errno, errstr);
         // Also log to .xml in -xml mode ...
         if (Cmd_XML) fprintf(WLOG, "<warning> \"%s\": %s (rc=%d - %s) </warning>\n",
            RelPathDir, pw_acls_emsg, pw_acls_errno, errstr);
      }
      if (aclstat) {
         acl_present = TRUE;
         DS.NACLs += 1;
      } else strcat(mode_str, ".");
   }
#endif // PWALK_ACLS
   if (acl_present && Opt_MODE && P_ACL_P) strcat(mode_str, "+");

   // @@@ GATHER (directory): Owner name, group name, owner_sid, group_sid ...
   get_owner_group(&curdir_sb, owner_name, group_name, owner_sid, group_sid);
#if defined(__ONEFS__)
   onefs_get_sids((dir)->dd_fd, owner_sid, group_sid);
   // FWIW, OSX has different DIR struct ..
   // onefs_get_sids(dir->__dd_fd, owner_sid, group_sid);
#endif
   if (VERBOSE > 2) fprintf(stderr, "> %s %s <\n", mode_str, RelPathDir);

   // @@@ ACTION/OUTPUT (directory): Perform requested actions on <directory> itself ...
   if (Cmd_XML) {
      fprintf(WLOG, "<directory>\n<path> %lld%s%s %u %lld %s%s </path>\n",
         bytes_allocated, (Opt_MODE ? " " : ""), mode_str, curdir_sb.st_nlink, (long long) curdir_sb.st_size, REDACT_RelPathDir, ns_stat_s);
   } else if (Cmd_LS | Cmd_LSD) {
      if (ftell(WLOG)) fprintf(WLOG, "\n");
      fprintf(WLOG, "@ %s\n", REDACT_RelPathDir);
   } else if (Cmd_LSC) {
      if (ftell(WLOG)) fprintf(WLOG, "\n");
      if (Opt_REDACT) fprintf(WLOG, "@ %s\n", REDACT_RelPathDir);
      else            fprintf(WLOG, "@ %llx %s\n", curdir_sb.st_ino, REDACT_RelPathDir);
   } else if (Cmd_RM) {
      rm_path_hits = 0;		// reset for this dir; -rm does not act on directories
   } else if (Cmd_FIXTIMES) {
      // fprintf(WLOG, "# \"%s\":\n", REDACT_RelPathDir);
   } 

   // @@@ PROCESS (directory): +rm_acls ...
#if defined(__ONEFS__)		// OneFS-specific features ...
   if (Cmd_RM_ACLS && !PWdryrun) {		// klooge: dupe code for <directory> vs. <dirent>
      rc = onefs_rm_acls(dfd, RelPathDir, &curdir_sb, (char *) &rc_msg);
      if (rc < 0) {
         WS[w_id]->NWarnings += 1;
         fprintf(WERR, "WARNING: onefs_rm_acls(\"%s\") for \"%s\"\n", rc_msg, RelPathName);
      } else if (rc > 0) {
         WS[w_id]->NACLs += 1;
         sprintf(emsg, "@ %s \"%s\"\n", rc_msg, RelPathName); fputs(emsg, WLOG);
      }
   }
#endif

   // @@@ DIRECTORY SCAN LOOP (begin): push dirs as we go ...
scandirloop:
   // Copy DirPath to buffer in which we will iteratively append FileNames from dirents ...
   strcpy(RelPathName, RelPathDir);
   pathlen = strlen(RelPathName);
   RelPathName[pathlen++] = PATHSEPCHR;
   RelPathName[pathlen] = '\0';
   pdirent = WDAT.Dirent; // Convenience pointer

   // NOTE: readdir_r() is the main potential metadata-reading LATENCY HOTSPOT
   if (VERBOSE > 2) { fprintf(WLOG, "@readdir_r loop\n"); fflush(WLOG); }
   while (((rc = readdir_r(dir, pdirent, &result)) == 0) && (result == pdirent)) {
      // @@@ PATHCALC (dirent): Quietly skip "." and ".." ...
      FileName = pdirent->d_name;
      if (strcmp(FileName, ".") == 0) continue;
      if (strcmp(FileName, "..") == 0) continue;

      // Construct RelPathName from current directory entry (dirent) ...
      // struct dirent { // (from OSX; Solaris has no d_namlen)
      //    ino_t      d_ino;                /* file number of entry */
      //    __uint16_t d_reclen;             /* length of this record */
      //    __uint8_t  d_type;               /* file type, see below */
      //    __uint8_t  d_namlen;             /* length of string in d_name */
      //    char    d_name[255 + 1];   	     /* name must be no longer than this */
      // };
#if defined(SOLARIS) || defined(__LINUX__)
      namelen=strlen(FileName);
#else
      namelen=pdirent->d_namlen;
#endif
      // Protect against possible buffer overrrun in upcoming strcat ...
      // NOTE: Report overrrun to main log stream as well as worker's log.
      if ((namelen + pathlen + 1) > MAX_PATHLEN) {		// @@ <warning> ...
         DS.NWarnings += 1;
         if (Cmd_XML)
            fprintf(WLOG, "<warning> Cannot expand %s! </warning>\n", RelPathDir);
         fprintf(WERR, "WARNING: Filename \"%s\" expansion would exceed MAX_PATHLEN (%d)\n",
            FileName, MAX_PATHLEN);
         continue;
      }
      strcpy(RelPathName+pathlen, FileName);
      catpath3(AbsPathName, SOURCE_PATH(w_id), RelPathDir, FileName);
      // #redact

      // @@@ GATHER (dirent): stat/fstatat() info ...
      // Get RelPathName's metadata via fstatat() or perhaps just from the dirent's d_type ...
      // At this juncture, we MUST know if this child is a directory or not, so we can decide to push
      // it onto our FIFO. Over NFS, this requires a stat() call, but on a local filesystem, we could
      // use the current dirent->d_type value for this purpose to accelerate treewalk speed.
      // Some dormant code here is aimed at possibly leveraging that in the future for a 'fast'
      // names-only treewalk (eg: to find files using a regexp match).
      have_stat = 0;
      mode_str[0] = '\0';
      ns_stat_s[0] = '\0';
      ns_getacl_s[0] = '\0';

      if (Cmd_AUDIT && 0) {		// DORMANT/EXPERIMENTAL: FAST TREEWALK W/O STAT() - FUTURE
         // Avoid stat() call, require d_type ...
         if (pdirent->d_type == DT_UNKNOWN) {
            fprintf(WLOG, "ERROR: DT_UNKNOWN %s\n", RelPathName);
            continue;
         }
         if (pdirent->d_type == DT_REG || pdirent->d_type == DT_DIR) dirent_type = pdirent->d_type;
         else dirent_type = DT_UNKNOWN;
      } else {				// Gather stat() info for dirent ...
         if (Opt_TSTAT) t0 = gethrtime();
         // NOTE: dfd aleady incorporates multipath logic ...
         rc = fstatat(dfd, FileName, &dirent_sb, AT_SYMLINK_NOFOLLOW);		// $$$ PAYDAY $$$
         if (Opt_TSTAT) { t1 = gethrtime(); sprintf(ns_stat_s," (%lldus) ", (t1-t0)/1000); }
         DS.NStatCalls += 1;
         if (rc) {
            DS.NStatErrors += 1;
            WS[w_id]->NWarnings += 1;
            if (Cmd_XML) fprintf(WLOG, "<warning> Cannot stat(%s) (rc=%d) </warning>\n", RelPathName, rc);
            else fprintf(WERR, "WARNING: Cannot stat(%s) (rc=%d)\n", RelPathName, rc);
            continue;
         }
         have_stat = 1;
         // Cheap-to-keep WS stats ...
         if (dirent_sb.st_ino > WS[w_id]->MAX_inode_Value_Seen)
            WS[w_id]->MAX_inode_Value_Seen = dirent_sb.st_ino;
         // Redaction ...
         if (Opt_REDACT) sprintf(RedactedFileName, "%lld", dirent_sb.st_ino);
         format_mode_bits(mode_str, dirent_sb.st_mode);
         // Make up for these bits not always being set correctly (eg: over NFS) ...
         if S_ISREG(dirent_sb.st_mode) dirent_type = DT_REG;
         else if S_ISDIR(dirent_sb.st_mode) dirent_type = DT_DIR;
         else dirent_type = DT_UNKNOWN;
         // Update DS per-directory misc counters ...
         if (dirent_type != DT_DIR) {
            if (dirent_sb.st_nlink > 1) {
               DS.NHardLinkFiles += 1;
               DS.NHardLinks += (dirent_sb.st_nlink - 1);
            }
            if (dirent_type == DT_REG && dirent_sb.st_size == 0) DS.NZeroFiles += 1;
         }
      }

      // @@@ ACTION (dirent): Quietly skip files that are not selected ...
      if (SELECT_HARDCODED && !selected(RelPathName, &dirent_sb)) continue;

      // Cheap-to-keep WS stats ...
      if (dirent_sb.st_ino > WS[w_id]->MAX_inode_Value_Selected)
         WS[w_id]->MAX_inode_Value_Selected = dirent_sb.st_ino;

      // @@@ ACTION (dirent): -rm selected() non-directories only unless -dryrun ...
      // NOTE: The .sh files created by -rm would NOT be safely executable, because a failed 'cd'
      // command would make the following 'rm' commands invalid -- so we output the return code
      // from each unlink() operation before the 'rm' to make the .sh files not directly executable.
      if (Cmd_RM && selected(FileName, &dirent_sb)) {	// klooge: we're only here cuz we're selected()!
         rm_path_hits += 1;				// Want to delete this one
         rm_rc_str[0] = '0'; rm_rc_str[1] = '\0';	// Assume no error
         if (PWdryrun) {
            rm_rc_str[0] = '#';				// Dryrun indicator
         } else {		// rm the file!
            // Only flag option is AT_REMOVEDIR, which we do not need here ...
            // NOTE: dfd already incorporates multipath logic ...
            rc = unlinkat(dfd, FileName, 0);
            if (rc) {
               assert(strerror_r(errno, errstr, sizeof(errstr)) == 0);
               WS[w_id]->NWarnings += 1;
               sprintf(emsg, "WARNING: In \"%s\", cannot -rm \"%s\" (%s)\n",
                  RelPathName, FileName, errstr);
               sprintf(rm_rc_str, "%d", rc);
            } else {
               WS[w_id]->NRemoved += 1;			// Successful -rm
            }
         }
         if (!PWquiet) {
            if (rm_path_hits == 1) fprintf(WLOG, "@ cd \"%s\"\n", AbsPathDir);
            fprintf(WLOG, "%s rm \"%s\"\n", rm_rc_str, FileName);
         }
      }

      // @@@ GATHER (dirent): Fetch and process file ACL ...
#if defined(__ONEFS__)
      acl_present = (dirent_sb.st_flags & SF_HASNTFSACL);
#else
      acl_present = 0;	// It's a flag on OneFS, but another metadata call elsewhere (for later)
#endif
#if PWALK_ACLS // Linux ACL-related logic for a <file> ....
      ns_getacl_s[0]='\0';
      acl4.n_aces = 0;
      if (acl_supported && (P_ACL_P || Cmd_XACLS || Cmd_WACLS)) {
         assert(have_stat);		// klooge: primitive insurance
         // INPUT & TRANSLATE: Translate POSIX ACL plus DACL to a single ACL4 ...
         pw_acl4_get_from_posix_acls(AbsPathName, S_ISDIR(dirent_sb.st_mode), &aclstat, &acl4, pw_acls_emsg, &pw_acls_errno);
         if (PWdebug > 2) fprintf(Plog, "$ AbsPathName=\"%s\" aclstat=%d pw_acls_errno=%d\n", AbsPathName, aclstat, pw_acls_errno);
         if (Opt_TSTAT) { t2 = gethrtime(); ns_getacl = t2 - t1; sprintf(ns_getacl_s," (%lldus) ", ns_getacl/1000); }
         if (pw_acls_errno) {
            DS.NWarnings += 1;
            if (Cmd_XML) {
               fprintf(WLOG, "<warning> \"%s\": %s (rc=%d) %s </warning>\n",
                  AbsPathName, pw_acls_emsg, pw_acls_errno, strerror(pw_acls_errno));
            } else {
               fprintf(WERR, "WARNING: \"%s\": %s [%d - \"%s\"]\n",
                  AbsPathName, pw_acls_emsg, pw_acls_errno, strerror(pw_acls_errno));
            }
            continue;
         }
         if (aclstat) {
            acl_present = TRUE;
            if (!S_ISDIR(dirent_sb.st_mode)) DS.NACLs += 1;
         } else strcat(mode_str, ".");
      }
#endif // PWALK_ACLS
      if (acl_present && Opt_MODE && P_ACL_P) strcat(mode_str, "+");	// Actually only works in OneFS?

      // @@@ GATHER (dirent): Accumulate f/d/s/o counts ... and PUSH newly-discovered directories ...
      if (S_ISREG(dirent_sb.st_mode)) {		// ordinary
         DS.NFiles += 1;
      } else if (S_ISDIR(dirent_sb.st_mode)) {	// directory ... push?
         DS.NDirs += 1;

         // NOTE: If we are 'fixing' ACLs, we need to fix directory ACLs BEFORE they are PUSH'ed!
         // NOTE: At (depth == 0), we will assume the directory ACLs are to be preserved.
         // As soon as we PUSH this directory, some other worker may POP it, and it will not
         // do ACL inheritance operations correctly if we have not fixed the directory's ACL first.
         //onefs_acl_inherit(CurrentDirectoryACL, -1, RelPathName, isdir, depth);	// ##### klooge INCOMPLETE
         if (!Opt_SPAN && (dirent_sb.st_dev != curdir_sb.st_dev)) {	// +span enforcement
            fprintf(WERR, "NOTICE: Skipping reference outside filesystem @ \"%s\"\n", AbsPathDir);
         } else {
            fifo_push(RelPathName, &dirent_sb, w_id);
         }
      } else if (S_ISLNK(dirent_sb.st_mode)) {	// symlink
         DS.NSymlinks += 1;
      } else {					// other
         DS.NOthers += 1;
      }

      // NOTE: To avoid multiple-counting, we only count the nominal directory sizes ONCE; when we pop them.
      // However, directory output lines will reflect the sizes reported by stat().
      if (!S_ISDIR(dirent_sb.st_mode)) {
         DS.NBytesNominal += dirent_sb.st_size;
         DS.NBytesAllocated += bytes_allocated = dirent_sb.st_blocks * ST_BLOCK_SIZE;
      }

      // @@@ GATHER (dirent): Owner name & group name ...
      get_owner_group(&dirent_sb, owner_name, group_name, owner_sid, group_sid);

      // @@@ GATHER (dirent): '+tally' accumulation ...
      if (Cmd_TALLY)
         pwalk_tally_file(&dirent_sb, w_id);

      // @@@ READONLY (BEGIN): READONLY operations (+crc, +md5, +denist, etc) @@@
      // open() file READONLY if we need to read file or get a file handle to query.
      // For OneFS PWget_SD, we must open each file|dir to get its security_descriptor.
      // For OneFS +rm_acls  we must open each file|dir to get&set its security_descriptor.
      // For +crc, +md5, and +denist, we must only open each non-zero-length ordinary file.
      // Multiple purposes will be served from the open file handle.
      openit = (Cmd_RM_ACLS || (PWget_MASK & PWget_SD));			// MUST open!
      crc_val = md5_val = 0;
      if ((dirent_type == DT_REG) && (Cmd_DENIST || P_CRC32 || P_MD5)) {	// MIGHT open ...
          if (dirent_sb.st_size == 0) WS[w_id]->READONLY_Zero_Files += 1;
         else openit = 1;
      }
      if (!openit) goto outputs;

      // We do NOT follow links, ever ...
      // NOTE: OneFS has O_OPENLINK to explcitly permit opening a symlink!
      if ((fd = openat(SOURCE_DFD(w_id), RelPathName, O_RDONLY|O_NOFOLLOW|O_OPENLINK, 0)) < 0) {
         WS[w_id]->READONLY_Errors += 1;
         assert(strerror_r(errno, errstr, sizeof(errstr)) == 0);
         fprintf(WERR, "ERROR: Cannot READONLY open() \"%s\" (%s)\n", AbsPathName, errstr);
         goto outputs;
      }

      // @@@ READONLY file is now open ...
      WS[w_id]->READONLY_Opens += 1;

      // @@@ READONLY +denist ...
      if (Cmd_DENIST) {						// This is ALL that +denist does!
         nbytes = pread(fd, &rbuf, 128, 0);
         if (nbytes > 0) WS[w_id]->READONLY_DENIST_Bytes += nbytes;
         else WS[w_id]->READONLY_Errors += 1;
      }

      // @@@ READONLY +crc & +md5 ...
      if (P_CRC32 || P_MD5) {		// klooge: need f() to do CRC32 and MD5 in single pass!
         nbytes = crc32(fd, (void *) rbuf, sizeof(rbuf), &crc_val);
         if (nbytes > 0) WS[w_id]->READONLY_CRC_Bytes += nbytes;
         // Cross-check that we read all bytes of the file ...
         // ==== if (nbytes != dirent_sb.st_size) WS[w_id]->READONLY_Errors += 1;	// === Add error!
      }
#if defined(__ONEFS__)
      // @@@ READONLY (OneFS) +rm_acls ...
      if (Cmd_RM_ACLS && !PWdryrun) {
         rc = onefs_rm_acls(fd, RelPathName, &dirent_sb, (char *) &rc_msg);
         // klooge: add counters for ACLs modified or removed (rc == 1 or 2, respectively)
         if (rc < 0) {
            WS[w_id]->NWarnings += 1;
            fprintf(WERR, "WARNING: onefs_rm_acls(\"%s\") for \"%s\"\n", rc_msg, RelPathName);
         } else if (rc > 0) {
            WS[w_id]->NACLs += 1;
         }
      }

      // @@@ READONLY (OneFS) get SIDs ...
      if (PWget_MASK & PWget_SD) {
         onefs_get_sids(fd, owner_sid, group_sid);
         if (VERBOSE > 2) fprintf(stderr, "< %s %s >\n", owner_sid, group_sid);
      }
#endif
      // @@@ READONLY (dirent): END READONLY operations and close() file ...
      close(fd);	// klooge: SHOULD check rc, but WTF, it's READONLY

      // @@@ OUTPUT (dirent): Per-child information & added processing @@@
outputs:
      // NOTE: mode_str will be empty string when '-pmode' option is used
      // NOTE: ns_stat_s will be empty string unless '+pstat' option is used
      // NOTE: ns_getacl_s will be empty string unless '+pstat' option is used
      // NOTE: stat() data may not be available with Cmd_AUDIT if FASTSCAN is implemented

      // NOTE: crc_str will be empty if +crc not specified
      if (P_CRC32) sprintf(crc_str, " crc=0x%x", crc_val); else crc_str[0] = '\0';

      // ... EXPERIMENTAL; on OneFS only (NFS clients may not convey birthtime)
#if defined(BIRTHTIME_CODE)
//    struct timespec st_atimespec;  /* time of last access */
//    struct timespec st_mtimespec;  /* time of last data modification */
//    struct timespec st_ctimespec;  /* time of last file status change */
//    struct timespec st_birthtimespec;  /* time of file creation */
      fprintf(WLOG, "<file>%s%s %lld %s%s b=%lu c=%lu a=%lu m=%lu%s </file>\n",
         (PMODE ? " " : ""), mode_str, (long long) dirent_sb.st_size, FileName, ns_stat_s,
         UL(dirent_sb.st_birthtime), UL(dirent_sb.st_ctime), UL(dirent_sb.st_atime), UL(dirent_sb.st_mtime),
         (UL(dirent_sb.st_birthtime) != UL(dirent_sb.st_ctime)) ? " NOTE: B!=C" : ""
         );
      //    (UL(dirent_sb.st_mtime) != UL(dirent_sb.st_ctime)) ? " NOTE: M!=C" : ""
#endif

      // @@@ OUTPUT (dirent): Mutually-exclusive primary modes ...
      if (Cmd_LSD || (SELECT_HARDCODED && !selected(FileName, &dirent_sb))) {	// No per-file output!
         ;
      } else if (Cmd_LS) {		// -ls
         fprintf(WLOG, "%s %u %lld %s%s%s\n",
            (Opt_MODE ? mode_str : ""), dirent_sb.st_nlink, (long long) dirent_sb.st_size, REDACT_FileName, ns_stat_s, crc_str);
      } else if (Cmd_LSC) {		// -lsc
         if (!S_ISDIR(dirent_sb.st_mode)) {
            if (Opt_REDACT) fprintf(WLOG, "%c %s\n", mode_str[0], REDACT_FileName);
            else            fprintf(WLOG, "%c %llu %s\n", mode_str[0], dirent_sb.st_ino, FileName);
         }
      } else if (Cmd_XML) {		// -xml
         fprintf(WLOG, "<file> %s %u %lld %s%s%s </file>\n",
            (Opt_MODE ? mode_str : ""), dirent_sb.st_nlink, (long long) dirent_sb.st_size, REDACT_FileName, ns_stat_s, crc_str);
      } else if (Cmd_CMP) {		// -cmp
         if (cmp_target_dir_exists)
            cmp_source_target(w_id, RelPathName, &dirent_sb, cmp_file_result_str);
         else // File CANNOT exist!
            strcpy(cmp_file_result_str, "E");
         if (strcmp(cmp_file_result_str, "-")) {	// Only report differences
            if (!cmp_dir_reported) {			// If we deferred reporting directory, do it now
               if (ftell(WDAT.wlog)) fprintf(WLOG, "\n");	// blank line before each new directory
               fprintf(WLOG, "@ %s %s\n", cmp_dir_result_str, RelPathDir);
               cmp_dir_reported = TRUE;
            }
            fprintf(WLOG, "%c %s %s\n", mode_str[0], cmp_file_result_str, FileName);
         }
      } else if (Cmd_AUDIT) {		// -audit
#if PWALK_AUDIT // OneFS only
         pwalk_audit_file(RelPathName, &dirent_sb, crc_val, w_id);
#else
         abend("-audit not supported");
#endif // PWALK_AUDIT
      } else if (Cmd_FIXTIMES) {	// -fixtimes
         pwalk_fix_times(FileName, RelPathName, &dirent_sb, w_id);
      } else if (Cmd_CSV) {		// -csv= (DEVELOPMENTAL: Temporary placeholder code)
         if (SELECT_HARDCODED) {
            fprintf(WLOG, "\"%s\"\n", RelPathName);
         } else {			// klooge: SHOULD BE call to reporting module
            fprintf(WLOG, "%u,%s,%s,%u,%s,%s,\"%s\"\n",
               dirent_sb.st_uid, owner_name, owner_sid, dirent_sb.st_gid, group_name, group_sid, RelPathName);
         }
      }

      // @@@ OUTPUT (dirent): ... @@@

#if PWALK_ACLS // Linux-only ACL-related outputs ...
      // @@@ ... +wacls & +xacls ACL4 outputs (all are no-ops with an empty acl4) ...
      if (acl4.n_aces) {
         if (Cmd_WACLS) {
            if (!WDAT.WACLS_PIPE) ; // === in-process
            pw_acl4_fwrite_binary(&acl4, RelPathName, &(WDAT.WACLS_PIPE), acl4OUTmode, pw_acls_emsg, &pw_acls_errno);
         }
         if (Cmd_XACLS & Cmd_XACLS_BIN) {
            if (!WDAT.XACLS_BIN_FILE) worker_aux_create(w_id, &(WDAT.XACLS_BIN_FILE), "acl4bin");
            pw_acl4_fwrite_binary(&acl4, RelPathName, &(WDAT.XACLS_BIN_FILE), acl4OUTmode, pw_acls_emsg, &pw_acls_errno);
         }
         if (Cmd_XACLS & Cmd_XACLS_CHEX) {
            if (!WDAT.XACLS_CHEX_FILE) worker_aux_create(w_id, &(WDAT.XACLS_CHEX_FILE), "acl4chex");
            pw_acl4_fprintf_chex(&acl4, RelPathName, &dirent_sb, WDAT.XACLS_CHEX_FILE);
         }
         if (Cmd_XACLS & Cmd_XACLS_NFS) {
            if (!WDAT.XACLS_NFS_FILE) worker_aux_create(w_id, &(WDAT.XACLS_NFS_FILE), "acl4nfs");
            pw_acl4_fprintf_nfs4_setfacl(&acl4, RelPathName, WDAT.XACLS_NFS_FILE);
         }
         if (Cmd_XACLS & Cmd_XACLS_ONEFS) {
            if (!WDAT.XACLS_ONEFS_FILE) worker_aux_create(w_id, &(WDAT.XACLS_ONEFS_FILE), "acl4onefs");
            pw_acl4_fprintf_onefs(&acl4, RelPathName, &dirent_sb, WDAT.XACLS_ONEFS_FILE);
         }
      }
#endif // PWALK_ACLS
   }

exit_scan:
   // @@@ DIRECTORY SCAN LOOP (end): Subtotals & such ...
   if (dir != NULL) {
      rc = closedir(dir);
      if (VERBOSE > 2) { fprintf(WLOG, "@closedir rc=%d\n", rc); fflush(WLOG); }

      // @@@ MATH (parent exit): Aggregate per-directory statistics (DS) to per-worker statistics (WS[w_id]) ...
      // NOTE: Before pwalk exists, it will sum all per-worker statistics to form its global statistics (GS).
      WS[w_id]->NStatCalls += DS.NStatCalls;
      WS[w_id]->NStatErrors += DS.NStatErrors;
      WS[w_id]->NFiles += DS.NFiles;
      WS[w_id]->NDirs += DS.NDirs;
      WS[w_id]->NSymlinks += DS.NSymlinks;
      WS[w_id]->NOthers += DS.NOthers;
      WS[w_id]->NBytesAllocated += DS.NBytesAllocated;
      WS[w_id]->NBytesNominal += DS.NBytesNominal;
      WS[w_id]->NACLs += DS.NACLs;
      WS[w_id]->NZeroFiles += DS.NZeroFiles;
      WS[w_id]->NHardLinkFiles += DS.NHardLinkFiles;
      WS[w_id]->NHardLinks += DS.NHardLinks;

      // @@@ OUTPUT (parent exit): End-of-directory outputs ...
      if (Cmd_XML) {
         fprintf(WLOG, "<summary> f=%llu d=%llu s=%llu o=%llu errs=%llu space=%llu size=%lld </summary>\n",
            DS.NFiles, DS.NDirs, DS.NSymlinks, DS.NOthers, DS.NStatErrors, DS.NBytesAllocated, DS.NBytesNominal);
         fprintf(WLOG, "</directory>\n");
      } else if (Cmd_LS || Cmd_LSD) {
         fprintf(WLOG, "S: f=%llu d=%llu s=%lld o=%llu z=%llu space=%llu size=%llu errs=%llu\n",
            DS.NFiles, DS.NDirs, DS.NSymlinks, DS.NOthers,
            DS.NZeroFiles, DS.NBytesAllocated, DS.NBytesNominal, DS.NStatErrors);
      } else if (Cmd_LSC) {
         fprintf(WLOG, "S: f=%llu d=%llu s=%lld o=%llu z=%llu space=%llu size=%llu errs=%llu\n",
            DS.NFiles, DS.NDirs, DS.NSymlinks, DS.NOthers,
            DS.NZeroFiles, DS.NBytesAllocated, DS.NBytesNominal, DS.NStatErrors);
      }
   }
   fflush(WLOG);	// Flush worker's output at end of each directory ...
   LogMsg(NULL, 1);	// ... also force main pwalk.log flush with possible progress report
}	// +++++ BREAK UP THIS SPAGHETTI CODE: END @@@

// @@@ SECTION: Top-level pwalk logic & main() @@@

// check_maxfiles() - Spot check max open file limit

void
check_maxfiles(void)
{
   struct rlimit rlimit;

   // APPROXIMATION of what we may need for concurrently-open files ...
   //
   // Persistent + per-worker ...
   //	1 - .log file
   //	2 - .fifo (push and pop handles)
   //	3 - stdin, stdout, stderr
   //   N_WORKERS - .err
   //	N_WORKERS – Primary output (.ls, .xml, .audit, .cmp, .fix, .out) - iff primary mode given
   //   N_WORKERS - READONLY file operations
   //   N_WORKERS - current directory
   //	N_SOURCE_PATHS - for relative root handle
   //   N_TARGET_PATHS - for relative root handle
   // With +tally -> (Cmd_TALLY ? 1 : 0)
   // With -audit -> (Cmd_AUDIT ? N_WORKERS : 0) - for Python IPC pipes
   // With ACL options -> (==== : 4*N_WORKERS : 0)

   // How many files are we allowed?
   assert (getrlimit(RLIMIT_NOFILE, &rlimit) == 0);

   // What might we need?
   MAX_OPEN_FILES = 1 + 2 + 3 + 4*N_WORKERS + N_SOURCE_PATHS + N_TARGET_PATHS
	+ (Cmd_TALLY ? 1 : 0)
	+ (Cmd_AUDIT ? N_WORKERS : 0)
        + (Cmd_WACLS ? N_WORKERS : 0)
        + (Cmd_XACLS & Cmd_XACLS_BIN ? N_WORKERS : 0)
        + (Cmd_XACLS & Cmd_XACLS_CHEX ? N_WORKERS : 0)
        + (Cmd_XACLS & Cmd_XACLS_NFS ? N_WORKERS : 0)
        + (Cmd_XACLS & Cmd_XACLS_ONEFS ? N_WORKERS : 0);

   // Do we have enough?
   if (MAX_OPEN_FILES <= rlimit.rlim_cur) return;	// No worries!

   // Can we get enough?
   if (MAX_OPEN_FILES > rlimit.rlim_max) {		// No way!
      fprintf(Plog, "ERROR: MAX_OPEN_FILES (%d) > RLIMIT_NOFILE rlim_max (%llu)\n",
         MAX_OPEN_FILES, rlimit.rlim_max);
      exit(-1);
   }

   // Can we increase our limit?
   // DEBUG: fprintf(Plog, "NOTICE: setrlimit %llu / %d / %llu\n", rlimit.rlim_cur, MAX_OPEN_FILES, rlimit.rlim_max);
   rlimit.rlim_cur = MAX_OPEN_FILES;
   if (setrlimit(RLIMIT_NOFILE, &rlimit)) {		// Nope!
      fprintf(Plog, "ERROR: Not enough file handles! (MAX_OPEN_FILES=%d)\n", MAX_OPEN_FILES);
      exit(-1);
   }
}

// arg_count_ch() - helper function for -vvv, -dddd, etc - returns VERBOSE or DEBUG level based
// on repeated characters.  Returns -1 on any error.  Expectation is that passed-in string arg
// will be all the same letter, iterated.

int
arg_count_ch(char *arg, char ch)
{
   char *p;
   int count = 0;

   assert (arg[0] == '-');
   for (p = arg+1; *p; p++)
      if (*p == ch) count += 1;
      else return (-1);
   return (count);
}

// @@@ SECTION: Command-line argument processing @@@

// get_since_time() - Process -since=<path> argument ...
// klooge: This is a temporary hack to get a parameter into selected().

void
get_since_time(char *pathname)
{
   struct stat sb;
   int rc;

   assert(stat(pathname, &sb) == 0);		// klooge: crude
   SELECT_T_SINCE = sb.st_mtimespec.tv_sec;
}

// process_arglist() - Process command-line options w/ rudimentary error-checking.
// Errors log to stderr; there's no WLOG stream yet.

void
process_arglist(int argc, char *argv[])
{
   char *arg, *p;
   char msg[256];
   int i, narg, nc, nmodes, badarg = FALSE;
   enum { none, relative, absolute } path_mode, dirarg_mode = none;
   int dirarg_count = 0;

   if (argc < 2) usage();
   for (narg=1; narg < argc; narg++) {
      arg = argv[narg];
      if (sscanf(arg, "-dop=%d", &N_WORKERS) == 1) {
         if (N_WORKERS > MAX_WORKERS)
            { fprintf(stderr, "ERROR: Exceeded MAX_WORKERS=%d with -dop= argument!\n", MAX_WORKERS); exit(-1); }
      } else if (strncmp(arg, "-pfile=", strlen("-pfile=")) == 0) {
         parse_pfile(arg+strlen("-pfile="));
      } else if (strncmp(arg, "-source=", strlen("-source=")) == 0) {
         SOURCE_ARG = malloc(strlen(arg));
         strcpy(SOURCE_ARG, arg+strlen("-source="));
      } else if (strncmp(arg, "-target=", strlen("-target=")) == 0) {
         TARGET_ARG = malloc(strlen(arg));
         strcpy(TARGET_ARG, arg+strlen("-target="));
      } else if (strncmp(arg, "-output=", strlen("-output=")) == 0) {
         OUTPUT_ARG = malloc(strlen(arg));
         strcpy(OUTPUT_ARG, arg+strlen("-output="));
#if PWALK_AUDIT // OneFS only
      } else if (strcmp(arg, "-audit") == 0) {		// Special modes ...
         Cmd_AUDIT = 1;
         assert((PYTHON_COMMAND = malloc(strlen(argv[0]) + 32)) != NULL);
         // Test that Python script is readable in same directory as pwalk binary ...
         sprintf(PYTHON_COMMAND, "%s_python.py", argv[0]);
         if (eaccess(PYTHON_COMMAND, R_OK) != 0)
            abend("Cannot read pwalk_python.py file!");
         // Calculate full command ...
         sprintf(PYTHON_COMMAND, "/usr/bin/python %s_python.py", argv[0]);
#endif // PWALK_AUDIT
      } else if (strcmp(arg, "-ls") == 0) {		// Generic primary modes ...
         Cmd_LS = 1;
      } else if (strcmp(arg, "-lsd") == 0) {
         Cmd_LSD = 1;
      } else if (strcmp(arg, "-lsc") == 0 || strcmp(arg, "-lsc") == 0) {
         Cmd_LSC = 1;
      } else if (strcmp(arg, "-xml") == 0) {
         Cmd_XML = 1;
      } else if (strcmp(arg, "-cmp") == 0 || strncmp(arg, "-cmp=", 5) == 0) {
         if (strncmp(arg, "-cmp=", 5) == 0) cmp_arg_parse(arg+5);
         Cmd_CMP = 1;
      } else if (strcmp(arg, "-fix_times") == 0 || strcmp(arg, "-fix-times") == 0) {
         Cmd_FIXTIMES = 1;
      } else if (strcmp(arg, "-rm") == 0) {
         Cmd_RM = 1;
      } else if (strcmp(arg, "-trash") == 0) {
         Cmd_TRASH = 1;
         assert("-trash primary mode not-yet implemented" == NULL);
         exit(-42);
      } else if (strncmp(arg, "-csv=", 5) == 0) {	// DEVELOPMENTAL ====
         csv_pfile_parse(arg+5);
         Cmd_CSV = 1;
      } else if (strcmp(arg, "+denist") == 0) {
         Cmd_DENIST = 1;
#if defined(__ONEFS__)	// OneFS only features
      } else if (strcmp(arg, "+rm_acls") == 0) {
         Cmd_RM_ACLS = 1;
#endif
      } else if ((strcmp(arg, "+tally") == 0) || (strncmp(arg, "+tally=", 7) == 0) ) {
         Cmd_TALLY = 1;
         if (strlen(arg) > 7) TALLY_TAG = arg + 7;	// <tag> modifier for +tally
#if PWALK_ACLS // ACL-related command args (Linux only) ...
      } else if (strncmp(arg, "+wacls=", 7) == 0) {	// Write binary NFS4 ACLS over a pipe ...
         Cmd_WACLS = 1;
         WACLS_CMD = malloc(strlen(arg));		// klooge: could add some kind of load balancing here
         strcpy(WACLS_CMD, arg+7);
      } else if (strcmp(arg, "+xacls=bin") == 0) {	// eXtract NFS4 ACLS ... bin ...
         Cmd_XACLS |= Cmd_XACLS_BIN;
      } else if (strcmp(arg, "+xacls=chex") == 0) {	// eXtract NFS4 ACLS ... chex ...
         Cmd_XACLS |= Cmd_XACLS_CHEX;
      } else if (strcmp(arg, "+xacls=nfs") == 0) {	// eXtract NFS4 ACLS ... nfs ...
         Cmd_XACLS |= Cmd_XACLS_NFS;
      } else if (strcmp(arg, "+xacls=onefs") == 0) {	// eXtract NFS4 ACLS ... onefs ...
         Cmd_XACLS |= Cmd_XACLS_ONEFS;
#endif // PWALK_ACLS
      } else if (strcmp(arg, "+acls") == 0) {		// showing ACL presence (ie: with '+')
         P_ACL_P = TRUE;
      } else if (strcmp(arg, "+crc") == 0) {		// Tag-along modes ...
         P_CRC32 = 1;
      } else if (strcmp(arg, "-select") == 0) {		// klooge: hard-coded -select criteria
         SELECT_HARDCODED = 1;
#if defined(__ONEFS__)
      } else if (strcmp(arg, "-select=fake") == 0) {	// Only on OneFS native!
         SELECT_FAKE = 1;
#endif // __ONEFS__
      } else if (strncmp(arg, "-since=", 7) == 0) {	// klooge: for INTERIM selected() logic
         SELECT_SINCE = 1;
         get_since_time(arg+7);
      } else if (strcmp(arg, "+.snapshot") == 0) {	// also traverse .snapshot[s] directories
         Opt_SKIPSNAPS = 0;
      } else if (strcmp(arg, "+span") == 0) {		// include dirs that cross filesystems
         Opt_SPAN = 1;
      } else if (strcmp(arg, "+tstat") == 0) {		// also add timed stats
         Opt_TSTAT = 1;
      } else if (strcmp(arg, "-gz") == 0) {
         Opt_GZ = 1;
      } else if (strcmp(arg, "-redact") == 0) {
         Opt_REDACT = 1;
      } else if (strcmp(arg, "-pmode") == 0) {
         Opt_MODE = 0;
      } else if (strcmp(arg, "-bs=512") == 0) {
         ST_BLOCK_SIZE = 512;
      } else if (strcmp(arg, "-dryrun") == 0) {		// Modifiers ...
         PWdryrun = 1;
      } else if (strcmp(arg, "-q") == 0) {		// Quiet ...
         PWquiet += 1;
      } else if (strncmp(arg, "-v", 2) == 0) {		// Verbosity ...
         if ((nc = arg_count_ch(arg, 'v')) < 1) {
            fprintf(stderr, "ERROR: \"%s\" - unknown option!\n", arg); exit(-1);
         } 
         VERBOSE += nc;
         fprintf(stderr, "DEBUG: VERBOSE=%d\n", VERBOSE);
      } else if (strncmp(arg, "-d", 2) == 0) {		// Debug ...
         if ((nc = arg_count_ch(arg, 'd')) < 1) {
            fprintf(stderr, "ERROR: \"%s\" - unknown option!\n", arg); exit(-1);
         } 
         PWdebug += nc;
         fprintf(stderr, "DEBUG: PWdebug=%d\n", PWdebug);
      } else if (*arg == '-' || *arg == '+') {		// Unknown +/- option ...
         fprintf(stderr, "ERROR: \"%s\" option unknown!\n", arg);
         exit(-1);
      } else { 		// Everything else assumed to be a <directory> arg ...
         dirarg_count += 1;
         if (PWdebug) fprintf(Plog, "DEBUG: directory[%d] = \"%s\"\n", dirarg_count, arg);
         // NOTE: our FIFO is only created AFTER all args are validated, so we can't push these yet!
         // Enforce that all <directory> args *must* either be absolute or relative ...
         path_mode = (*arg == PATHSEPCHR) ? absolute : relative;
         if (dirarg_mode == none) {
            dirarg_mode = path_mode; 
         } else if (path_mode != dirarg_mode) {
            fprintf(Plog, "ERROR: <directory> args must consistently be either absolute or relative!\n");
            exit(-1);
         }
      }
      if (PWdebug) fprintf(stderr, "DEBUG: argv[%d] = \"%s\"\n", narg, arg);
   }

   // @@@ Argument sanity checks @@@

   // @@@ ... Enforce mutual exclusion of PRIMARY modes ...
   nmodes  = Cmd_LS;
   nmodes += Cmd_LSD;
   nmodes += Cmd_LSC;
   nmodes += Cmd_XML;
   nmodes += Cmd_CSV;
   nmodes += Cmd_CMP;
   nmodes += Cmd_RM;
   nmodes += Cmd_TRASH;
   nmodes += Cmd_FIXTIMES;
   nmodes += Cmd_AUDIT;
   if (nmodes > 1) {
      p = "ls|lsd|lsc|xml|csv|cmp|rm|trash|fix_times|audit"; // Mutually Exclusive options
      fprintf(Plog, "ERROR: Only one PRIMARY mode (%s) can be specified!\n", p);
      exit(-1);
   }

   // @@@ ... Enforce that we MUST have at least one PRIMARY or SECONDARY mode specified ...
   nmodes += Cmd_DENIST;
   nmodes += Cmd_TALLY;
   nmodes += Cmd_XACLS;
   nmodes += Cmd_WACLS;
   nmodes += Cmd_RM_ACLS;
   if (nmodes < 1) {
      fprintf(Plog, "ERROR: No PRIMARY or SECONDARY modes specified; nothing to do!\n");
      exit(-1);
   }

   // @@@ ... Resolve all multipath-related restrictions and related sanity checks ...
   ABSPATH_MODE = (dirarg_mode == absolute);		// GLOBALize the dirarg mode ...
   // fprintf(Plog, "* ABSPATH_MODE=%s\n", ABSPATH_MODE ? "True" : "False");

   // When <directory> args are absolute, source and target paths cannot be specified!
   if (ABSPATH_MODE) {
      if (N_SOURCE_PATHS > 0 || N_TARGET_PATHS > 0 || SOURCE_ARG || TARGET_ARG) {
         fprintf(Plog, "ERROR: Cannot use -source= or -target= with absolute <directory> arguments!\n");
         exit(-1);
      } else {
         SOURCE_ARG = PATHSEPSTR;	// root ('/') is the implicit -source= parameter in absolute mode
      }
   }

   // Apply -source= parameter if -pfile= [source] does not conflict ...
   if (SOURCE_ARG) {
      if (N_SOURCE_PATHS > 0) {
         fprintf(Plog, "ERROR: Cannot specify both -source= and -pfile== [source] paths!\n");
         exit(-1);
      } else {
         SOURCE_PATHS[0] = SOURCE_ARG;	// Either implied "/" or -source= arg
         N_SOURCE_PATHS = 1;
      }
   }

   // Iff no -source= or -pfile== [source] paths specified, default to CWD (".") ...
   if (N_SOURCE_PATHS < 1) {	
      SOURCE_PATHS[0] = ".";
      N_SOURCE_PATHS = 1;
   }

   // Apply -target= parameter if -pfile== does not conflict ...
   if (TARGET_ARG) {
      if (N_TARGET_PATHS > 0) {
         fprintf(Plog, "ERROR: Cannot specify both -target= and -pfile== [target] paths!\n");
         exit(-1);
      } else {
         TARGET_PATHS[0] = TARGET_ARG;
         N_TARGET_PATHS = 1;
      }
   }

   if (Cmd_CMP && (N_TARGET_PATHS < 1)) {
      fprintf(Plog, "ERROR: '-cmp' requires '-target=' or [target] paths from '-pfile='!\n");
      exit(-1);
   }

   if (N_TARGET_PATHS > 0 && !(Cmd_CMP || Cmd_FIXTIMES)) {
      fprintf(Plog, "ERROR: '-target=' or -pfile= [target] only allowed with -cmp, -trash, and -fix_times!\n");
      exit(-1);
   }

   // @@@ ... Check if we'll be able to open all the files we may need ...
   // NOTE: This check MUST follow -pfile= parsing, but before multipaths are opened.
   check_maxfiles();

   // @@@ ... Establish multi-path SOURCE and TARGET relative-root DFD's & related sanity checks @@@
   //     ... BIG MOMENT HERE: Open all the source and target root paths, or die trying!
   for (i=0; i<N_SOURCE_PATHS; i++)
      setup_root_path(&SOURCE_PATHS[i], &SOURCE_DFDS[i], &SOURCE_INODES[i]);	// exits on failure!
   for (i=0; i<N_TARGET_PATHS; i++)
      setup_root_path(&TARGET_PATHS[i], &TARGET_DFDS[i], &TARGET_INODES[i]);	// exits on failure!

   // ... Sanity check all equivalent paths must resolve to same inode number ...
   // ... as they will when they all represent mounts of the same remote directory.  When mount points are
   // NOT mounted, they will return distinct inode numbers from the host system.
   if (N_SOURCE_PATHS > 1)		// must all point to same place!
      for (i=1; i<N_SOURCE_PATHS; i++)
         if (SOURCE_INODES[i] != SOURCE_INODES[0])
            { fprintf(Plog, "ERROR: Not all source paths represent same inode! Check mounts?\n"); exit(-1); }

   if (N_TARGET_PATHS > 1)		// 'equivalent' paths must actually all point to same place!
      for (i=1; i<N_TARGET_PATHS; i++)
         if (TARGET_INODES[i] != TARGET_INODES[0])
            { fprintf(Plog, "ERROR: Not all target paths represent same inode! Check mounts?\n"); exit(-1); }

   if ((N_TARGET_PATHS > 0) && (TARGET_INODES[0] == SOURCE_INODES[0]))
         { fprintf(Plog, "ERROR: source and target paths cannot point to the same place!\n"); exit(-1); }

   // @@@ ... Other argument sanity checks ...

   if (N_WORKERS < 0 || N_WORKERS > MAX_WORKERS) {
      fprintf(Plog, "ERROR: -dop=<N> must be on the range [1 .. %d]!\n", MAX_WORKERS);
      badarg = TRUE;
   }

   if (!SELECT_HARDCODED && SELECT_T_SINCE != 0) {		// klooge: '-since=' is TEMPORARY code
      fprintf(Plog, "ERROR: -since=<file> requires -select option!\n");
      badarg = TRUE;
   }

   if (N_WORKERS < 0 || N_WORKERS > MAX_WORKERS) {
      fprintf(Plog, "ERROR: -dop=<N> must be on the range [1 .. %d]!\n", MAX_WORKERS);
      badarg = TRUE;
   }

   if (Cmd_WACLS && (strlen(WACLS_CMD) < 5)) {	// crude and arbitrary
      fprintf(Plog, "ERROR: '+wacls=' requires '<command>' value!\n");
      badarg = TRUE;
   }

   if (badarg)
      exit(-1);
}

// @@@ main() ... @@@

int
main(int argc, char *argv[])
{
   int i, w_id;
   int rc;
   char *emsg;
   // Statistics ...
   double t_elapsed_sec;
   char ebuf[64], s64[64], *str;
   struct rusage p_usage, c_usage;
   struct tms cpu_usage;
   struct utsname uts;
   struct rlimit rlimit;
   int dirarg_count = 0;	// Default to "." if none on command line
   int exit_status = 0;		// Succeed by default
   sigset_t sigmask;

   unsigned nw_busy;
   count_64 fifo_depth;

   // ------------------------------------------------------------------------

   // Globalize UID and GID values ...
   USER.uid = getuid();
   USER.euid = geteuid();
   USER.gid = getgid();
   USER.egid = getegid();

   // Die quickly if not using 64-bit file offsets!
   assert ( sizeof(GS.NBytesAllocated) == 8 );

   // Allow only selected signals ...
   //==== sigemptyset(&sigmask);
   //==== sigaddset(&sigmask, SIGBUS);
   //==== sigaddset(&sigmask, SIGSEGV);
   //==== assert(sigprocmask(SIG_SETMASK, &sigmask, NULL) == 0);

   // Default Plog output to stderr, flushing on newlines. We'll replace this with
   // a shared buffered log stream after our output directory is created.
   Plog = fopen("/dev/stderr", "a");
   setvbuf(Plog, NULL, _IOLBF, 8192);

#if defined(__LINUX__)
   // Get CLK_TIC (when not #defined) ...
   CLK_TCK = sysconf(_SC_CLK_TCK);
#endif

   // Take note of our default directory ...
#if defined(SOLARIS) || defined(__LINUX__)
   CWD = getcwd(NULL, MAX_PATHLEN+1);
#else
   CWD = getwd(NULL);
#endif

   // Initialize stats blocks ...
   bzero(&GS, sizeof(PWALK_STATS_T));			// 'GS' is 'Global Stats'
   for (i=0; i<(MAX_WORKERS+1); i++) WS[i] = NULL; 	// 'WS' is 'Worker Stats'

   // ------------------------------------------------------------------------

   // Process command-line options ...
   // NOTE: Up through argument validation, errors go to stderr ...
   process_arglist(argc, argv);

   // Initialize global mutexes ...
   init_main_mutexes();

   // Create output dir (OUTPUT_DIR), pwalk.log (Plog), and pwalk.fifo ...
   // NOTE: After this, errors all go to Plog rather than stderr ...
   init_main_outputs();

   fprintf(Plog, "NOTICE: --- Arguments ---\n");

   // Log command-line recap ...
   fprintf(Plog, "NOTICE: cmd =");
   for (i=0; i<argc; i++) fprintf(Plog, " %s", argv[i]);
   fprintf(Plog, "\n");

   // Log operational context ...
   fprintf(Plog, "NOTICE: cwd = %s\n", CWD);
   fprintf(Plog, "NOTICE: output = %s\n", OUTPUT_DIR);

   for (i=0; i<N_SOURCE_PATHS; i++)
      fprintf(Plog, "NOTICE: source[%d] = %s\n", i, SOURCE_PATHS[i]);
   for (i=0; i<N_TARGET_PATHS; i++)
      fprintf(Plog, "NOTICE: target[%d] = %s\n", i, TARGET_PATHS[i]);

   if (SELECT_HARDCODED && SELECT_T_SINCE != 0)	// NOTE: ctime() provides the '\n' here ...
      fprintf(Plog, "NOTICE: -select -since = %s", ctime(&SELECT_T_SINCE));

   fprintf(Plog, "NOTICE: --- Platform ---\n");
   (void) uname(&uts);
   fprintf(Plog, "NOTICE: uts.nodename = %s\n", uts.nodename);
   fprintf(Plog, "NOTICE: uts.sysname  = %s\n", uts.sysname);
   fprintf(Plog, "NOTICE: uts.release  = %s\n", uts.release);
   fprintf(Plog, "NOTICE: uts.version  = %s\n", uts.version);
   fprintf(Plog, "NOTICE: uts.machine  = %s\n", uts.machine);

   fprintf(Plog, "NOTICE: --- Process ---\n");
   fprintf(Plog, "NOTICE: pid = %d\n", getpid());
   fprintf(Plog, "NOTICE: MAX_OPEN_FILES = %d\n", MAX_OPEN_FILES);
   assert (getrlimit(RLIMIT_NOFILE, &rlimit) == 0);
   fprintf(Plog, "NOTICE: RLIMIT_NOFILES = %llu\n", rlimit.rlim_cur);
   // OSX uses 0x7fffffffffffffff and Linux uses 0xffffffffffffffff - for 'unlimited'
   assert (getrlimit(RLIMIT_CORE, &rlimit) == 0);
   sprintf(s64, "%llu", rlimit.rlim_cur);
   str = (rlimit.rlim_cur >= 0x7fffffffffffffff) ? "unlimited" : s64;
   fprintf(Plog, "NOTICE: RLIMIT_CORE    = %s\n", str);

   // Push initial command-line <directory> args to FIFO ...
   for (i=1; i < argc; i++)
      if (*argv[i] != '-' && *argv[i] != '+') {
         dirarg_count += 1;
         fifo_push(argv[i], NULL, 0);
      }
   if (dirarg_count == 0)	// Default directory arg is just "."
      fifo_push(".", NULL, 0);

   // Force flush Plog so far. HENCEFORTH, Plog WRITES from WORKERS GO THRU LogMsg() ...
   LogMsg(NULL, 1);

   // ------------------------------------------------------------------------

   // @@@ Start worker threads ...
   init_worker_pool();

   // ------------------------------------------------------------------------

   if (PWdebug) {
      worker_status(NULL, &nw_busy, &fifo_depth);
      fprintf(stderr, "= main: nw_busy=%u fifo_depth=%llu\n", nw_busy, fifo_depth);
   }

   // Capture our start times ...
   gettimeofday(&T_START_tv, NULL);		// timeval (tv_sec, tv_ns)

   // @@@ Main runtime loop ...
   T_START_hires = gethrtime();		// Start hi-res work clock
   manage_workers();			// Runs until all workers are IDLE and FIFO is empty
   T_FINISH_hires = gethrtime();	// Stop hi-res work clock

   // ------------------------------------------------------------------------

   // Force flush Plog. HENCEFORTH, FURTHER Plog WRITES CAN JUST fprintf(Plog ...) ...
   LogMsg(NULL, 1);
   fprintf(Plog, "NOTICE: +++ %s Ends +++\n", PWALK_VERSION);

   // @@@ Aggregate per-worker-stats (WS[w_id]) to program's global-stats (GS) (lockless) ...
   // ... regardless of whether or not the statistic was actually accumulated by the workers.
   for (w_id=0; w_id<N_WORKERS; w_id++) {
      if (WS[w_id] == NULL) break;		// (non-NULL for workers that actually ran)
      GS.NOpendirs += WS[w_id]->NOpendirs;
      GS.NACLs += WS[w_id]->NACLs;
      GS.NRemoved += WS[w_id]->NRemoved;
      GS.NWarnings += WS[w_id]->NWarnings;
      GS.NStatCalls += WS[w_id]->NStatCalls;
      GS.NDirs += WS[w_id]->NDirs;
      GS.NFiles += WS[w_id]->NFiles;
      GS.NSymlinks += WS[w_id]->NSymlinks;
      GS.NOthers += WS[w_id]->NOthers;
      GS.NStatErrors += WS[w_id]->NStatErrors;
      GS.NBytesAllocated += WS[w_id]->NBytesAllocated;
      GS.NBytesNominal += WS[w_id]->NBytesNominal;
      GS.NZeroFiles += WS[w_id]->NZeroFiles;
      GS.NHardLinkFiles += WS[w_id]->NHardLinkFiles;
      GS.NHardLinks += WS[w_id]->NHardLinks;
      GS.READONLY_Zero_Files += WS[w_id]->READONLY_Zero_Files;
      GS.READONLY_Opens += WS[w_id]->READONLY_Opens;
      GS.READONLY_Errors += WS[w_id]->READONLY_Errors;
      GS.READONLY_CRC_Bytes += WS[w_id]->READONLY_CRC_Bytes;
      GS.READONLY_DENIST_Bytes += WS[w_id]->READONLY_DENIST_Bytes;
      GS.NPythonCalls += WS[w_id]->NPythonCalls;
      GS.NPythonErrors += WS[w_id]->NPythonErrors;
      // @@@ Cheap-to-keep WS -> GS stats aggregation ...
      if (GS.MAX_inode_Value_Seen < WS[w_id]->MAX_inode_Value_Seen)
         GS.MAX_inode_Value_Seen = WS[w_id]->MAX_inode_Value_Seen;
      if (GS.MAX_inode_Value_Selected < WS[w_id]->MAX_inode_Value_Selected)
         GS.MAX_inode_Value_Selected = WS[w_id]->MAX_inode_Value_Selected;
      // @@@ #tally: accumulate GS totals from WS subtotals ...
      if (Cmd_TALLY) {
         for (i=0; i<TALLY_BUCKETS; i++) {
            GS.TALLY_BUCKET.count[i] += WS[w_id]->TALLY_BUCKET.count[i];
            GS.TALLY_BUCKET.size[i] += WS[w_id]->TALLY_BUCKET.size[i];
            GS.TALLY_BUCKET.space[i] += WS[w_id]->TALLY_BUCKET.space[i];
         }
      }
   }

   // ------------------------------------------------------------------------

   // @@@ OUTPUT (.tally): +tally writes its own .tally file ...
   if (Cmd_TALLY) pwalk_tally_output();

   // @@@ OUTPUT (.log): Various final summary outputs ...

   // @@@ ... -audit decoder ring maps columns of .audit files ...
#if PWALK_AUDIT // OneFS only
   if (Cmd_AUDIT) log_audit_keys();
#endif // PWALK_AUDIT

   // @@@ ...  OS-level pwalk process stats ...
   (void) getrusage(RUSAGE_SELF, &p_usage);
   // (void) getrusage(RUSAGE_CHILDREN, &c_usage);	// ... for if we add children
   //     struct rusage {	// from OSX; YMMV
   //             struct timeval ru_utime; /* user time used */
   //             struct timeval ru_stime; /* system time used */
   //             long ru_maxrss;          /* max resident set size */
   //             long ru_ixrss;           /* integral shared text memory size */ (!SOLARIS)
   //             long ru_idrss;           /* integral unshared data size */
   //             long ru_isrss;           /* integral unshared stack size */ (!SOLARIS)
   //             long ru_minflt;          /* page reclaims */
   //             long ru_majflt;          /* page faults */
   //             long ru_nswap;           /* swaps */
   //             long ru_inblock;         /* block input operations */
   //             long ru_oublock;         /* block output operations */
   //             long ru_msgsnd;          /* messages sent */
   //             long ru_msgrcv;          /* messages received */
   //             long ru_nsignals;        /* signals received */
   //             long ru_nvcsw;           /* voluntary context switches */
   //             long ru_nivcsw;          /* involuntary context switches */
   //     };

   fprintf(Plog, "NOTICE: Summary process stats ...\n");
   fprintf(Plog, "NOTICE: %16ld - max resident set size (KB)\n", p_usage.ru_maxrss/1024);
#ifdef SOLARIS
   fprintf(Plog, "NOTICE: %16ld - integral resident set size\n", p_usage.ru_idrss);
#else
   fprintf(Plog, "NOTICE: %16ld - integral shared text memory size\n", p_usage.ru_ixrss);
   fprintf(Plog, "NOTICE: %16ld - integral unshared data size\n", p_usage.ru_idrss);
   fprintf(Plog, "NOTICE: %16ld - integral unshared stack size\n", p_usage.ru_isrss);
#endif
   fprintf(Plog, "NOTICE: %16ld - page reclaims\n", p_usage.ru_minflt);
   fprintf(Plog, "NOTICE: %16ld - page faults\n", p_usage.ru_majflt);
   fprintf(Plog, "NOTICE: %16ld - swaps\n", p_usage.ru_nswap);
   fprintf(Plog, "NOTICE: %16ld - block input operations\n", p_usage.ru_inblock);
   fprintf(Plog, "NOTICE: %16ld - block output operations\n", p_usage.ru_oublock);
   fprintf(Plog, "NOTICE: %16ld - messages sent\n", p_usage.ru_msgsnd);
   fprintf(Plog, "NOTICE: %16ld - messages received\n", p_usage.ru_msgrcv);
   fprintf(Plog, "NOTICE: %16ld - signals received\n", p_usage.ru_nsignals);
   fprintf(Plog, "NOTICE: %16ld - voluntary context switches\n", p_usage.ru_nvcsw);
   fprintf(Plog, "NOTICE: %16ld - involuntary context switches\n", p_usage.ru_nivcsw);

   // @@@ ... Summary pwalk stats ...
   fprintf(Plog, "NOTICE: Summary pwalk stats ...\n");
   fprintf(Plog, "NOTICE: %16llu - push%s\n", FIFO_PUSHES, (FIFO_PUSHES != 1) ? "es" : "");
   fprintf(Plog, "NOTICE: %16llu - pop%s\n", FIFO_POPS, (FIFO_POPS != 1) ? "s" : "");
   fprintf(Plog, "NOTICE: %16llu - warning%s\n", GS.NWarnings, (GS.NWarnings != 1) ? "s" : "");
   if (GS.NPythonCalls > 0) 
      fprintf(Plog, "NOTICE: %16llu - Python call%s from -audit\n",
         GS.NPythonCalls, (GS.NPythonCalls != 1) ? "s" : "");

   // @@@ ... Summary treewalk stats ...
   fprintf(Plog, "NOTICE: Summary file stats ...\n");

   // @@@ ... Results of -rm operations ...
   if (Cmd_RM)
      fprintf(Plog, "NOTICE: %16llu - file%s removed by -rm\n", GS.NRemoved, (GS.NRemoved != 1) ? "s" : "");

   // @@@ ... Grand total of stat(2)-based stats ...
   // NStatCalls should equal (NOpendirs + NFiles + NSymlinks + NOthers + NStatErrors) ...
   fprintf(Plog, "NOTICE: %16llu - stat() call%s in readdir_r loops\n", GS.NStatCalls, (GS.NStatCalls != 1) ? "s" : "");
   fprintf(Plog, "NOTICE: %16llu -> stat() error%s\n", GS.NStatErrors, (GS.NStatErrors != 1) ? "s" : "");
   fprintf(Plog, "NOTICE: %16llu -> director%s\n", GS.NOpendirs, (GS.NOpendirs != 1) ? "ies" : "y");
   fprintf(Plog, "NOTICE: %16llu -> file%s\n", GS.NFiles, (GS.NFiles != 1) ? "s" : "");
   fprintf(Plog, "NOTICE: %16llu -> symlink%s\n", GS.NSymlinks, (GS.NSymlinks != 1) ? "s" : "");
   fprintf(Plog, "NOTICE: %16llu -> other%s\n", GS.NOthers, (GS.NOthers != 1) ? "s" : "");
   fprintf(Plog, "NOTICE: %16llu - byte%s allocated (%4.2f GB)\n",
      GS.NBytesAllocated, (GS.NBytesAllocated != 1) ? "s" : "", GS.NBytesAllocated / 1000000000.);
   fprintf(Plog, "NOTICE: %16llu - byte%s nominal (%4.2f GB)\n",
      GS.NBytesNominal, (GS.NBytesNominal != 1) ? "s" : "", GS.NBytesNominal / 1000000000.);
   if (GS.NBytesNominal > 0) {	// protect divide ...
      fprintf(Plog, "NOTICE: %15.2f%% - overall overhead ((allocated-nominal)*100.)/nominal)\n",
         ((GS.NBytesAllocated - GS.NBytesNominal)*100.)/GS.NBytesNominal);
   }
   fprintf(Plog, "NOTICE: %16llu - zero-length file%s\n", GS.NZeroFiles, (GS.NZeroFiles != 1) ? "s" : "");

   // @@@ Hard link accounting ...
   if (GS.NHardLinkFiles) {
      fprintf(Plog, "NOTICE: %16llu - files with hard link count > 1\n", GS.NHardLinkFiles);
      fprintf(Plog, "NOTICE: %16llu - sum of hard links > 1\n", GS.NHardLinks);
   }

   // @@@ ... Show  ACL-related stats ...
   if (Cmd_XACLS || Cmd_WACLS || Cmd_RM_ACLS || P_ACL_P) {
      fprintf(Plog, "NOTICE: %16llu - ACL%s found\n", GS.NACLs, (GS.NACLs != 1) ? "s" : "");
   }

   // @@@ ... Show +crc, md5, and +denist stats ...
   if (Cmd_DENIST || P_CRC32 || P_MD5 || Cmd_RM_ACLS) {
      fprintf(Plog, "NOTICE: Summary (READONLY) file data stats ...\n");
      fprintf(Plog, "NOTICE: %16llu - zero-length file%s\n", GS.READONLY_Zero_Files, (GS.READONLY_Zero_Files != 1) ? "s" : "");
      fprintf(Plog, "NOTICE: %16llu - open() call%s\n", GS.READONLY_Opens, (GS.READONLY_Opens != 1) ? "s" : "");
      fprintf(Plog, "NOTICE: %16llu - open() or read() error%s\n", GS.READONLY_Errors, (GS.READONLY_Errors != 1) ? "s" : "");
      if (P_CRC32)
         fprintf(Plog, "NOTICE: %16llu - CRC byte%s read\n", GS.READONLY_CRC_Bytes, (GS.READONLY_CRC_Bytes != 1) ? "s" : "");
      if (Cmd_DENIST)
         fprintf(Plog, "NOTICE: %16llu - DENIST byte%s read\n", GS.READONLY_DENIST_Bytes, (GS.READONLY_DENIST_Bytes != 1) ? "s" : "");
   }

   // @@@ Cheap-to-keep GS counters ...
   fprintf(Plog, "NOTICE: %16llu - MAX inode value seen\n", GS.MAX_inode_Value_Seen);
   fprintf(Plog, "NOTICE: %16llu - MAX inode value selected()\n", GS.MAX_inode_Value_Selected);

   // @@@ ... Command line recap ...
   fprintf(Plog, "NOTICE: cmd =");
   for (i=0; i<argc; i++) fprintf(Plog, " %s", argv[i]);
   fprintf(Plog, "\n");

   // @@@ ... CPU usage ...
   (void) times(&cpu_usage);
   fprintf(Plog, "NOTICE: %5.3fs usr, %5.3fs sys cpu\n",
           ((cpu_usage.tms_utime + cpu_usage.tms_cutime) / (double) CLK_TCK),
           ((cpu_usage.tms_stime + cpu_usage.tms_cstime) / (double) CLK_TCK) );

   // @@@ ... Elapsed time ...
   t_elapsed_sec = (T_FINISH_hires - T_START_hires) / 1000000000.; // convert nanoseconds to seconds
   fprintf(Plog, "NOTICE: %llu files, %s elapsed, %3.0f files/sec\n",
      GS.NFiles+GS.NDirs+GS.NOthers,
      format_ns_delta_t(ebuf, T_START_hires, T_FINISH_hires),
      (t_elapsed_sec > 0.) ? ((GS.NFiles+GS.NDirs+GS.NOthers)/(t_elapsed_sec)) : 0.);

   // @@@ Final Sanity Checks and Warnings @@@
   if (FIFO_POPS != FIFO_PUSHES) {	// (Old debug code)
      fprintf(Plog, "WARNING: FIFO_POPS(%llu) != FIFO_PUSHES(%llu)\n",
         FIFO_PUSHES, FIFO_POPS);
      exit_status = -1;
   }
   if (GS.NPythonErrors > 0) {
      fprintf(Plog, "WARNING: %llu Python call errors encountered!\n", GS.NPythonErrors);
      exit_status = -2;
   }
   fflush(Plog);

   // @@@ Close auxillary outputs @@@
   close_all_outputs();

   // @@@ Cleanup all worker threads @@@
   for (i=0; i<N_WORKERS; i++)
      pthread_cancel(WORKER_pthread[i]);
   for (i=0; i<N_WORKERS; i++)
      pthread_join(WORKER_pthread[i], NULL);

   exit(exit_status);
}
