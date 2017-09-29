// pwalk.c - by Bob Sneed (Bob.Sneed@dell.com) - FREE CODE, based on prior work whose source
// was previously distributed as FREE CODE.

#define PWALK_VERSION "pwalk 2.02 BETA-7"
#define PWALK_SOURCE 1

// --- DISCLAIMERS ---
//
// This is FREE CODE, intended for instructional and non-production purposes only. There
// are no warranties, express or implied of any sort whatsoever, including any warrantees
// of correctness or suitability for any particular purpose. Use at your own risk. This
// code is explicitly not a supported product of Dell EMC.
//
// The coding style is unapologetically ad-hoc, with lots of global variables, an occassional
// 'goto' and crude (but semi-thorough) error-handling.
//
// --- DESCRIPTION ---
//
// This program does a multithreaded directory tree walk with a variable degree of concurrency,
// optionally spreading the work across multiple 'equivalent paths' representing the same
// exported NAS directory structure. It is implemented using POSIX pThreads for portability.
// Program outputs vary depending on the command-line options specified.  This code is intended
// to be a reusable template for constructing diverse tactical solutions requiring a high-speed
// concurrent treewalk.
//
// This code has been developed and tested on Linux, Solaris, OSX, and OneFS - but not all build
// targets have been tested for each iteration of the code. Some functionality is coded such that
// it is only supported on specific build platforms, such as ACL-related features only supported
// on Linux, or SmartLock auditing features only supported natively on OneFS.
//
// For walking large directory structures on OneFS, better performance has been observed when
// running the code over NFS or SMB NAS protocols versus direct execution on OneFS. With NFS,
// this is presumeably due to the benefits of READIRPLUS more-efficiently collecting file attribute
// data than single per-file stat() calls used natively on OneFS. Beware that high rates of
// READIRPLUS calls targeting a single OneFS initiator node within a OneFS cluster can cause high
// CPU usage on that initiator node. It is advised to test first with moderate levels of concurrency
// per-initiator-node, and to leverage the '-paths=<pathfile>' feature to spread pwalk's access to
// OneFS across multiple initiator nodes.
//
// --- HISTORY ---
//
// RFE: Subtotal by bins; 0, 1k, 2k, 4k, 8k, 16k, 32k, 64k, 128k, 256k, 512k, 1M, 2M and perhaps 1G, 10G, 100+G.
// RFE: Add inode output
// RFE: Implement '-o' option like 'ps' (inode,asize,mode,nlink,nsize,name)
// RFE: Output filters ($variable expression like 'find' predicates)
//
// Version 2.02 2017/07/10 - Feature adds & MAJOR bug fix
//	- Added +rm_acls option (OneFS only) removes all non-inherited ACEs
//	- If current or calculated ACL is NULL, replace with apparent mode bits
//	- Corrected READONLY operations to use O_NOFOLLOW | O_OPENLINK (!)
//	- Bug fix: eliminate distinct lock for FIFO; use MP_lock instead, and simplify control flow
//	- '+acls' changed to '-acls' to suppress ACL-fetching with -ls and -xml
//	- '+crc' added to -ls and -xml outputs
// Version 2.01 2017/05/12 - Feature adds
//	- Added -cd= option; where to cd before creating output dirctory
// Version 2.0 2017/04/?? - ...
//	- TODO ... -paths to allow two columns for src and dst (for -cmp)
//	- TODO ... implement -cmp to use efficient cmp(src_fd, dst_fd) function
//	- TODO ... implement -find initial functionality
//	- TODO ... restructure to make extensibility easier and allow functionality stubbing
//	- TODO ... Embed Python code in machine-generated pwalk_python.c (from pwalk_python.py)
// Version 1.9.78 2016/12/15 - Feature added
//	- Add OneFS logic for extracting native ownership (ID vs. SID)
// Version 1.9.76 2016/12/13 - Feature adds
//	- Added -csv= primary mode (PARTIAL)
//	- Changed old -tag to +tally[=<string>]
//	- Start parameterizing +tally buckets (hardcoded)
// Version 1.9.75 2016/??/?? - Bug fixes
//	- Isolate from SIGINT or other truss-related signals (TBD)
//	- Added '-1' write to Python pclose in the SAR logic
//	- Add initial timestamp in log file
// Version 1.9.74 2016/11/01 - Bug fixes & added robustness ...
//	- When output directory cannot be created due to EEXIST, retry up to MAX_MKDIR_RETRIES times
//	- Send '-1' to Python before pclose() to tell it to exit()
//	- Python changed: now returns 'P' as 1st column, errno as 2nd column
//	- Python changed: now recognizes '-1' as a signal to exit()
// Version 1.9.73 2016/11/01 - Special -audit logic for SmartLock accounting
//	- Output raw w_ctime and w_retention_time
//	- Output Python call count
// Version 1.9.72 2016/11/01 - Enhance -audit reporting
// Version 1.9.71 2016/11/01 - Enhance -audit reporting
// Version 1.97 2016/07/20 - Add ACL-handling options (Linux ONLY)
//	- "+crc" adds CRC value to SmartLock -audit report (reads all files!)
//	- "+xacls=" pulls POSIX ACLs, translates them to NFSv4 for output in various formats
//	- "+wacls=" pulls POSIX ACLs, translates them to NFSv4 for 'wacls' symbiont on OneFS
//	- "+acls" pulls POSIX ACLs and may alter -ls and -xml outputs
//	- Conditionalize for clean compiles on Linux, OneFS 7.2, and OneFS 8.0
//	- New POSIX-to-NFS4 ACL code in pwalk_acls.[ch], documented in pwalk_acls_<version>.docx (Linux ONLY)
// Version 1.96 2016/03/22 - Add -acls option
//	- ".snapshot" (OneFS) and ".snapshots" (GPFS) are now both considered as snapshot directories
//	- Added tentative portability bits for xattrs and Debian Linux
//	- Added st_blocks in -audit
//	- ALL COUNTERS ARE NOW 64-BIT!!
// Version 1.95 2016/03/07 - Check OSX/Linux/OneFS code portability
//	- Modified -audit output
// Version 1.94 2016/02/17 - Refinements to -audit
//	- Make worker-to-Python symbiont ratio 1:1
//	- Correct and refine -audit logic
//	- Improve pwalk_python.py
// Version 1.93 2016/02/08 - Limited release with -audit
//	- Implement loosely-coupled Python co-processes for native OneFS execution
// Version 1.92 2016/02/08 - Limited release with +tally
//	- +tally code is prototype for similar logic for stuff like buckets by size
// Version 1.91 2016/01/19 - Limited release with -fix_times
//	- Includes references to OneFS-native lvtimes() API
// Version 1.9 2015/12/30 - Correct and improve time-fixing logic
//	- Changed -fix_mtimes to -fix_times
//	- Changed fix_times() logic to catch *any* bad date (not in 32-bit [0 .. 0x7fffffff] Unix epoch)
//	- Developed companion programs: mystat.c, pwalk_create_shadow.c, pwalk_touch_shadow.c, and  touch3.c
//	- Leverage lvtimes() when running natively on OneFS
//	- Use lutimes(2) with -fix-mtime for symlinks
// Version 1.8 2015/11/16 - Added -fix_mtime option (uses optional -shadow= option)
//	- Repairs [amcb]time values that are bad
//	- Now MUST specify one of [ -ls, -xml, -fix_mtime, -cmp ]
//	- Implemented '-shadow=' for '-fix_mtime'
// Version 1.7 2015/1/21 - Minor mods
//	- Count commandline args in 'directories' in .log summary count
//	- Change (hidden) DENIST option to '+denist' (was '-denist')
// Version 1.6 2015/1/21 - Redesignated version
//	- Code/comment cleanup & PPTX sync point
//	- OSX & Linux compile/build validation
// Version 1.5+ 2014/12/03 - Minor code cleanup
//	- Added '+tstat' option (timed statistics for stat() calls)
//	- Added '-pmode' option (omit file mode bits output)
// Version 1.5b 2014/09/10 - Major updates
//	- Bug fix: "don't crash trying to close files that were never opened (race condition)"
//	- Added '-paths=<pathfile>' feature for 'equivalent paths'
//	- Added '-gz' feature
//	- Added '+.snapshot' feature, plus logic to suppress .snapshot traversal by default
//	- Added 'Files/second' statistic to summary stats
//	- TBD: Change merge.
//	- TBD: Assure that > 4B files can be walked (4*10^9); requires 64-bit unsigned counters.
//	- TBD: Hide 'more fully-formed XML' outputs?
// Version 1.5a 2014/05/30 - Make program do 'ls'-style output.
//	- Not released.
// Version 1.4 2013/10/20 - Bug fixes.
//	- More fully-formed XML output.
//	- Morph code for templated output function (LS, JSON, other)
// Version 1.3a 2013/10/20 - Added obscure (hidden) DENIST benchmarking feature.
//	- See DENIST notes below.
// Version 1.3 2013/10/20 - Bug fixes.
//	- Fixed race condition in worker startup logic.
// Version 1.2 2013/10/15 - Redesigned threading model to give consistent results.
//	- Major edits for clarity and maintainability
//	- Prior coding strategy had subtle race conditions
//	- Added -dop= and -paths= options
// Version 1.1 2013/09/17 - Initial Linux build.
// Version 1.0 2013/09/10 - First release.
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

/* @@@ SECTION: Declarations @@@ */

/* @@@ Basic #includes ... */

// RE: http://docs.oracle.com/cd/E19683-01/806-6867/compile-74765/index.html
#ifdef SOLARIS
#define _GNU_SOURCE
#define _POSIX_PTHREAD_SEMANTICS
#define _LARGEFILE64_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
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
#include <fcntl.h>
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

#if PWALK_ACLS
#include "pwalk_acls.h"		// POSIX ACL-handling logic only on Linux
#endif // PWALK_ACLS

// @@@ SECTION: Program initializers & compile-time constraints ...

// Shorthand MACROs for casting printf args ...
#define UL(x) ((unsigned long) x)

#define PROGNAME "pwalk"		// Our program basename only

#if defined(SOLARIS)			// Platform name
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
#define PATHSEPCHAR '/'			// Might make conditional for Windoze
#define PATHSEPSTR "/"			// Might make conditional for Windoze
#define SECS_PER_DAY 86400		// 24*60*60 = 86400

// @@@ Forward declarations ...
void fifo_push(char *p);
int fifo_pop(char *p);
void directory_scan(int w_id);
void abend(char *msg);
void *worker_thread(void *parg);

// @@@ Global variables written *only* by controlling thread ...
static int N_WORKERS = 1;			// <N> from "-dop=<N>"
static int GZ_OUTPUT = 0;			// gzip output streams when '-gz' used
static int DOT_SNAPSHOT = 0;			// Skip .snapshot unless '+.snapshot' used
static int TSTAT = 0;				// Show timed statistics when +tstat used
static int P_MODE = 1;				// Show mode bits unless -pmode suppresses
static int P_ACL_PLUS = 1;			// Show ACL as '+' unless -acls suppresses
static int P_CRC32 = 0;				// Show CRC32 for -ls, -xml, -audit
static int ST_BLOCK_SIZE = 1024;		// Units for statbuf->st_blocks (not currently settable)
static char *PYTHON_COMMAND = NULL;		// For OneFS -audit operation

// Primary operating modes ...
static int Cmd_LS = 0;
static int Cmd_XML = 0;
static int Cmd_AUDIT = 0;
static int Cmd_CMP = 0;
static int Cmd_FIXTIMES = 0;
static int Cmd_CSV = 0;

// Secondary modes ...
static int Cmd_DENIST = 0;			// +denist
static int Cmd_RM_ACLS = 0;			// +rm_acls (OneFS only)
static int Cmd_SELECT = 0;			// -select
static int Cmd_TALLY = 0;			// +tally
static int Cmd_WACLS = 0;			// +wacls=
static int Cmd_XACLS = 0;			// +xacls= (Linux only) bitmask combo of ...
#define Cmd_XACLS_BIN 1
#define Cmd_XACLS_CHEX 2
#define Cmd_XACLS_NFS 4
#define Cmd_XACLS_ONEFS 8

static char *CWD;	 			// Our initial default directory
static char *CD_ARG = NULL; 			// Argument from -cd= option
static char OPATH[MAX_PATHLEN+1];		// Directory we'll create for output files
static char *SHADOW_DIR = NULL;  		// For '-shadow=' arg
static char *WACLS_CMD = NULL;  		// For '+wacls=' arg

static char *TALLY_TAG = "tally";		// For '+tally=<tag>' value
static struct {					// klooge: hard-coded +tally options (externalize!)
   int days;
   char *label;
} TALLY_INFO[] = {
#ifdef NORMAL
   { -1, "Total" },
   { 30, "< 30" },
   { 60, "< 60" },
   { 90, "< 90" },
   { 120, "< 120" },
   { 180, "< 180" },
   { -1, ">= 180" }
#else
   { -1, "Total" },
   { 365, "< 365" },	// 1 year
   { 730, "< 730" },	// 2 years
   { 0, NULL },
   { 0, NULL },
   { 0, NULL },
   { -1, ">= 730" }
#endif
};

// @@@ Globals foundation to the treewalk logic per se ...
static FILE *Fpop = NULL, *Fpush = NULL;	// File-based FIFO pointers
static FILE *Flog = NULL;			// Main logfile output (pwalk.log)
static long long T_START, T_FINISH;		// Program elapsed time (hi-res)
struct timeval START_TIMEVAL;			// Program start time
#define MAXPATHS 64				// Arbitrary limit for '-paths='
static int NPATHS = 0;				// Number of equivalent path prefixes in '-paths=' file
static char *PATHS[MAXPATHS];			// Storage for '-paths=' value pointers

typedef enum {BORN=0, IDLE, BUSY} wstate_t;	// Worker state

// @@@ Statistics blocks ...
//
// Statistics are collected in three phases;
//	1. At the per-directory level (DS) - during each directory scan
//		- We need per-directory subtotals in some outputs
//	2. At the per-worker level (WS) - sub-totaled at the end of each directory scan
//		- We do not want lock competition between workers while scanning
//	3. At the pwalk global level (GS) - grand-total summed from worker subtotals at the very end
//		- Aggregating the grnad totals is a lock-less operation

typedef struct {
   count_64 NFiles;				// Number of files
   off_t NBytesNominal;				// Sum of nominal file sizes
   off_t NBytesAllocated;			// Sum of allocated space
} pwalk_tally_stats_t;

typedef struct {
   // Accumulated per-directory ...
   count_64 NDiropens;				// Number of diropen() calls
   count_64 NStatCalls;				// Number of calls to lstat() during scans
   count_64 NDirs;				// ... # that were directories
   count_64 NFiles;				// ... # that were files
   count_64 NOthers;				// ... # that were others
   count_64 NStatErrors;			// ... # that were errors
   count_64 NWarnings;				// Scan issues other than stat() failures
   off_t NBytesAllocated;			// Sum of allocated space
   off_t NBytesNominal;				// Sum of nominal file sizes
   count_64 NACLs;				// +acls, +xacls=, or +wacls= # files & dirs w/ ACL processed
   // Accumulated per-worker ...
   count_64 READONLY_Zero_Files;		// READONLY zero-length files
   count_64 READONLY_Opens;			// READONLY file opens
   count_64 READONLY_Errors;			// READONLY open/read errors
   count_64 READONLY_CRC_Bytes;			// READONLY CRC bytes read
   count_64 READONLY_DENIST_Bytes;		// READONLY DENIST bytes read
   count_64 NPythonCalls;			// Python calls
   count_64 NPythonErrors;			// Python errors
   pwalk_tally_stats_t TALLY_STATS[7];		// +tally stats [total, plus 6 buckets]
} pwalk_stats_t;
static pwalk_stats_t GS;			// 'GS' is 'Global Stats'
static pwalk_stats_t *WS[MAX_WORKERS+1];	// 'WS' is 'Worker Stats', calloc'd (per-worker) on worker startup

// LogMsg_mutex for serializing writes to pwalk.log from LogMsg() ...
static pthread_mutex_t LOGMSG_mutex;

// WAKEUP counter and mutex, maintained by N worker_threads ...
static pthread_mutex_t WAKEUP_mutex;
count_64 N_Worker_Wakeups;

// MP_mutex for MP-coherency of worker status and FIFO state ...
static pthread_mutex_t MP_mutex;
count_64 FIFO_PUSHES = 0;			// # pushes (increments in fifo_push())
count_64 FIFO_POPS = 0;				// # pops (increments in fifo_pop())

// WorkerData is array of worker's Thread-Specific private DATA ...
static struct {				// Thread-specific data (WorkerData[i]) ...
   // Worker-related ...
   int			w_id;			// Worker's unique index
   FILE			*wlog;			// WLOG output file for this worker
   wstate_t		wstate;			// Worker's operational state
   // Co-process & xacls support ...
   FILE 		*PYTHON_PIPE;		// Pipe for -audit Python symbiont
   FILE 		*WACLS_PIPE;		// Pipe for +wacls= process
   FILE 		*XACLS_BIN_FILE;	// File for +xacls=bin output
   FILE 		*XACLS_CHEX_FILE;	// File for +xacls=chex output
   FILE 		*XACLS_NFS_FILE;	// File for +xacls=nfs output
   FILE 		*XACLS_ONEFS_FILE;	// File for +xacls=onefs output
   // Pointers to runtime-allocated buffers ...
   char			*DirPath;	// Fully-qualified directory to process
   struct dirent	*Dirent;	// Buffer for readdir_r()
   // pThread-related ...
   pthread_t		thread;
   pthread_cond_t	WORKER_cv;	// Condition variable for worker wakeup logic
   pthread_mutex_t	WORKER_cv_mutex;
} WorkerData[MAX_WORKERS+1];			// klooge: s/b dynamically-allocated f(N_WORKERS) */

// Convenience MACROs for worker's thread-specific values ...
#define WDAT WorkerData[w_id]		// Coding convenience
#define WLOG WDAT.wlog			// Output file handle, compact

/* @@@ SECTION: Simple support functions @@@ */

// usage() - command line instructions

void
usage(void)
{
   printf("%s %s\nUsage: pwalk [<primary_mode>] [<secondary_mode> ...] [<option> ...] <directory> [<directory> ...]\n",
      PWALK_VERSION, PWALK_PLATFORM);
   printf(" Where:\n");
   printf("   <primary_mode> is at most ONE of:\n");
   printf("	-ls			// create .ls outputs (like ls -l)\n");
   printf("	-xml			// create .xml outputs\n");
#if PWALK_AUDIT // OneFS only
   printf("	-audit			// create .audit files based on OneFS SmartLock status\n");
#endif // PWALK_AUDIT
   // printf("	-cmp			// create .cmp from binary compare with alternate -target directory\n");
   printf("	-fix_times		// create .fix outputs (or just enumerate with -dryrun)\n");
   printf("	-csv=<ifile>		// create .csv outputs based on fields in <ifile>\n");
   printf("   <secondary_mode> is zero or more of:\n");
   printf("	+denist			// also ... read first 128 bytes of every file encountered\n");
   printf("	+tally[=<tag>]		// also ... output bucketized file/space counts in .tally file\n");
   printf("	+crc			// also ... calculate CRC for each file (READS ALL FILES!)\n");
#if defined(__ONEFS__)
   printf("	+rm_acls		// also ... remove non-inherited ACEs in any ACLs encountered\n");
#endif
#if PWALK_ACLS // ACL-related commandline options ...
   printf("	+wacls=<command>	// also ... write derived binary NFS4 ACLs to <command>\n");
   printf("	+xacls=[bin|nfs|chex]	// also ... create .acl4bin, .acl4nfs, .acl4chex outputs\n");
#endif // PWALK_ACLS
   printf("   <option> values are:\n");
   printf("	-cd=<relative_path>	// cd to here before evaluating directory arguments\n");
   printf("	-dop=<n>		// specifies the Degree Of Parallelism (max number of workers)\n");
   printf("	-paths=<paths_file>	// specify equivalent pathname prefixes for multi-pathing\n");
   printf("	-gz			// gzip output files (HANGS on OSX!!)\n");
   printf("	-dryrun			// suppress making changes (with -fix_times)\n");
   printf("	-shadow=<shadow_d>	// shadow directory; optional (with -fix_times)\n");
   printf("	-pmode			// suppress showing formatted mode bits (with -ls and -xml)\n");
   printf("	-acls			// suppress ACL info in some outputs, eg: '+'\n");
   printf("	-v			// verbose; verbosity increased by each '-v'\n");
   printf("	-d			// debug; verbosity increased by each '-d'\n");
   printf("	+tstat			// include hi-res timing statistics in some outputs\n");
   printf("	+.snapshot		// include .snapshot[s] directories (OFF by default)\n");
   printf("   <directory> ...		// one or more directories to traverse\n");
   exit(-1);
}

// LogMsg() - write to main output log stream (Flog); serialized by mutex, with a timestamp
// being generated anytime more than a second has passed since the last output. If called with
// a NULL msg, generate a timestamp and flush Flog.

void
LogMsg(char *msg)
{
   static time_t last_time = 0;
   time_t this_time;
   char timestamp[32];		// ctime() only needs 26 bytes

   pthread_mutex_lock(&LOGMSG_mutex);				// +++ LOGMSG lock +++

   // If time has advanced, log a timestamp ...
   this_time = time(NULL);
   if (this_time > last_time) {
      last_time = this_time;
      ctime_r(&this_time, timestamp);
      if (Flog) fputs(timestamp, Flog);
   }

   // NULL message forces a flush ...
   if (msg == NULL) fflush(Flog);
   else             fputs(msg, Flog);

   pthread_mutex_unlock(&LOGMSG_mutex);				// --- LOGMSG lock ---
}

// close_all_outputs() - Shutdown Python and +wacls pipes, and close +xacls= files ...
// NOTE: WDAT is a macro for WorkerData[w_id]

void
close_all_outputs(void)
{
   char pw_acls_emsg[128] = "";
   int pw_acls_errno = 0;
   int w_id;

   for (w_id=0; w_id<N_WORKERS; w_id++) {
      // Close per-worker primary output ...
      if (WDAT.wlog) {			// Iff log was ever opened (non-NULL) ...
         if (Cmd_XML)			// Output trailer[s] ...
            fprintf(WLOG, "\n</xml-listing>\n");
         if (GZ_OUTPUT)			// Close log stream ...
            pclose(WLOG);
         else
            fclose(WLOG);
      }

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

void
abend(char *msg)
{
   fprintf(stderr, "%d: FATAL: %s\n", getpid(), msg);
   LogMsg(msg); LogMsg(NULL);
   perror("");
   close_all_outputs();
   exit(-1);
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

// crc32() - Reads entire open file and calculates CRC-32 value.
// RETURNS: CRC value in passed variable, bytes processed as function value.
// NOTE: Caller should assume result is valid iff returned size matches file's size.
// MT-safe.

size_t
crc32(int fd, char *rbuf, int rbuf_size, unsigned *crc_val)
{
   size_t nbytes, nbytes_t;

   nbytes_t = 0;
   while ((nbytes = pread(fd, rbuf, rbuf_size, nbytes_t)) > 0) {
      nbytes_t += nbytes;
   }
   *crc_val = 0xdeadbeef ^ nbytes_t;
   return(nbytes_t);
}

// crc16() - Calculate CRC-16 for passed buffer

unsigned short
crc16(const unsigned char *data_p, int length)
{
   unsigned char x;
   unsigned short crc = 0xFFFF;

   while (length--) {
      x = crc >> 8 ^ *data_p++;
      x ^= x>>4;
      crc = (crc << 8) ^ ((unsigned short)(x << 12)) ^ ((unsigned short)(x <<5)) ^ ((unsigned short)x);
   }
   return crc;
}

// format_mode_bits() - translate passed mode into 'rwx' format in passed buffer

void
format_mode_bits(char *str, mode_t mode)
{
   str[0] = '\0';			// default NUL string
   if (!P_MODE) return;

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

/* @@@ SECTION: Portable hi-resolution timing support  @@@ */

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

// worker_aux_create() - creates per-worker auxillary output files.
// ftype is filename suffix, eg: ".bin"

void
worker_aux_create(int w_id, FILE **pFILE, char *ftype)
{
   char ofile[MAX_PATHLEN+64];
   char emsg[128];

   sprintf(ofile, "%s%cworker-%03d.%s", OPATH, PATHSEPCHAR, w_id, ftype);
   *pFILE = fopen(ofile, "wx");					// O_EXCL create
   if (*pFILE == NULL) {
      sprintf(emsg, "Cannot create worker %d's \"%s\" output file!\n", w_id, ftype);
      abend(emsg);
   }
   // Give output stream a decent buffer size ...
   setvbuf(*pFILE, NULL, _IOFBF, WORKER_OBUF_SIZE);		// Fully-buffered
}

/* @@@ SECTION: Worker log open/close @@@ */

// worker_log_create() - creates per-worker output file.

// Create a buffered output stream WDAT.wlog, which will be referred to by the macro
// WLOG in most contexts.
// NOTE: ulimits in the environment need to allow a few more than MAX_WORKERS open files.

void
worker_log_create(int w_id)
{
   char ofile[MAX_PATHLEN+64];
   char *ftype;

   // Create ${OPATH}/worker%03d.{ls,xml,cmp,audit,fix,csv,out}[.gz] ...
   // Output will be determied by <primary_mode>, or '.out' otherwise
   if (Cmd_LS) ftype = "ls";
   else if (Cmd_XML) ftype = "xml";
   else if (Cmd_CMP) ftype = "cmp";
   else if (Cmd_AUDIT) ftype = "audit";
   else if (Cmd_FIXTIMES) ftype = "fix";
   else if (Cmd_CSV) ftype = "csv";
   else ftype = "out";

   if (GZ_OUTPUT) {		// WARNING: gzip-piped output hangs on OSX!
      sprintf(ofile, "gzip > %s%cworker-%03d.%s.gz", OPATH, PATHSEPCHAR, w_id, ftype);
      WLOG = popen(ofile, "w");
   } else {
      sprintf(ofile, "%s%cworker-%03d.%s", OPATH, PATHSEPCHAR, w_id, ftype);
      WLOG = fopen(ofile, "wx");				// O_EXCL create
   }
   if (WLOG == NULL)
      abend("Cannot create worker's output file!\n");

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

/* @@@ SECTION: Initializations @@@ */

// init_main_mutexes() - 1st initialization.

void
init_main_mutexes(void)
{
   pthread_mutexattr_t mattr;

   // Start with default mutex characteristics ...
   pthread_mutexattr_init(&mattr);
   // ... add: return -1 rather than deadlock if same thread does extra lock tries ...
   pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK);

   // ------------------------------------------------------------------------

   // MP mutex for MP-coherent global data access ...
   if (pthread_mutex_init(&MP_mutex, &mattr)) abend("FATAL: Can't init MP mutex!\n");

   // WAKEUP mutex for wakeup counter ...
   if (pthread_mutex_init(&WAKEUP_mutex, &mattr)) abend("FATAL: Can't init WAKEUP mutex!\n");

   // LOGMSG mutex for serializing logfile messages ...
   if (pthread_mutex_init(&LOGMSG_mutex, &mattr)) abend("FATAL: Can't init LOGMSG mutex!\n");

   // ------------------------------------------------------------------------

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

   // Create ${OPATH} output directory based on current time ...
   // Retry logic here is to cope with multiple pwalk processes being started at the same time
   // and colliding on their output directory name which is unique with one-second granularity.
   for (try=0; try < MAX_MKDIR_RETRIES; try++) {
      time(&clock);
      localtime_r(&clock, &tm_now);
      sprintf(OPATH, "%s%c%s-%04d-%02d-%02d_%02d_%02d_%02d", CWD, PATHSEPCHAR, PROGNAME,
         tm_now.tm_year+1900, tm_now.tm_mon+1, tm_now.tm_mday, tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec);
      rc = mkdir(OPATH, 0777);
      if (rc == 0) break;			// Success!
      if (errno != EEXIST)			// Only retry on EEXIST errors ...
         abend("Cannot create output directory!\n");
      if (try == (MAX_MKDIR_RETRIES-1))		// ... but do not retry forever.
         abend("Cannot create output directory after MAX_MKDIR_RETRIES attempts!\n");
      sleep(1);					// 1 second wait between retries
   }
   assert (rc == 0);

   // Create ${OPATH}/${PROGNAME}.log as our primary (shared, buffered) output log ...
   sprintf(ofile, "%s%c%s.log", OPATH, PATHSEPCHAR, PROGNAME);
   fclose(Flog);
   Flog = fopen(ofile, "w");
   if (Flog == NULL) abend("Cannot open Flog!");
   setvbuf(Flog, NULL, _IOFBF, 8192);

   // Start being chatty (we should use LogMsg() henceforth) ...
   sprintf(msg, "NOTICE: %s Begins\n", PWALK_VERSION);
   LogMsg(msg);

   // Create ${OPATH}/${PROGNAME}.fifo as file-based FIFO, with distinct push and pop streams ...
   sprintf(ofile, "%s%c%s.fifo", OPATH, PATHSEPCHAR, PROGNAME);
   Fpush = fopen(ofile, "w");
   if (Fpush == NULL) abend("Cannot create Fpush!");
   // Make our FIFO writes line-buffered ...
   setvbuf(Fpush, NULL, _IOLBF, 2048);
   Fpop = fopen(ofile, "r");
   if (Fpop == NULL) abend("Cannot open Fpop!");
}

// init_worker_pool() - 3rd initialization; all worker-pool and WorkerData inits here ...

// NOTE: Even though variable accesses are uncontended here, they are wrapped by their
// respective mutexes to assure they are flushed to globally-coherent memory.
// NOTE: Only outputs here are via abend(), because FLog may not yet be initialized.

void
init_worker_pool(void)
{
   int w_id;
   pthread_mutexattr_t mattr;
   pthread_condattr_t cattr;

   // Start with default mutex characteristics ...
   pthread_mutexattr_init(&mattr);
   // ... add: return -1 rather than deadlock if same thread does extra lock tries ...
   pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK);

   // Take default condition variable characteristics ...
   pthread_condattr_init(&cattr);

   // ------------------------------------------------------------------------

   // Initialize each worker's thread-specific data and start their pThreads ...
   bzero(&WorkerData, sizeof(WorkerData));				// Start with all zeroes
   for (w_id=0; w_id<N_WORKERS; w_id++) {
      WDAT.w_id = w_id;
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
      WS[w_id] = calloc(1, sizeof(pwalk_stats_t));			// Worker statistics

      // Worker's wakeup mechanism ...
      if (pthread_cond_init(&(WDAT.WORKER_cv), &cattr))		// Condition Variable
         abend("FATAL: Can't init WORKER cv!\n");
      if (pthread_mutex_init(&(WDAT.WORKER_cv_mutex), &mattr))	// Associated Mutex
         abend("FATAL: Can't init WORKER cv mutex!\n");

      // Start the worker's pThread ...
      if (pthread_create(&(WDAT.thread), NULL, worker_thread, &(WDAT.w_id)))
         abend("FATAL: Can't start pthread!\n");
      WDAT.wstate = BORN;					// Successfully born worker
   }

   // ------------------------------------------------------------------------

   // Cleanup ...
   pthread_mutexattr_destroy(&mattr);
   pthread_condattr_destroy(&cattr);
}

/* @@@ SECTION: Multi-path support (primitive) @@@ */

// parse_paths() - get alternate 'equivalent paths' from -paths= parameter file
// klooge: PRIMITIVE ERROR HANDLING; all assert()

void
parse_paths(char *parfile)
{
   int fd, fsize, i, len, rc;
   char *p, *buf;
   struct stat sb;

   // Open -paths= file and read entirely into memory ...
   assert ((fd = open(parfile, O_RDONLY)) >= 0);
   assert (fstat(fd, &sb) == 0);			// get st_size from stat()
   assert ((fsize = sb.st_size) <= 8191);		// arbitrary sanity check
   assert ((buf = calloc(1, fsize+1)));
   assert ((rc = read(fd, buf, fsize)) == fsize);
   close (fd);

   // Change all non-graphic characters to NULs and point PATH[i] to each run of graphic chars ...
   for (p=buf; p<(buf+fsize); ) {
      if (!isgraph(*p)) {
         *p++ = '\0';
      } else {
         assert (NPATHS < MAXPATHS);
         PATHS[NPATHS] = p;
         while (isgraph(*p)) p++;
         *p = '\0';
         if (VERBOSE) printf("PATHS[%d] = \"%s\"\n", NPATHS, PATHS[NPATHS]);	// Capture path
         assert (access(PATHS[NPATHS], R_OK|X_OK) == 0);			// Must be accessible
         assert (stat(PATHS[NPATHS], &sb) == 0);				// Get st_mode from stat()
         assert (S_ISDIR(sb.st_mode));						// Must be a dir
         NPATHS += 1;
      }
   }
   if (VERBOSE) printf("NPATHS=%d\n", NPATHS);
   assert (NPATHS > 0);								// Must specifiy SOME paths
   len = strlen(PATHS[0]);
   for (i=1; i<NPATHS; i++) assert (strlen(PATHS[i]) == len);
}

void
path_prefix(char *path, int worker)
{
   int i;

   // === klooge: needs robustness added here ...
   if (NPATHS) {	// Overwrite initial path with worker-specific path ...
      i = worker % NPATHS;
      strncpy(path, PATHS[i], strlen(PATHS[i]));
   }
}

// path_is_snapdir() - TRUE iff filename is ".snapshot" or ".snapshots"
// NOTE: Since this is ONLY called by fifo_push(), it SHOULD only be evaluated for DIRECTORIES

int
path_is_snapdir(char *path)
{
   char *p;

   p = rindex(path, PATHSEPCHAR);			// Isolate last pathname element
   if (p == NULL) p = path;
   else p += 1;
   if (strncmp(p, ".snapshot", 9)) return 0;		// False: Cannot match
   if (strcmp(p, ".snapshot") == 0) return 1;		// True: ".snapshot"
   if (strcmp(p, ".snapshots") == 0) return 1;		// True: ".snapshots"
   return 0;						// False: Something follows '.snapshot(s)'
}

/* @@@ SECTION: pwalk -fix_times support @@@ */

// NOTE: w_id is passed-in for WLOG macro, as this operates in an MT context ...
// If -shadow not specified, or no shadow file found, return 0
// Otherwise, return 1 with passed stat structure populated from shadow

int
shadow_time(char *path, struct stat *pssb, int w_id)
{
   char shadow_path[MAX_PATHLEN+16];
   char *p;

   if (SHADOW_DIR) {
      // Calculate shadow pathname ...
      if (strncmp(path, "/mnt/", 5) != 0) { printf("FATAL: \"/mnt/\" not initial pathname!\n"); exit(-1); }
      if ((p = index(path + 5, '/')) == NULL) { printf("FATAL: malformed path!\n"); exit(-1); }
      strcpy(shadow_path, SHADOW_DIR);
      strcat(shadow_path, p);
      if (lstat(shadow_path, pssb)) return 0;	// no shadow file exists
      if (pssb->st_mtime == 0) return 0;	// shadow time is zero
   }
   return 1;					// valid shadow time exists
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
pwalk_fix_times(char *filename, char *filepath, struct stat *oldsbp, int w_id)
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
   struct stat sfsb;		// shadow file stat buf
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
   if (bad_timespec(&(oldsbp->st_atimespec))) { bad_time_mask |= 8; bad_time_str[0] = '1'; atime_OK = 0; }
   if (bad_timespec(&(oldsbp->st_mtimespec))) { bad_time_mask |= 4; bad_time_str[1] = '1'; mtime_OK = 0; }
   if (bad_timespec(&(oldsbp->st_ctimespec))) { bad_time_mask |= 2; bad_time_str[2] = '1'; ctime_OK = 0; }
   if (bad_timespec(&(oldsbp->st_birthtimespec))) { bad_time_mask |= 1; bad_time_str[3] = '1'; btime_OK = 0; }
   if (bad_time_mask == 0) return;			// No trouble found!

   // Encode file type ...
   if (S_ISREG(oldsbp->st_mode)) ftype = '-';
   else if (S_ISDIR(oldsbp->st_mode)) ftype = 'd';
   else if (S_ISBLK(oldsbp->st_mode)) ftype = 'b';
   else if (S_ISCHR(oldsbp->st_mode)) ftype = 'c';
   else if (S_ISLNK(oldsbp->st_mode)) ftype = 'l';
   else if (S_ISSOCK(oldsbp->st_mode)) ftype = 's';
   else if (S_ISFIFO(oldsbp->st_mode)) ftype = 'p';
   else ftype = '?';

   // mtime_strategy coding scheme ...
   //    Shadow cases ...
   //    's' - use shadow mtime, because old mtime is BAD
   //    'S' - use shadow mtime, because it's newer than old mtime (unlikely)
   //    'M' - use old mtime, because it's newer than shadow mtime (likely)
   //    Non-Shadow cases ...
   //    'm' - use old mtime, because it's OK
   //    'c' - use old ctime, because it's OK
   //    'n' - use 'now' time, because no other option was selected
   //    'R' - Revert good btime to earlier mtime
   //    'C' - Change good btime to earlier ctime
   // NOTE: for mtime_strategy of 'm' or 'M', touch_strategy[mtime] = '-' (ie: no change) ... however,
   // if utimes() is used to set atime, mtime value must also be set.

   // First, determine mtime_strategy ...
   mtime_strategy = '-';						// Initially undecided ...
   if (SHADOW_DIR && shadow_time(filepath, &sfsb, w_id)) {		// Nonzero shadow mtime exists ...
      if (!mtime_OK) mtime_strategy = 's';							// Use shadow mtime (old mtime BAD)
      else if (oldsbp->st_mtimespec.tv_sec < sfsb.st_mtimespec.tv_sec) mtime_strategy = 'S';	// Use shadow mtime (> old mtime (unlikely))
      else mtime_strategy = 'M';								// Use old mtime (>= shadow mtime (likely))
   } else if (mtime_OK) {
      mtime_strategy = 'm';						// 1st choice: use OK old mtime.
   } else if (ctime_OK) {
      mtime_strategy = 'c';						// 2nd choice: use OK old ctime.
   } else {
      mtime_strategy = 'n';						// 3rd choice: use 'now' time as last resort.
   }

   // Put chosen mtime value in ts_time[1] ...
   switch (tolower(mtime_strategy)) {
   case 'c':	// Use old ctime ...
      ts_ttime[1].tv_sec = oldsbp->st_ctimespec.tv_sec;
      ts_ttime[1].tv_nsec = oldsbp->st_ctimespec.tv_nsec;
      break;
   case 's':	// Use shadow mtime ...
      ts_ttime[1].tv_sec = sfsb.st_mtimespec.tv_sec;
      ts_ttime[1].tv_nsec = sfsb.st_mtimespec.tv_nsec;
      break;
   case '-':	// Carry forward old mtime ...
   case 'm':
      ts_ttime[1].tv_sec = oldsbp->st_mtimespec.tv_sec;
      ts_ttime[1].tv_nsec = oldsbp->st_mtimespec.tv_nsec;
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
   // For atime: If BAD, use the mtime per mtime_strategy.  If OK, use old atime in case
   // utimes() is called to set mtime.
   // WARNING: Over SMB or NFS, server may apply its own atime instead of passed value.
   // In other words if atime strategy shows 'no change' ('-') it may still be changed.
   // If atime is applied via vtimes() native to OneFS, it should match mtime precisely.
   if (atime_OK) {
      ts_ttime[0].tv_sec = oldsbp->st_atimespec.tv_sec;
      ts_ttime[0].tv_nsec = oldsbp->st_atimespec.tv_nsec;
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
   // we do -- but if the old value was BAD, then we set 'n' for 'now' in the strategy string
   // to convey that fact.  There is no API means available for setting ctime explicitly to any
   // value of our choosing.
   if (!ctime_OK) touch_strategy[2] = 'n';

   // -----------------------------------------------------------------------------------------
   // For birthtime: If BAD, we will apply the EARLIER of our chosen mtime or a good old ctime.
   // If the old birthtime is OK but greater than our chosen mtime, we will apply our chosen mtime,
   // -- which is EXACTLY what utimes() is SUPPOSED to do.
   // WARNING: utimes() over NFS and SMB do NOT correct future btime values on OneFS.
   // WARNING: The OneFS-local utimes() call corrects a future btime, but does not require
   // another utimes() call to set the atime and mtime. HOWEVER, on OneFS, we may just use the
   // OneFS-private vtimes() call to explciitly set the btime.
   // WARNING: A OneFS birthtime can ONLY be explicitly set via the OneFS-private vtimes().
   btime_strategy = '-';
   if (!btime_OK) {		// Use the earlier of chosen mtime or the old valid ctime
      if (ctime_OK && (oldsbp->st_ctimespec.tv_sec < ts_ttime[1].tv_sec))
         btime_strategy = 'C';			// 'Change' to ctime which predates chosen mtime ...
      else
         btime_strategy = mtime_strategy;	// Chosen mtime might be any of [mMsSnc] ...
   } else {
      if (oldsbp->st_birthtimespec.tv_sec > ts_ttime[1].tv_sec)
         btime_strategy = 'R';			// 'Revert' to chosen mtime ...
   }

   // Prepare to apply the btime_strategy ...
   if (btime_strategy != '-') {
      touch_strategy[3] = btime_strategy;
      btime_OK = 0;		// It may be 'OK', but this triggers our adjustment logic later.
      switch (tolower(btime_strategy)) {
      case 'c':			// Use old ctime ...
         ts_ttime[2].tv_sec = oldsbp->st_ctimespec.tv_sec;
         ts_ttime[2].tv_nsec = oldsbp->st_ctimespec.tv_nsec;
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
   strcpy(atime_epoch_str, format_epoch_ts(&(oldsbp->st_atimespec)));
   strcpy(mtime_epoch_str, format_epoch_ts(&(oldsbp->st_mtimespec)));
   strcpy(ctime_epoch_str, format_epoch_ts(&(oldsbp->st_ctimespec)));
   strcpy(btime_epoch_str, format_epoch_ts(&(oldsbp->st_birthtimespec)));
   fprintf(WLOG, "# %c%s %s \"%s\" a=%s m=%s c=%s b=%s%s\n",
      ftype, touch_strategy,
      bad_time_str,
      filename,
      atime_epoch_str,
      mtime_epoch_str,
      ctime_epoch_str,
      btime_epoch_str,
      (oldsbp->st_birthtime != oldsbp->st_ctime) ? " NOTE: B!=C" : ""
      );

   // COMMANDs: These emitted commands are for native execution on OneFS, assuming;
   // (1) user scripts the OneFS commands by selecting either 'touch' or 'touch3' commands, and
   // (2) user corrects the pathsnames in each command to reflect the actual OneFS absolute paths.

   // COMMAND #1: touch [-A [-][[hh]mm]SS] [-acfhm] [-r file] [-t [[CC]YY]MMDDhhmm[.SS]] file ...
   localtime_r((time_t *) &(ts_ttime[0].tv_sec), &touch_t_tm);
   strftime(touch_t_str, sizeof (touch_t_str) - 1, "%G%m%d%H%M.%S", &touch_t_tm);
   fprintf(WLOG, "touch -%s -t %s \"%s\"\n", atime_OK ? "mc" : "amc", touch_t_str, filepath);

   // COMMAND #2: touch3 <info> <atime> <mtime> <btime> <ifs_pathname> ...
   // NOTE: pwalk_create_shadow depends on these 'touch3' commands ...
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


/* @@@ SECTION: pwalk -audit support @@@ */

#if PWALK_AUDIT // OneFS only

// Basic logic for extracting <path>'s worm state is ...
// python -c 'import isi.fs.domain;import sys;print isi.fs.domain.get_domain_info('<path>')['worm_state'];'
// worm_state: {'committed': 0, 'ctime': 0L, 'retention_date': 0L}
// python -u // unbuffered I/O mode
// python -E // ignore environment vbls

// pwalk_audit_keys() - Secret decoder ring for .audit output files (awk -F, $column numbers) ...

void
pwalk_audit_keys(void)
{
   fprintf(Flog, "AUDIT: Column indexes for -audit ...\n");
   fprintf(Flog, "AUDIT:	1.  lock_domain_type - SmartLock domain type;\n");
   fprintf(Flog, "AUDIT:	  'E' - Enterprise\n");
   fprintf(Flog, "AUDIT:	  'C' - Compliance\n");
   fprintf(Flog, "AUDIT:	  '-' - Neither\n");
   fprintf(Flog, "AUDIT:	2.  lock_status - SmartLock lock status;\n");
   fprintf(Flog, "AUDIT:	  '-' - Not locked\n");
   fprintf(Flog, "AUDIT:	  'C' - Committed (READONLY, NON-DELETABLE)\n");
   fprintf(Flog, "AUDIT:	  'c' - Latent Commit (READONLY, ?POSSIBLY-DELETABLE?)\n");
   fprintf(Flog, "AUDIT:	  'X' - eXpired (READONLY, DELETABLE)\n");
   fprintf(Flog, "AUDIT:	3.  w_ref_date - Reference time of worm status enquiry\n");
   fprintf(Flog, "AUDIT:	4.  st_atime\n");
   fprintf(Flog, "AUDIT:	5.  st_mtime\n");
   fprintf(Flog, "AUDIT:	6.  st_ctime\n");
   fprintf(Flog, "AUDIT:	7.  st_birthtime\n");
   fprintf(Flog, "AUDIT:	8.  w_ctime\n");
   fprintf(Flog, "AUDIT:	9.  w_retention_date\n");
   fprintf(Flog, "AUDIT:	10.  eff_auto_date - Ephemeral AutoCommit date\n");
   fprintf(Flog, "AUDIT:	11.  eff_exp_type - Basis of effective expiration date;\n");
   fprintf(Flog, "AUDIT:	   '<' - past (persisted,expired; committed with eff_exp_date in the past)\n");
   fprintf(Flog, "AUDIT:	   '>' - future (persisted, committed)\n");
   fprintf(Flog, "AUDIT:	   '=' - forced (persisted, uncommitted w/ w_retention_date from WORM state)\n");
   fprintf(Flog, "AUDIT:	   '!' - future (override)\n");
   fprintf(Flog, "AUDIT:	   '*' - future (ephemeral, based on future autocommit)\n");
   fprintf(Flog, "AUDIT:	   '+' - TBD (expiration not ascertainable)\n");
   fprintf(Flog, "AUDIT:	   '?' - ERROR: unexpected case w/ persisted expiration!\n");
   fprintf(Flog, "AUDIT:	   '#' - ERROR: unexpected fall-through\n");
   fprintf(Flog, "AUDIT:	12.  eff_exp_date - Effective expiration date\n");
   fprintf(Flog, "AUDIT:	13.  st_uid\n");
   fprintf(Flog, "AUDIT:	14.  st_size\n");
   fprintf(Flog, "AUDIT:	15.  st_blocks\n");
   fprintf(Flog, "AUDIT:	16.  \"<ifspath>\"\n");
}

// Shell scripting hints for analyzing .audit files ...
//
// Discover likely 'stuck' worm_state.cdate values ...
// cat *.audit | awk -F, '{print $8}' | sort | uniq -c | sort -n | tail
//
// For 'stuck' worm_state.cdate values, determine diversity of uid ...
// cat *.audit | awk -F, '$8 == 1455685665 {print "uid=",$14}' | sort | uniq -c
//
// Create script to do 'touch -at' commands ...
// cat *.audit | awk -F, '$8 == 1455685665 {print "touch -at",$12,$15}'
//
// One can use touch(1) to change a file's w_ctime, but it will also cause the file's
// expiration date to be persisted using the domain's MINIMUM offset value rather than
// its DEFAULT offset value  -- which can be pretty confusing. A SmartLock-aware
// program should be able to innoculate against the autocommit offset lapsing by
// issuing a net-zero-change metadata-write operation just after opening the file,
// such as doing a chown(2) to re-state the file's owner uid, or perhaps a chmod(2) to
// re-state its mode bit settings. Because open(), chown(), and chmod() are all synchronous
// NFS operations, that would have the effecting of pushing the autocommit time comfortably
// ahead in time.

// CAUTION: pwalk_audit_file() must be re-entrant -- so no static locals!

void
pwalk_audit_file(char *ifspath, struct stat *sb, unsigned crc_val, int w_id)
{
   char pycmd[64], pyout[1024], *pnext, *p;
   int nvals;
   // Response variables from Python symbiont call ...
   char py_p;			// Must always be 'P' in Python response
   int py_rc;
   int py_errno;
   int w_committed;		// File WORM state values ...
   time_t w_ref_date;
   time_t w_ctime;
   time_t w_retention_date;
   time_t w_auto_offset;	// SmartLock DOMAIN values ...
   time_t w_min_offset;
   time_t w_max_offset;
   time_t w_def_offset;
   time_t w_override_date;
   // Derived a.k.a. "ephemeral" values ...
   long eff_ctime, eff_auto_date, eff_exp_date;	
   int expired;		// boolean
   // Formatting buffers and formats ...
   char lock_domain_type, lock_status, eff_exp_type;
   char *default_date_strf;
   char w_ref_date_str[64], *w_ref_date_strf;
   char st_atime_str[64], *st_atime_strf;
   char st_mtime_str[64], *st_mtime_strf;
   char st_ctime_str[64], *st_ctime_strf;
   char st_birthtime_str[64], *st_birthtime_strf;
   char w_ctime_str[64], *w_ctime_strf;
   char w_retention_date_str[64], *w_retention_date_strf;
   char eff_ctime_str[64], *eff_ctime_strf;
   char eff_auto_date_str[64], *eff_auto_date_strf;
   char eff_exp_date_str[64], *eff_exp_date_strf;

   // Skip directories ...
   if (S_ISDIR(sb->st_mode)) return;

   // --- Fragile pipe-based Python request/response logic for fetching WORM metadata ---
   //
   // Python is re-started after every 50,000 calls because it was determined that the
   // particular logic being used caused it to fail after about 100,000 calls -- presumeably
   // due to heap exhaustion or other such issue. This logic is a 'Software Aging and
   // Rejuvenation (SAR) strategy that will not be necessary when this logic is re-coded to
   // use OneFS native C-language APIs.

   if ((WS[w_id]->NPythonCalls % 50000) == 0) {	// Start or re-start Python co-process
      if (WDAT.PYTHON_PIPE) {
         fprintf(WDAT.PYTHON_PIPE, "-1\n");	// Signal script to exit()
         pclose(WDAT.PYTHON_PIPE);
      }
      WDAT.PYTHON_PIPE = popen(PYTHON_COMMAND, "r+");
      if (VERBOSE > 2) { fprintf(WLOG, "@ <START Python>\n"); fflush(WLOG); }
   }
   if (WDAT.PYTHON_PIPE == NULL) abend("Cannot start Python co-process!");

   // @@@ Fetch raw WORM info for OneFS LIN @@@
   sprintf(pycmd, "%llu", sb->st_ino);
   fprintf(WDAT.PYTHON_PIPE, "%s\n", pycmd);		// Python REQUEST is just inode (LIN)
   WS[w_id]->NPythonCalls += 1;
   fgets(pyout, sizeof(pyout), WDAT.PYTHON_PIPE);	// Python RESPONSE
   if (VERBOSE > 2) { fprintf(WLOG, "@ << %s", pyout); fflush(WLOG); }

   // Parse OneFS WORM info from Python co-process (normally 12 space-delimited columns) ...
   //        print 'P',     				-> py_p (literal 'P' always 1st value, else die!)
   //        print 0,     				-> py_rc (0 on successful fetch of WORM data)
   //        print 0,     				-> py_errno
   //        print worm_state['committed'],		-> w_committed
   //        print ref_date,  				-> w_ref_date
   //        print worm_state['ctime'],			-> w_ctime (WORM compliance clock ctime)
   //        print worm_state['retention_date'],       	-> w_retention_date
   //        print domain_info['autocommit_offset'],	-> w_auto_offset
   //        print domain_info['min_offset'],		-> w_min_offset
   //        print domain_info['max_offset'],		-> w_max_offset
   //        print domain_info['default_offset'],	-> w_def_offset
   //        print domain_info['override_retention']	-> w_override_date
   // NOTE: 18446744073709551614 == 0x7FFFFFFFFFFFFFFF -- which is default max_retention of FOREVER
   //	sscanf() on OneFS will not parse it as a signed long long, so unsigned is used to avoid overflow
   py_p = '?';
   assert (sizeof(time_t) == 8);
   nvals = sscanf(pyout, "%c %i %i %llu %i %llu %llu %llu %llu %llu %llu %llu",
      &py_p,
      &py_rc,
      &py_errno,
      &w_ref_date,
      &w_committed,
      &w_ctime,
      &w_retention_date,
      &w_auto_offset,
      &w_min_offset,
      &w_max_offset,
      &w_def_offset,
      &w_override_date);
   if (((nvals != 12) && (nvals < 3)) || py_p != 'P') {	// Should never happen
      fflush(WLOG);
      fprintf(WLOG, "@ \"%s\"\n", ifspath);
      fprintf(WLOG, "@ pycmd: \"%s\"\n", pycmd);
      fprintf(WLOG, "@ nvals: %d\n", nvals);
      fprintf(WLOG, "@ pyout: %s", pyout);
      fflush(WLOG);
      while (fgets(pyout, sizeof(pyout), WDAT.PYTHON_PIPE))	// Drain Python output
         fputs(pyout, WLOG);
      fflush(WLOG);
      abend("Python symbiont error! Unexpected response format!\n");
   }
   if (VERBOSE > 2) {
      fprintf(WLOG, "@ >> %c %d %d %llu %d %llu %llu %llu %llu %llu %llu %llu\n",
         py_p, py_rc, py_errno,
         w_ref_date,
         w_committed, w_ctime, w_retention_date,
         w_auto_offset, w_min_offset, w_max_offset, w_def_offset, w_override_date);
      fflush(WLOG);
   }

   // @@@ No SmartLock info; return @@@
   if (py_rc) {
      WS[w_id]->NPythonErrors += 1;
      fprintf(WLOG, "-,%d,0,0,0,0,0,0,0,0,0,0,\"?\",0,%u,%lld,%lld,\"%s\"\n",
         py_rc, sb->st_uid, sb->st_size, sb->st_blocks, ifspath);
      return;
   }

   // @@@ Derive 'effective' and 'ephemeral' values @@@

   // AutoCommit decisions are based on 'effective' ctime ...
   eff_ctime = (w_ctime) ? w_ctime : sb->st_ctime;		// f(Compliance v. Enterprise mode)

   // Effective autocommit time is zero when autocommit offset is zero ...
   if (w_auto_offset)						// Autocommit enabled
      eff_auto_date = eff_ctime + w_auto_offset;		// Ephemeral autocommit date
   else								// No autocommit
      eff_auto_date = 0;

   // Determine effective expiration date as ...
   // (a) already persisted, or
   // (b) ephemeral (based on eff_auto_date), or
   // (c) TBD (not ascertainable)
   if (w_committed || w_retention_date) {
      eff_exp_date = w_retention_date;		// Expiration date previously persisted (but file not necessarily committed)
   } else if (eff_auto_date) {
      eff_exp_date = eff_auto_date + w_def_offset;	// Expiration date is ephemeral, based on hypothetical future autocommit
   } else {
      eff_exp_date = 0;					// Expiration date not ascertainable
   }

   // Apply min and max domain constraints ...			// === VALIDATE! ===
   // TBD ...

   // Apply override date ...
   if (eff_exp_date < w_override_date) eff_exp_date = w_override_date;		// === VALIDATE! ===

   // Expired status (includes 'expired just this second') ...
   expired = w_committed && (eff_exp_date <= w_ref_date);

   // Characterize file's effective expiration date ...
   if (expired) {
      eff_exp_type = '<';						// Expiration is PAST (expired; committed with expiration in the past)
   } else if (eff_exp_date == 0) {
      eff_exp_type = '+';						// Expiration is TBD; not ascertainable
   } else if (eff_exp_date == w_override_date) {
      eff_exp_type = '!';						// Expiration is from domain OVERRIDE value
   } else if (eff_exp_date == w_retention_date) {	// (Expiration is WORM-persisted ...)
      if (eff_exp_date != sb->st_atime) eff_exp_type = '=';		// Expiration is persisted, but not committed
      else if (w_committed) eff_exp_type = '>';				// Expiration is persisted, file is committed but not expired
      else eff_exp_type = '?';						// ERROR: unexpected case w/ persisted expiration!
   } else if (eff_auto_date && eff_exp_date) {
      eff_exp_type = '*';						// future (ephemeral)
   } else {
      eff_exp_type = '#';						// ERROR: unexpected fall-through!
   }

   // @@@ Output Formatting @@@

   // Format ENTERPRISE versus COMPLIANCE mode ...
   lock_domain_type = w_ctime ? 'C' : 'E';

   // Format COMMITTED state (order of tests very important here) ...
   if (expired) lock_status = 'X';						// eXpired
   else if (w_committed) lock_status = 'C';					// Committed
   else if (eff_auto_date && (eff_auto_date <= w_ref_date)) lock_status = 'c';	// Latent commit
   else lock_status = '-';

   // Format dates ... with an eye towards future parametrization ...
   // "%G%m%d%H%M.%S" -> YYYYMMDDhhmm.ss (for 'touch -at YYYYMMDDhhmm.ss <file>')
   // "%F %T" -> "YYYY-MM-DD HH:MM:SS"       
   // NULL -> format raw Unix epoch time (w/o TZ adjustment)

   default_date_strf = NULL;			// Default to Unix epoch time
   st_atime_strf = default_date_strf;
   st_mtime_strf = default_date_strf;
   st_ctime_strf = default_date_strf;
   st_birthtime_strf = default_date_strf;
   w_ref_date_strf = default_date_strf;
   w_ctime_strf = default_date_strf;
   w_retention_date_strf = default_date_strf;
   eff_ctime_strf = default_date_strf;
   eff_auto_date_strf = default_date_strf;
   eff_exp_date_strf = default_date_strf;

   pwalk_format_time_t(&(sb->st_atime), st_atime_str, sizeof(st_atime_str), st_atime_strf);
   pwalk_format_time_t(&(sb->st_mtime), st_mtime_str, sizeof(st_mtime_str), st_mtime_strf);
   pwalk_format_time_t(&(sb->st_ctime), st_ctime_str, sizeof(st_ctime_str), st_ctime_strf);
   pwalk_format_time_t(&(sb->st_birthtime), st_birthtime_str, sizeof(st_birthtime_str), st_birthtime_strf);
   pwalk_format_time_t(&w_ref_date, w_ref_date_str, sizeof(w_ref_date_str), w_ref_date_strf);
   pwalk_format_time_t(&w_ctime, w_ctime_str, sizeof(w_ctime_str), w_ctime_strf);
   pwalk_format_time_t(&w_retention_date, w_retention_date_str, sizeof(w_retention_date_str), w_retention_date_strf);
   pwalk_format_time_t(&eff_ctime, eff_ctime_str, sizeof(eff_ctime_str), eff_ctime_strf);
   pwalk_format_time_t(&eff_auto_date, eff_auto_date_str, sizeof(eff_auto_date_str), eff_auto_date_strf);
   pwalk_format_time_t(&eff_exp_date, eff_exp_date_str, sizeof(eff_exp_date_str), eff_exp_date_strf);

   // @@@ OUTPUT (audit): NORMAL -audit output line (14 columns) ...
   // fprintf(WLOG, "%c,%c,%s,%s,%s,%s,%s,%s,%s,%c,%s,%u,%lld,%lld,\"%s\"\n",
   //    lock_domain_type, lock_status,
   //    w_ref_date_str, st_atime_str, st_mtime_str, st_ctime_str, eff_ctime_str, st_birthtime_str,
   //    eff_auto_date_str, eff_exp_type, eff_exp_date_str,
   //    sb->st_uid, sb->st_size, sb->st_blocks, ifspath);
   fprintf(WLOG, "%c,%c,%s,%s,%s,%s,%s,%s,%s,%s,%c,%s,%u,%lld,%lld,\"%s\"\n",
      lock_domain_type, lock_status,
      w_ref_date_str, st_atime_str, st_mtime_str, st_ctime_str, st_birthtime_str,
      w_ctime_str, w_retention_date_str,
      eff_auto_date_str, eff_exp_type, eff_exp_date_str,
      sb->st_uid, sb->st_size, sb->st_blocks, ifspath);
}

#endif // PWALK_AUDIT

/* @@@ SECTION: pwalk +tally support @@@ */

// Results is array with [0] == *T row, plus 6 buckets such than [6] == ">= 180" ...
//
// [0] total
// [1] atime < 30 days
// [2] atime < 60 days
// [3] atime < 90 days
// [4] atime < 120 days
// [5] atime < 180 days
// [6] atime >= 180 days
//
// "Tag","Age","Files","Files%","Size","Size%","Space","Space%"
// "<tagval>","< 30",#files_total,N%,#size_total,N%,#space_total,N%
// "<tagval>","< 60",#files_total,N%,#size_total,N%,#space_total,N%
// "<tagval>","< 90",#files_total,N%,#size_total,N%,#space_total,N%
// "<tagval>","< 120",#files_total,N%,#size_total,N%,#space_total,N%
// "<tagval>","< 180",#files_total,N%,#size_total,N%,#space_total,N%
// "<tagval>",">=180",#files_total,N%,#size_total,N%,#space_total,N%

void
pwalk_tally_file(struct stat *sb, int w_id)
{
   int atime_match, days_since_accessed;
   int i;

   // We only tally regular files here ...
   if (!S_ISREG(sb->st_mode)) return;

   for (i=0; i<7; i++) {
      days_since_accessed = (START_TIMEVAL.tv_sec - sb->st_atime)/SECS_PER_DAY;
      atime_match = (days_since_accessed < TALLY_INFO[i].days) || (i == 6);
      if (i == 0 || atime_match) {
         WS[w_id]->TALLY_STATS[i].NFiles += 1;
         WS[w_id]->TALLY_STATS[i].NBytesNominal += sb->st_size;
         WS[w_id]->TALLY_STATS[i].NBytesAllocated += sb->st_blocks * ST_BLOCK_SIZE;
         if (atime_match) break;
      }
   }
}

void
pwalk_tally_output()
{
   FILE *TALLY;
   char ofile[MAX_PATHLEN+2];
   int i, j, w_id;

   // Output stats ...
   sprintf(ofile, "%s%cpwalk.tally", OPATH, PATHSEPCHAR);
   TALLY = fopen(ofile, "w");
   if (TALLY == NULL) abend("Cannot create .tally file!");

   // Heading row ...
   fprintf(TALLY, "\"%s\"%s", "Tag", ",");
   fprintf(TALLY, "\"%s\"%s", "Age", ",");
   fprintf(TALLY, "\"%s\"%s", "Files", ",");
   fprintf(TALLY, "\"%s\"%s", "Files%", ",");
   fprintf(TALLY, "\"%s\"%s", "Size", ",");
   fprintf(TALLY, "\"%s\"%s", "Size%", ",");
   fprintf(TALLY, "\"%s\"%s", "Space", ",");
   fprintf(TALLY, "\"%s\"%s", "Space%", "\n");

   // Results is Total plus 6 buckets ...
   // (Division operations protected in calculating percentage columns!)
   for (i=0; i<7; i++) {
      j = (i != 6) ? i+1 : 0;	// To output Total last ...
      if (TALLY_INFO[j].days == 0) continue;
      fprintf(TALLY, "\"%s\",\"%s\",%llu,%4.2f%%,%llu,%4.2f%%,%llu,%4.2f%%\n",
         TALLY_TAG,
         TALLY_INFO[j].label,
         GS.TALLY_STATS[j].NFiles,
         (GS.TALLY_STATS[0].NFiles == 0) ? 0. : GS.TALLY_STATS[j].NFiles * 100. / GS.TALLY_STATS[0].NFiles,
         GS.TALLY_STATS[j].NBytesNominal,
         (GS.TALLY_STATS[0].NBytesNominal == 0) ? 0. : GS.TALLY_STATS[j].NBytesNominal * 100. / GS.TALLY_STATS[0].NBytesNominal,
         GS.TALLY_STATS[j].NBytesAllocated,
         (GS.TALLY_STATS[0].NBytesAllocated == 0) ? 0. : GS.TALLY_STATS[j].NBytesAllocated * 100. / GS.TALLY_STATS[0].NBytesAllocated
      );
   }
   fclose(TALLY);
}

// selected() is a TEMPORARY placeholder for file-selection logic. Files and directories which return
// FALSE will not be output.

int
selected(char *path, struct stat *sb)
{
   // Blacklist excludes ...
   if (S_ISDIR(sb->st_mode)) return (0);		// Skip dirs
   // Whitelist includes ...
   if (!S_ISREG(sb->st_mode)) return (1);		// Include all non-ordinary files
   if (strstr(path, "|")) return (1);			// Include names with '|'
   // Default is to exclude ...
   return (0);
}

/* @@@ SECTION: FIFO management @@@ */

// Must be re-entrant because multiple workers may be pushing new pathnames at the same time.
// Access is serialized by MP_mutex. These push and pop routines are atomic as far as the
// rest of the program logic is concerned; so the depth of the FIFO is never ambiguous for
// even an instant.

// fifo_push() - Store passed pathname in a tmpfile-based FIFO.

void
fifo_push(char *pathname)
{
   char msg[2048];

   // Ignore .snapshot directories unless '+.snapshot' was specified ...
   if (!DOT_SNAPSHOT && path_is_snapdir(pathname)) {
      sprintf(msg, "NOTICE: Skipping \"%s\"\n", pathname);
      LogMsg(msg);
      return;
   }

   assert (Fpush != NULL);
   if (pthread_mutex_lock(&MP_mutex))				// +++ MP lock +++
      abend("FATAL: Can't get FIFO lock in fifo_push()!\n");
   fprintf(Fpush, "%s\n", pathname);				// push
   FIFO_PUSHES += 1;
   pthread_mutex_unlock(&MP_mutex);				// --- MP lock ---
}

// fifo_pop() - Pop FIFO into passed pathname, returning pre-pop FIFO depth.

// Always returns current (pre-pop) depth of the FIFO (ie: 0 -> FIFO is empty).
// If passed pathname is NULL, do not actually pop the FIFO; just determine its depth.
// If passed pathname is not NULL, pop FIFO into the passed buffer.

int
fifo_pop(char *pathname)
{
   char *p;
   int fifo_depth, rc;

   assert(Fpop != NULL);	// File handle for FIFO pops

   if (pthread_mutex_lock(&MP_mutex))				// +++ MP lock +++
      abend("FATAL: Can't get FIFO lock in fifo_pop()!\n");
   fifo_depth = FIFO_PUSHES - FIFO_POPS;
   if (fifo_depth == 0 || pathname == NULL) {
      pthread_mutex_unlock(&MP_mutex);				// --- MP lock ---
      return(fifo_depth);
   }
   // Still holding MP lock ...
   pathname[0] = '\0';
   if (fgets(pathname, MAX_PATHLEN, Fpop) == NULL)	// pop (or die!)
      abend("FATAL: fifo_pop() read failure!\n");
   FIFO_POPS += 1;
   pthread_mutex_unlock(&MP_mutex);				// --- MP lock ---

   // Details, details ...
   p = index(pathname, '\n'); // Remove newline or die ...
   if (p) *p = '\0';
   else abend("FATAL: Popped FIFO entry ill-formed; has no newline!\n");

   return(fifo_depth);
}

/* @@@ SECTION: worker_thread() @@@ */

// worker_thread() - Worker pThread ...

// Up to N_WORKERS of these may be running concurrently. This is the outer control loop
// for a worker, which ultimately calls a single 'payload' function when the worker is
// awoken; in this case, directory_scan(). Each worker remains BUSY as long as it can
// pop more work for directory_scan() from the FIFO. When a worker runs out of work, it
// transitions from BUSY an IDLE, but might be re-awakened by manage_workers(). Each of
// these workers remains active until shut down from main().

void *
worker_thread(void *parg)
{
   int w_id = *((int *) parg); // Unique our thread & passed on to subordinate functions
   sigset_t sigmask;
   unsigned long wakeups;
   char msg[256];

   // Disable all signals in our thread ...
   sigemptyset(&sigmask);
   if (pthread_sigmask(SIG_SETMASK, &sigmask, NULL))
      abend("WARNING: Can't block signals!\n");

   // We hold our own cv lock at all times past here except during our condition wait ...
   if (pthread_mutex_lock(&WDAT.WORKER_cv_mutex))	// +++ WORKER cv lock +++
      abend("FATAL: Can't get WORKER cv lock prior to first condition wait!\n");

   // Transition from BORN to IDLE ...
   pthread_mutex_lock(&MP_mutex);				// +++ MP lock +++
   WDAT.wstate = IDLE;
   pthread_mutex_unlock(&MP_mutex);				// --- MP lock ---

   // Wakeup whenever signaled by our condition variable ...
   while (1) {							// Multiple wakeup loop
      while (WDAT.wstate == IDLE) {				// Wakeup polling loop
         // Block on our condition variable ...
         pthread_cond_wait(&(WDAT.WORKER_cv), &(WDAT.WORKER_cv_mutex));
         // Anything to do?
         if (fifo_pop(NULL)) {
            // Transition to BUSY ...
            pthread_mutex_lock(&MP_mutex);			// +++ MP lock +++
            WDAT.wstate = BUSY;
            pthread_mutex_unlock(&MP_mutex);			// --- MP lock ---
         }
      }

      // WAKEUP accounting and logging ...
      if (pthread_mutex_lock(&WAKEUP_mutex))			// +++ WAKEUP lock +++
         abend("FATAL: Can't get WAKEUP lock to increment N_Worker_Wakeups!\n");
      wakeups = N_Worker_Wakeups += 1;
      pthread_mutex_unlock(&WAKEUP_mutex);			// --- WAKEUP lock ---
      sprintf(msg, "@ Worker %d wakeup (wakeup #%lu)\n", w_id, wakeups);
      LogMsg(msg); LogMsg(NULL);

      // Remain BUSY as long as the FIFO is not empty ...
      while (fifo_pop(WDAT.DirPath)) {
         path_prefix(WDAT.DirPath, w_id);			// Apply multi-path logic
         if (!WDAT.wlog) worker_log_create(w_id);
         directory_scan(w_id);					// $$$ WORKER'S MISSION $$$
      }

      // Transition from BUSY to IDLE and log it...
      pthread_mutex_lock(&MP_mutex);				// +++ MP lock +++
      WDAT.wstate = IDLE;
      pthread_mutex_unlock(&MP_mutex);				// --- MP lock ---
      sprintf(msg, "@ Worker %d idle\n", w_id);
      LogMsg(msg); LogMsg(NULL);
   }
}

/* @@@ SECTION: manage_workers() @@@ */

// manage_workers() - Manage worker threads. Only called once; this loop lasts for
// the duration of the 'workers active' phase of pwalk operation. Returns when all
// workers are IDLE *and* the FIFO is empty.

void
manage_workers()
{
   int w_id = 0, last_w_id_woken = -1;
   int fifo_depth, nw_to_wake, nw_wakeups, nw_idle, nw_busy, iterations;
   wstate_t wstate;
   char msg[256];

   // Worker management loop ...
   iterations = 0;	// Cyclic [0-100]
   while (1) {
      // Get a COHERENT inventory of worker status and FIFO status ...
      while (1) {
         nw_idle = nw_busy = 0;
         pthread_mutex_lock(&MP_mutex);					// +++ MP lock +++
         for (w_id=0; w_id < N_WORKERS; w_id++) {
            if (WDAT.wstate == IDLE) nw_idle++;
            if (WDAT.wstate == BUSY) nw_busy++;
         }
         fifo_depth = FIFO_PUSHES - FIFO_POPS;
         pthread_mutex_unlock(&MP_mutex);				// --- MP lock ---
         // NOTE: *ALL* worker threads *must* be either IDLE or BUSY at this
         // juncture, so if a laggard thread needs a chance to finish being BORN,
         // we yield to them before looping ...
         if ((nw_idle + nw_busy) == N_WORKERS) break;			// Inventory coherent!
         yield_cpu();
      }

      // Do a little housekeeping every few seconds ...
      if ((iterations % 100) == 0) {	// Every ~10 seconds (100 * 100 ms loop wait)
         if (PWdebug) {
            sprintf(msg, "= manage_workers(fifo_depth=%d nw_idle=%d nw_busy=%d)\n",
               fifo_depth, nw_idle, nw_busy);
            LogMsg(msg);
         }
         LogMsg(NULL);			// Gratuitous log-flush
         iterations = 0;
      }

      // Are we done yet?
      if ((nw_busy == 0) && (fifo_depth == 0)) break;			// All done!

      // Are we completely busy?
      if (nw_busy == N_WORKERS) goto loop;	// "I'm givin' ya all we got, Captain!"

      // Wakeup workers as needed. Workers transition themselves between IDLE and BUSY.
      //
      // Determine how many workers to wake. We might wake a worker that subsequently
      // finds no work to do and rapidly returns to IDLE, but that's OK. Indeed, a newly-
      // woken worker may well find the FIFO has already been emptied by some already-BUSY
      // worker thread, in which case it will simply remain IDLE.
      //
      // Note that a worker's state may have transitioned since we took our inventory
      // above, so we inquire in a lock-protected way here. We do not care if an IDLE
      // worker was one from our inventory above; only that it's IDLE now. No worker can
      // transition back from IDLE to BUSY until and unless we wake them.
      //
      nw_to_wake = (fifo_depth < nw_idle) ? fifo_depth : nw_idle;
      if (nw_to_wake > 0) {
         // Round-robin/LRU worker assign logic ...
         w_id = last_w_id_woken;
         for (nw_wakeups=0; nw_wakeups < nw_to_wake; ) {
            w_id = ((w_id+1) < N_WORKERS) ? w_id+1 : 0;
            pthread_mutex_lock(&MP_mutex);				// +++ MP lock +++
            wstate = WDAT.wstate;
            pthread_mutex_unlock(&MP_mutex);				// --- MP lock ---
            if (wstate == IDLE) {
               // Signal for worker to wakeup ...
               if (pthread_cond_signal(&(WDAT.WORKER_cv)))
                  abend("FATAL: Worker cv signal error!\n");
               nw_wakeups += 1;
               last_w_id_woken = w_id;
            }
         }
      }
loop:
      // Throttle this outer worker wakeup loop at 10 iterations per second.
      // We yield_cpu() here to reduce scheduling contention with newly-awakened worker
      // threads while they are transitioning between states.
      iterations++;
      yield_cpu();
      usleep(100000);	// 100000us = 0.100000s delay between outer loop iterations ...
      yield_cpu();
   }
}

/* @@@ SECTION: directory_scan() @@@ */

// directory_scan() - Thread-safe directory-scanner.

// Process WDAT.DirPath with reentrant stdlib readdir_r() calls to walk directories.

// NOTE: It would be tempting to cwd to the directory we are scanning to avoid having to
// concatenate the pathname and filename before each stat(), but the cwd is process-wide,
// and we are just one on many threads in this process.

// struct stat { // Cribsheet ...
//    dev_t    st_dev;    /* device inode resides on */
//    ino_t    st_ino;    /* inode's number */
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

void
directory_scan(int w_id)		// CAUTION: MT-safe and RE-ENTRANT!
{
   DIR *dir;
   int fd, dfd, dirent_type;
   int i, rc, have_stat, has_acl;
   int openit;				// Flag that we must open target entry
   int pathlen, namelen;
   struct dirent *pdirent, *result;
   struct stat sb;
   char owner_sid[128], group_sid[128];
   char owner_name[64], group_name[64];
   unsigned crc_val;			// +crc results
   char crc_str[16];			// ... formatted as hex
   long long t0, t1, t2;		// For high-resolution timing samples
   long long ns_stat, ns_getacl;	// ns for stat() and get ACL calls
   char ns_stat_s[32], ns_getacl_s[32];	// Formatted timing values
   char mode_str[16];			// Formatted mode bits
   char *DirPathName;			// Pointer to WDAT.DirPath
   char *FileName;			// Pointer to dirent's filename
   char FullPathName[MAX_PATHLEN+1];	// Dirname or filename relative to cwd
   off_t bytes_allocated;		// Per-file allocated space
   unsigned char rbuf[128*1024];	// READONLY read buffer for +crc and +denist (cheap, on-stack, could be better)
   size_t nbytes;			// READONLY bytes read
   struct {				// Per-Directory Statistics (subtotals) ...
      count_64 NStatCalls;		// Number of calls to lstat() during scans
      count_64 NStatErrors;		// ... # that were errors
      count_64 NDirs;			// ... # that were directories
      count_64 NFiles;			// ... # that were files
      count_64 NOthers;			// ... # that were others
      count_64 NWarnings;		// Scan issues other than stat() failures
      off_t NBytesAllocated;		// Sum of allocated space
      off_t NBytesNominal;		// Sum of nominal file sizes
      count_64 NACLs;			// Count of ACLs
   } DS;
   char emsg[MAX_PATHLEN+256];
   char rc_msg[64] = "";
   // void *directory_acl = NULL;		// For +inherit functionality #####

#if PWALK_ACLS // POSIX ACL-related local variables ...
   // Interface to pwalk_acls module ...
   int aclstat;        		        // 0 == none, &1 == acl, &2 == trivial, &4 == dacl
   acl4_t acl4;
   char pw_acls_emsg[128] = "";
   int pw_acls_errno = 0;
   char acl4OUTmode;			// 'o' (file) or 'p' (pipe)
#endif // PWALK_ACLS

   // @@@ ACCESS (dir enter): opendir() just-popped directory ...
   DirPathName = WDAT.DirPath;
   if (VERBOSE) {
      sprintf(emsg, "@ Worker %d popped %s\n", w_id, DirPathName);
      LogMsg(emsg);
      if (VERBOSE > 1) LogMsg(NULL);	// force flush
      if (VERBOSE > 2) { fprintf(WLOG, "@%s\n", DirPathName); fflush(WLOG); }
      if (VERBOSE > 2) { fprintf(WLOG, "@opendir\n"); fflush(WLOG); }
   }

   // Here's the opendir() ...
   dir = opendir(DirPathName);
   if (dir == NULL) {						// @@ <warning> ...
      // Directory open errors (ENOEXIST, !ISDIR, etc) just provoke WARNING output.
      // klooge: want to skip ENOEXIST, EPERM, EBUSY, but otherwise process non-directory FIFO entry
      rc = errno;
      WS[w_id]->NWarnings += 1;
      if (Cmd_XML) fprintf(WLOG, "<warning> Cannot diropen() %s (rc=%d) </warning>\n", DirPathName, rc);
      sprintf(emsg, "WARNING: Worker %d cannot diropen() %s (rc=%d)\n", w_id, DirPathName, rc);
      LogMsg(emsg);  LogMsg(NULL); // Force-flush these errors
      goto exit_scan; // Skip to summary for this popped entry ...
   }
   WS[w_id]->NDiropens += 1;

   // @@@ GATHER (dir enter): Get directory's metadata - fstat() ...
   // Get fstat() info on the now-open directory (not counted with the other stat() calls) ...
#if SOLARIS
   dfd = dir->dd_fd;
#else
   dfd = dirfd(dir);
#endif
   ns_stat_s[0]='\0';
   if (TSTAT) t0 = gethrtime();
   fstat(dfd, &sb);		// klooge: assuming success because it's open
   if (TSTAT) { t1 = gethrtime(); ns_stat = t1 - t0; sprintf(ns_stat_s," (%lldus) ", ns_stat/1000); }
   if (VERBOSE > 2) { fprintf(WLOG, "@stat\n"); fflush(WLOG); }
   format_mode_bits(mode_str, sb.st_mode);

   // Initialize Directory Subtotals (DS) with size of the directory itself ...
   bzero(&DS, sizeof DS);
   DS.NBytesNominal = sb.st_size;
   DS.NBytesAllocated = bytes_allocated = sb.st_blocks * ST_BLOCK_SIZE;

   // @@@ GATHER: Get directory ACL for inheritance reasons ...
   // directory_acl = pwalk_acl_get_fd(dfd);	// #####

   // @@@ GATHER/PROCESS (dir enter): ACLs ...
#if defined(__ONEFS__)
   has_acl = (sb.st_flags & SF_HASNTFSACL);
#else
   has_acl = 0;		// It's a flag on OneFS, but another metadata call elsewhere (for later)
#endif
#if PWALK_ACLS		// POSIX-to-NFS4 ACL logic (Linux only) ...
   ns_getacl_s[0]='\0';
   if (P_ACL_PLUS || Cmd_XACLS || Cmd_WACLS) {
      // INPUT & TRANSLATE: Translate POSIX ACL plus DACL to a single ACL4 ...
      pw_acl4_get_from_posix_acls(DirPathName, 1, &aclstat, &acl4, pw_acls_emsg, &pw_acls_errno);
      if (TSTAT) { t2 = gethrtime(); ns_getacl = t2 - t1; sprintf(ns_getacl_s," (%lldus) ", ns_getacl/1000); }
      if (pw_acls_errno) {		// Log both to main log and worker's log ...
         DS.NWarnings += 1;
         sprintf(emsg, "WARNING: \"%s\": %s [%d - \"%s\"]\n", DirPathName, pw_acls_emsg, pw_acls_errno, strerror(pw_acls_errno));
         LogMsg(emsg); LogMsg(NULL);
         if (Cmd_XML) fprintf(WLOG, "<warning> \"%s\": %s (rc=%d) %s </warning>\n",
            DirPathName, pw_acls_emsg, pw_acls_errno, strerror(pw_acls_errno));
         else
            fprintf(WLOG, "%s", emsg);
      }
      if (aclstat) {
         strcat(mode_str, "+");
         DS.NACLs += 1;			// Only count *directories* HERE, when we pop them, not when they are pushed
      } else strcat(mode_str, ".");
   }
#else
   if (has_acl && P_MODE) strcat(mode_str, "+");	// Actually only works in OneFS
#endif // PWALK_ACLS

   // @@@ GATHER (dir enter): Owner name, group name, owner_sid, group_sid ...
   get_owner_group(&sb, owner_name, group_name, owner_sid, group_sid);
#if defined(__ONEFS__)
   onefs_get_sids((dir)->dd_fd, owner_sid, group_sid);
   // FWIW, OSX has different DIR struct ..
   // onefs_get_sids(dir->__dd_fd, owner_sid, group_sid);
#endif
   if (VERBOSE > 2) fprintf(stderr, "> %s %s <\n", mode_str, DirPathName);

   // @@@ ACTION/OUTPUT (dir enter): Perform requested actions on <directory> itself ...
   if (Cmd_SELECT && !selected(DirPathName, &sb)) {	// No output!
      ;
   } else if (Cmd_XML) {
      fprintf(WLOG, "<directory>\n");
      // Format <path> output line ...
      fprintf(WLOG, "<path> %lld%s%s %u %lld %s%s </path>\n",
         bytes_allocated, (P_MODE ? " " : ""), mode_str, sb.st_nlink, (long long) sb.st_size, DirPathName, ns_stat_s);
   } else if (Cmd_LS) {
      fprintf(WLOG, "\n%s:\n", DirPathName);
   } else if (Cmd_FIXTIMES) {
      // fprintf(WLOG, "# \"%s\":\n", DirPathName);
   } 

   // @@@ PROCESS (dir enter): +rm_acls ...
#if defined(__ONEFS__)		// OneFS-specific features ...
   // if (!PWdryrun) pwalk_acl_modify(dfd, directory_acl, ...);	// #####
   if (Cmd_RM_ACLS) {		// klooge: dupe code for <directory> vs. <dirent>
      rc = onefs_rm_acls(dfd, DirPathName, &sb, (char *) &rc_msg);
      if (rc < 0) {
         WS[w_id]->NWarnings += 1;
         sprintf(emsg, "WARNING: onefs_rm_acls(\"%s\") for \"%s\"\n", rc_msg, FullPathName);
         LogMsg(emsg);
      } else if (rc > 0) {
         WS[w_id]->NACLs += 1;
         sprintf(emsg, "@ %s \"%s\"\n", rc_msg, FullPathName); fputs(emsg, WLOG);
      }
   }
#endif

   // @@@ DIRECTORY SCAN LOOP: push dirs s we go ...

   // Copy DirPath to buffer in which we will iteratively append filenames from dirents ...
   strcpy(FullPathName, DirPathName);
   pathlen = strlen(FullPathName);
   FullPathName[pathlen++] = PATHSEPCHAR;
   FullPathName[pathlen] = '\0';
   pdirent = WDAT.Dirent; // Convenience pointer

   // NOTE: readdir_r() is the main potential metadata-reading LATENCY HOTSPOT
   if (VERBOSE > 2) { fprintf(WLOG, "@readdir_r loop\n"); fflush(WLOG); }
   while (((rc = readdir_r(dir, pdirent, &result)) == 0) && (result == pdirent)) {
      // Quietly skip "." and ".." ...
      FileName = pdirent->d_name;
      if (strcmp(FileName, ".") == 0) continue;
      if (strcmp(FileName, "..") == 0) continue;

      // Construct FullPathName from current directory entry (dirent) ...
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
         fprintf(WLOG, "<warning> Cannot expand %s! </warning>\n", DirPathName);
         sprintf(emsg, "WARNING: Worker %d- %s expansion would exceed MAX_PATHLEN (%d)\n",
            w_id, FileName, MAX_PATHLEN);
         LogMsg(emsg); LogMsg(NULL);
         continue;
      }
      strcpy(FullPathName+pathlen, FileName);

      // @@@ GATHER (dirent): fstat() info ...
      // Get FullPathName's metadata via stat() or perhaps just from the dirent's d_type ...
      // At this juncture, we MUST know if the dirent is a directory or not, so we can decide when
      // to recurse on directories. Over NFS, this requires a stat() call, but on a local filesystem,
      // we could use the current dirent->d_type value for this purpose to accelerate treewalk speed.
      // Some dormant code here is aimed at leveraging that in the future.
      have_stat = 0;
      mode_str[0] = '\0';
      ns_stat_s[0] = '\0';
      ns_getacl_s[0] = '\0';
      if (Cmd_AUDIT && 0) {		// DORMANT/EXPERIMENTAL: FAST TREEWALK W/O STAT() - FUTURE
         // Avoid stat() call, require d_type ...
         if (pdirent->d_type == DT_UNKNOWN) {
            fprintf(WLOG, "ERROR: DT_UNKNOWN %s\n", FullPathName);
            continue;
         }
         if (pdirent->d_type == DT_REG || pdirent->d_type == DT_DIR) dirent_type = pdirent->d_type;
         else dirent_type = DT_UNKNOWN;
      } else {
         if (TSTAT) t0 = gethrtime();
         rc = lstat(FullPathName, &sb);
         if (TSTAT) { t1 = gethrtime(); sprintf(ns_stat_s," (%lldus) ", (t1-t0)/1000); }
         DS.NStatCalls += 1;
         if (rc) {							// @@ <warning> ...
            DS.NStatErrors += 1;
            WS[w_id]->NWarnings += 1;
            if (Cmd_XML) fprintf(WLOG, "<warning> Cannot lstat() %s (rc=%d) </warning>\n", FullPathName, rc);
            sprintf(emsg, "WARNING: Cannot lstat() %s (rc=%d)\n", FullPathName, rc);
            LogMsg(emsg);  LogMsg(NULL); // Force-flush these errors
            continue;
         }
         have_stat = 1;
         format_mode_bits(mode_str, sb.st_mode);
         if S_ISREG(sb.st_mode) dirent_type = DT_REG;
         else if S_ISDIR(sb.st_mode) dirent_type = DT_DIR;
         else dirent_type = DT_UNKNOWN;
      }

      // @@@ GATHER (dirent): Process direct's ACL ...
#if defined(__ONEFS__)
      has_acl = (sb.st_flags & SF_HASNTFSACL);
#else
      has_acl = 0;	// It's a flag on OneFS, but another metadata call elsewhere (for later)
#endif
#if PWALK_ACLS // Linux ACL-related logic for a <file> ....
      ns_getacl_s[0]='\0';
      acl4.n_aces = 0;
      if (P_ACL_PLUS || Cmd_XACLS || Cmd_WACLS) {
         assert(have_stat);		// klooge: primitive insurance
         // INPUT & TRANSLATE: Translate POSIX ACL plus DACL to a single ACL4 ...
         pw_acl4_get_from_posix_acls(FullPathName, S_ISDIR(sb.st_mode), &aclstat, &acl4, pw_acls_emsg, &pw_acls_errno);
         if (TSTAT) { t2 = gethrtime(); ns_getacl = t2 - t1; sprintf(ns_getacl_s," (%lldus) ", ns_getacl/1000); }
         if (pw_acls_errno) {		// Log both to main log and worker's log ...
            DS.NWarnings += 1;
            sprintf(emsg, "WARNING: \"%s\": %s [%d - \"%s\"]\n", DirPathName, pw_acls_emsg, pw_acls_errno, strerror(pw_acls_errno));
            LogMsg(emsg); LogMsg(NULL);
            if (Cmd_XML) fprintf(WLOG, "<warning> \"%s\": %s (rc=%d) %s </warning>\n",
               DirPathName, pw_acls_emsg, pw_acls_errno, strerror(pw_acls_errno));
            else
               fprintf(WLOG, "%s", emsg);
            continue;
         }
         if (aclstat) {
            strcat(mode_str, "+");
            if (!S_ISDIR(sb.st_mode)) DS.NACLs += 1;	// Only count *directories* when we pop them (ie: not here) ...
         } else strcat(mode_str, ".");
      }
#else
      if (has_acl && P_MODE) strcat(mode_str, "+");	// Actually only works in OneFS
#endif // PWALK_ACLS

      // @@@ GATHER (dirent): Space accounting information ... and PUSH any directories encountered ...
      if (dirent_type == DT_DIR) {
         DS.NDirs += 1;
         // NOTE: If we are 'fixing' ACLs, we need to fix directory ACLs BEFORE they are PUSH'ed!
         // NOTE: At (depth == 0), we will assume the directory ACLs are to be preserved.
         // As soon as we PUSH this directory, some other worker may POP it, and it will not
         // do ACL inheritance operations correctly if we have not fixed the directory's ACL first.
         //onefs_acl_inherit(CurrentDirectoryACL, -1, FullPathName, isdir, depth);	// #####
         fifo_push(FullPathName);
         // NOTE: To avoid multiple-counting, we only count the nominal directory size ONCE; when we pop it
         sb.st_blocks = 0;
         sb.st_size = 0;
      } else if (dirent_type == DT_REG) {
         DS.NFiles += 1;
      } else {
         DS.NOthers += 1;
      }
      DS.NBytesNominal += sb.st_size;
      DS.NBytesAllocated += bytes_allocated = sb.st_blocks * ST_BLOCK_SIZE;

      // @@@ GATHER (dirent): Owner name & group name ...
      get_owner_group(&sb, owner_name, group_name, owner_sid, group_sid);

      // @@@ ACTION (dirent): open(READONLY) if we need to read file or query from file handle.
      // For OneFS PWget_SD, we must open each file|dir to get its security_descriptor.
      // For OneFS +rm_acls  we must open each file|dir to get&set its security_descriptor.
      // For +crc and +denist, we must only open each non-zero-length ordinary file.
      // Multiple purposes might be served from the open file handle.
      openit = 0;
      if (Cmd_RM_ACLS || (PWget_MASK & PWget_SD)) openit = 1;
      if ((Cmd_DENIST || P_CRC32) && (dirent_type == DT_REG)) {
         if (sb.st_size == 0) {			// Do not open zero-length files ...
            crc_val = 0;
            WS[w_id]->READONLY_Zero_Files += 1;
         } else {
            openit = 1;
         }
      }
      if (!openit) goto outputs;

      // OK, so we need to do an open() - NOT following links ...
      // NOTE: OneFS has O_OPENLINK to explcitly permit opening a symlink!
      if ((fd = open(FullPathName, O_RDONLY|O_NOFOLLOW|O_OPENLINK, 0)) < 0) {
         WS[w_id]->READONLY_Errors += 1;
         sprintf(emsg, "ERROR: Cannot READONLY open() \"%s\" errno=%d\n", FullPathName, rc);
         LogMsg(emsg);
         goto outputs;
      }

      // File is now open ...
      WS[w_id]->READONLY_Opens += 1;
      if (Cmd_DENIST) {						// This is ALL that +denist does!
         nbytes = pread(fd, &rbuf, 128, 0);
         if (nbytes > 0) WS[w_id]->READONLY_DENIST_Bytes += nbytes;
         else WS[w_id]->READONLY_Errors += 1;
      }
      if (P_CRC32) {
         nbytes = crc32(fd, (void *) rbuf, sizeof(rbuf), &crc_val);
         if (nbytes > 0) WS[w_id]->READONLY_CRC_Bytes += nbytes;
         // Cross-check that we read all bytes of the file ...
         // ==== if (nbytes != sb.st_size) WS[w_id]->READONLY_Errors += 1;	// === Add error!
      }
#if defined(__ONEFS__)		// OneFS-specific features ...
      // if (!PWdryrun) pwalk_acl_modify(fd, directory_acl, S_ISDIR(sb.st_mode));	// #####
      if (Cmd_RM_ACLS) {
         rc = onefs_rm_acls(fd, FullPathName, &sb, (char *) &rc_msg);
         // klooge: add counters for acls modified or removed (rc == 1 or 2, respectively)
         if (rc < 0) {
            WS[w_id]->NWarnings += 1;
            sprintf(emsg, "WARNING: onefs_rm_acls(\"%s\") for \"%s\"\n", rc_msg, FullPathName);
            LogMsg(emsg);
         } else if (rc > 0) {
            WS[w_id]->NACLs += 1;
            sprintf(emsg, "@ %s \"%s\"\n", rc_msg, FullPathName); fputs(emsg, WLOG);
         }
      }
      if (PWget_MASK & PWget_SD) {
         onefs_get_sids(fd, owner_sid, group_sid);
         if (VERBOSE > 2) fprintf(stderr, "< %s %s >\n", owner_sid, group_sid);
      }
#endif
      // Close ...
      close(fd);							// ... close()

outputs:
      // @@@ OUTPUT (dirent): Per-dirent information & added processing (<file>) ...
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
         (PMODE ? " " : ""), mode_str, (long long) sb.st_size, FileName, ns_stat_s,
         UL(sb.st_birthtime), UL(sb.st_ctime), UL(sb.st_atime), UL(sb.st_mtime),
         (UL(sb.st_birthtime) != UL(sb.st_ctime)) ? " NOTE: B!=C" : ""
         );
      //    (UL(sb.st_mtime) != UL(sb.st_ctime)) ? " NOTE: M!=C" : ""
#endif

      // @@@ OUTPUT: Handle primary mutually-exclusive operating modes ...
      if (Cmd_SELECT && !selected(FileName, &sb)) {	// No output!
         ;
      } else if (Cmd_LS) {			// -ls
         fprintf(WLOG, "%lld%s%s %u %lld %s%s%s\n",
            bytes_allocated, (P_MODE ? " " : ""), mode_str, sb.st_nlink, (long long) sb.st_size, FileName,
            ns_stat_s, crc_str);
      } else if (Cmd_XML) {		// -xml
         fprintf(WLOG, "<file> %lld%s%s %u %lld %s%s%s </file>\n",
            bytes_allocated, (P_MODE ? " " : ""), mode_str, sb.st_nlink, (long long) sb.st_size, FileName,
            ns_stat_s, crc_str);
      } else if (Cmd_AUDIT) {		// -audit
#if PWALK_AUDIT // OneFS only
         pwalk_audit_file(FullPathName, &sb, crc_val, w_id);
#else
         abend("FATAL: -audit not supported");
#endif // PWALK_AUDIT
      } else if (Cmd_FIXTIMES) {	// -fixtimes
         pwalk_fix_times(FileName, FullPathName, &sb, w_id);
      } else if (Cmd_CSV) {		// -csv= (DEVELOPMENTAL: Temporary placeholder code)
         if (Cmd_SELECT) {
            fprintf(WLOG, "\"%s\"\n", FullPathName);
         } else {			// klooge: SHOULD BE call to reporting module
            fprintf(WLOG, "%u,%s,%s,%u,%s,%s,\"%s\"\n",
               sb.st_uid, owner_name, owner_sid, sb.st_gid, group_name, group_sid, FullPathName);
         }
      }

      // @@@ OUTPUT (dirent): ... also '+tally' output ...
      if (Cmd_TALLY)
         pwalk_tally_file(&sb, w_id);

      // @@@ OUTPUT (dirent): ... also +wacls & +xacls ACL4 outputs (all are no-ops with an empty acl4) ...
#if PWALK_ACLS // Linux-only ACL-related outputs ...
      if (acl4.n_aces) {
         if (Cmd_WACLS) {
            if (!WDAT.WACLS_PIPE) ; // === in-process
            pw_acl4_fwrite_binary(&acl4, FullPathName, &(WDAT.WACLS_PIPE), acl4OUTmode, pw_acls_emsg, &pw_acls_errno);
         }
         if (Cmd_XACLS & Cmd_XACLS_BIN) {
            if (!WDAT.XACLS_BIN_FILE) worker_aux_create(w_id, &(WDAT.XACLS_BIN_FILE), "acl4bin");
            pw_acl4_fwrite_binary(&acl4, FullPathName, &(WDAT.XACLS_BIN_FILE), acl4OUTmode, pw_acls_emsg, &pw_acls_errno);
         }
         if (Cmd_XACLS & Cmd_XACLS_CHEX) {
            if (!WDAT.XACLS_CHEX_FILE) worker_aux_create(w_id, &(WDAT.XACLS_CHEX_FILE), "acl4chex");
            pw_acl4_fprintf_chex(&acl4, FullPathName, &sb, WDAT.XACLS_CHEX_FILE);
         }
         if (Cmd_XACLS & Cmd_XACLS_NFS) {
            if (!WDAT.XACLS_NFS_FILE) worker_aux_create(w_id, &(WDAT.XACLS_NFS_FILE), "acl4nfs");
            pw_acl4_fprintf_nfs4_setfacl(&acl4, FullPathName, WDAT.XACLS_NFS_FILE);
         }
         if (Cmd_XACLS & Cmd_XACLS_ONEFS) {
            if (!WDAT.XACLS_ONEFS_FILE) worker_aux_create(w_id, &(WDAT.XACLS_ONEFS_FILE), "acl4onefs");
            pw_acl4_fprintf_onefs(&acl4, FullPathName, &sb, WDAT.XACLS_ONEFS_FILE);
         }
      }
#endif // PWALK_ACLS
   }

exit_scan:
   // @@@ End-of-directory processing ...
   if (dir != NULL) {
      rc = closedir(dir);
      if (VERBOSE > 2) { fprintf(WLOG, "@closedir rc=%d\n", rc); fflush(WLOG); }

      // @@@ Aggregate per-directory statistics (DS) to per-worker statistics (WS[w_id]) ...
      // NOTE: Before pwalk exists, it will sum all per-worker statistics to form its global statistics (GS).
      WS[w_id]->NStatCalls += DS.NStatCalls;
      WS[w_id]->NStatErrors += DS.NStatErrors;
      WS[w_id]->NFiles += DS.NFiles;
      WS[w_id]->NDirs += DS.NDirs;
      WS[w_id]->NOthers += DS.NOthers;
      WS[w_id]->NBytesAllocated += DS.NBytesAllocated;
      WS[w_id]->NBytesNominal += DS.NBytesNominal;
      WS[w_id]->NACLs += DS.NACLs;

      // @@@ OUTPUT (dir end): End-of-directory outputs ...
      if (Cmd_XML) {
         fprintf(WLOG, "<summary> %llu files %llu dirs %llu other %llu errors %llu allocated %llu nominal </summary>\n",
            DS.NFiles, DS.NDirs, DS.NOthers, DS.NStatErrors, DS.NBytesAllocated, DS.NBytesNominal);
         fprintf(WLOG, "</directory>\n");
      } else if (Cmd_LS) {
         fprintf(WLOG, "total %llu files %llu dirs %llu other %llu errors %llu allocated %llu nominal\n",
            DS.NFiles, DS.NDirs, DS.NOthers, DS.NStatErrors, DS.NBytesAllocated, DS.NBytesNominal);
      }
   }

   // Flush worker's output at end of each directory ...
   fflush(WLOG);
}

/* @@@ SECTION: Top-level pwalk logic & main() @@@ */

// process_cmdopts() - Process command-line options w/ rudimentary error-checking ...

void
process_cmdopts(int argc, char *argv[])
{
   char *arg;
   char msg[256];
   char *mx_options, *p;
   int narg, npaths, noptions;

   // @@@ Command-line argument processing ...
   for (npaths=0,narg=1; narg < argc; narg++) {
      arg = argv[narg];
      if (sscanf(arg, "-dop=%d", &N_WORKERS) == 1) {
         continue;
      } else if (strncmp(arg, "-paths=", strlen("-paths=")) == 0) {
         parse_paths(arg+strlen("-paths="));
      } else if (strncmp(arg, "-shadow=", strlen("-shadow=")) == 0) {
         SHADOW_DIR = malloc(strlen(arg));
         strcpy(SHADOW_DIR, arg+strlen("-shadow="));
         strcat(SHADOW_DIR, "/");
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
      } else if (strcmp(arg, "-ls") == 0) {		// Basic -ls & -xml modes ...
         Cmd_LS = 1;
      } else if (strcmp(arg, "-xml") == 0) {
         Cmd_XML = 1;
      } else if (strcmp(arg, "-cmp") == 0) {
         Cmd_CMP = 1;
      } else if (strcmp(arg, "-fix_times") == 0) {
         Cmd_FIXTIMES = 1;
      } else if (strncmp(arg, "-csv=", 5) == 0) {
         pwalk_report_parse(arg+5);
         Cmd_CSV = 1;
      } else if (strcmp(arg, "-v") == 0) {		// Verbosity ...
         VERBOSE += 1;
         if (VERBOSE > 2) fprintf(stderr, "VERBOSE=%d\n", VERBOSE);
      } else if (strcmp(arg, "-d") == 0) {		// Debug ...
         PWdebug += 1;
      } else if (strcmp(arg, "-acls") == 0) {		// Suppress showing ACL presence (ie: with '+')
         P_ACL_PLUS = 0;
      } else if (strcmp(arg, "+crc") == 0) {		// Tag-along modes ...
         P_CRC32 = 1;
      } else if (strcmp(arg, "-select") == 0) {
         Cmd_SELECT = 1;
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
      } else if (strcmp(arg, "+.snapshot") == 0) {	// also traverse .snapshot[s] directories
         DOT_SNAPSHOT = 1;
      } else if (strcmp(arg, "+tstat") == 0) {		// also add timed stats
         TSTAT = 1;
      } else if (strcmp(arg, "-dryrun") == 0) {		// Modifiers ...
         PWdryrun = 1;
      } else if (strncmp(arg, "-cd=", 4) == 0) {
         CD_ARG = arg + 4;
      } else if (strcmp(arg, "-gz") == 0) {
         GZ_OUTPUT = 1;
      } else if (strcmp(arg, "-pmode") == 0) {
         P_MODE = 0;
      } else if (*arg == '-' || *arg == '+') {		// Unknown +/- option ...
         usage();
      } else { // Everything else assumed to be a pathname ...
         // NOTE: our FIFO is only created AFTER all args are validated, so we can't push these yet!
         npaths++;
      }
   }

   // @@@ Command-line argument sanity checking ...

   if (N_WORKERS < 0 || N_WORKERS > MAX_WORKERS) {
      fprintf(Flog, "ERROR: -dop=<N> must be on the range [1 .. %d]!\n", MAX_WORKERS);
      exit(-1);
   }

   if (Cmd_CMP && !SHADOW_DIR) {
      fprintf(Flog, "ERROR: '-cmp' requires '-shadow=' arg!\n");
      exit(-1);
   }

   mx_options = "[ ls | xml | fix_mtime | cmp | audit | csv ]";	// Mutually Exclusive options
   noptions = Cmd_LS + Cmd_XML + Cmd_FIXTIMES + Cmd_CMP + Cmd_AUDIT + Cmd_CSV;
   if (noptions > 1) {
      fprintf(Flog, "ERROR: Only one of %s allowed!\n", mx_options);
      exit(-1);
   }

   noptions += Cmd_DENIST + Cmd_TALLY + Cmd_XACLS + Cmd_WACLS + Cmd_RM_ACLS;
   if (noptions < 1) usage();		// nothing to do

   if (Cmd_WACLS && (strlen(WACLS_CMD) < 5)) {	// crude and arbitrary
      fprintf(Flog, "ERROR: '+wacls=' requires '<command>' value!\n");
      exit(-1);
   }

   if (npaths < 1)							// Most basic check is last
      usage();
}

int
main(int argc, char *argv[])
{
   int i, w_id;
   int rc;
   char *emsg;
   // Statistics ...
   double t_elapsed_sec, t_s;
   int t_h, t_m;
   struct rusage p_usage, c_usage;
   struct tms cpu_usage;
   struct utsname uts;
   int exit_status = 0;		// Succeed by default

   // ------------------------------------------------------------------------

   // @@@ main() entry & initializations ...

   // Die quickly if not 64-bit file offsets ...
   assert ( sizeof(GS.NBytesAllocated) == 8 );

   // Default Flog output to stderr, flushing on newlines. We'll replace this with
   // a shared buffered log stream after our output directory is created.
   Flog = fopen("/dev/stderr", "w");
   setvbuf(Flog, NULL, _IOLBF, 2048);

#if defined(__LINUX__)
   // Get CLK_TIC (when not #defined) ...
   CLK_TCK = sysconf(_SC_CLK_TCK);
#endif

   // Capture our start times ...
   T_START = gethrtime();
   gettimeofday(&START_TIMEVAL, NULL);

   // Take note of our default directory ...
#if defined(SOLARIS) || defined(__LINUX__)
   CWD = getcwd(NULL, MAX_PATHLEN+1);
#else
   CWD = getwd(NULL);
#endif

   // Initialize stats blocks ...
   bzero(&GS, sizeof(pwalk_stats_t));			// 'GS' is 'Global Stats'
   for (i=0; i<(MAX_WORKERS+1); i++) WS[i] = NULL; 	// 'WS' is 'Worker Stats'

   // ------------------------------------------------------------------------

   // Initialize global mutexes ...
   init_main_mutexes();

   // Process command-line options (excluding root paths) ...
   process_cmdopts(argc, argv);

   // Create output dir (OPATH), pwalk.log (Flog), and pwalk.fifo ...
   init_main_outputs();

   // Log command-line recap ...
   fprintf(Flog, "NOTICE: cmd =");
   for (i=0; i<argc; i++) fprintf(Flog, " %s", argv[i]);
   fprintf(Flog, "\n");

   // Log operational context ...
   fprintf(Flog, "NOTICE: cwd = %s\n", CWD);
   fprintf(Flog, "NOTICE: output = %s\n", OPATH);

   if (CD_ARG) {	// Iff -cd= argument was specified, chdir() there for all that follows ...
      if (chdir(CD_ARG)) {
         emsg = malloc(8192);
         sprintf(emsg, "Cannot cd to \"%s\"\n", CD_ARG);
         abend(emsg);
      }
      fprintf(Flog, "NOTICE: -cd = %s\n", CD_ARG);
   }

   (void) uname(&uts);
   fprintf(Flog, "NOTICE: utsname = %s (%s %s %s %s)\n",
      uts.nodename, uts.sysname, uts.release, uts.version, uts.machine);
   fprintf(Flog, "NOTICE: pid = %d\n", getpid());

   for (i=1; i < argc; i++)	// Push initial command-line <directory> args to FIFO ...
      if (*argv[i] != '-' && *argv[i] != '+') {
         fifo_push(argv[i]);
      }

   // Force flush Flog so far. HENCEFORTH, Flog WRITES from WORKERS GO THRU LogMsg() ...
   LogMsg(NULL);

   // ------------------------------------------------------------------------

   // @@@ Start worker threads ...
   init_worker_pool();

   // ------------------------------------------------------------------------

   // @@@ Main runtime loop ...
   manage_workers();		// Runs until all workers are IDLE and FIFO is empty

   // ------------------------------------------------------------------------

   // Stop the clock ...
   T_FINISH = gethrtime();

   // Force flush Flog. HENCEFORTH, FURTHER Flog WRITES CAN JUST fprintf(Flog ...) ...
   LogMsg(NULL);
   fprintf(Flog, "NOTICE: %s Ends\n", PWALK_VERSION);

   // @@@ Aggregate per-worker-stats (WS[w_id]) to program's global-stats (GS) (lockless) ...
   // ... regardless of whether or not the statistic was actually accumulated by the workers ...
   for (w_id=0; w_id<MAX_WORKERS; w_id++) {
      if (WS[w_id] == NULL) break;			// non-NULL for workers that ran
      GS.NDiropens += WS[w_id]->NDiropens;		// BASIC counters
      GS.NWarnings += WS[w_id]->NWarnings;
      GS.NStatCalls += WS[w_id]->NStatCalls;
      GS.NDirs += WS[w_id]->NDirs;
      GS.NFiles += WS[w_id]->NFiles;
      GS.NOthers += WS[w_id]->NOthers;
      GS.NStatErrors += WS[w_id]->NStatErrors;
      GS.NBytesAllocated += WS[w_id]->NBytesAllocated;
      GS.NBytesNominal += WS[w_id]->NBytesNominal;
      GS.READONLY_Zero_Files += WS[w_id]->READONLY_Zero_Files;
      GS.READONLY_Opens += WS[w_id]->READONLY_Opens;
      GS.READONLY_Errors += WS[w_id]->READONLY_Errors;
      GS.READONLY_CRC_Bytes += WS[w_id]->READONLY_CRC_Bytes;
      GS.READONLY_DENIST_Bytes += WS[w_id]->READONLY_DENIST_Bytes;
      GS.NPythonCalls += WS[w_id]->NPythonCalls;
      GS.NPythonErrors += WS[w_id]->NPythonErrors;
      GS.NACLs += WS[w_id]->NACLs;
      for (i=0; i<7; i++) {				// +tally counters
         GS.TALLY_STATS[i].NFiles += WS[w_id]->TALLY_STATS[i].NFiles;
         GS.TALLY_STATS[i].NBytesNominal += WS[w_id]->TALLY_STATS[i].NBytesNominal;
         GS.TALLY_STATS[i].NBytesAllocated += WS[w_id]->TALLY_STATS[i].NBytesAllocated;
      }
   }

   // ------------------------------------------------------------------------

   // @@@ OUTPUT (tally): +tally writes its own .tally file ...
   if (Cmd_TALLY) pwalk_tally_output();

   // @@@ OUTPUT (log): -audit decoder ring to log file ...
#if PWALK_AUDIT // OneFS only
   if (Cmd_AUDIT) pwalk_audit_keys();
#endif // PWALK_AUDIT

   // @@@ OUTPUT (log): OS-level pwalk process stats ...
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

   fprintf(Flog, "NOTICE: Summary process stats ...\n");
   fprintf(Flog, "NOTICE: %16ld - max resident set size (KB)\n", p_usage.ru_maxrss/1024);
#ifdef SOLARIS
   fprintf(Flog, "NOTICE: %16ld - integral resident set size\n", p_usage.ru_idrss);
#else
   fprintf(Flog, "NOTICE: %16ld - integral shared text memory size\n", p_usage.ru_ixrss);
   fprintf(Flog, "NOTICE: %16ld - integral unshared data size\n", p_usage.ru_idrss);
   fprintf(Flog, "NOTICE: %16ld - integral unshared stack size\n", p_usage.ru_isrss);
#endif
   fprintf(Flog, "NOTICE: %16ld - page reclaims\n", p_usage.ru_minflt);
   fprintf(Flog, "NOTICE: %16ld - page faults\n", p_usage.ru_majflt);
   fprintf(Flog, "NOTICE: %16ld - swaps\n", p_usage.ru_nswap);
   fprintf(Flog, "NOTICE: %16ld - block input operations\n", p_usage.ru_inblock);
   fprintf(Flog, "NOTICE: %16ld - block output operations\n", p_usage.ru_oublock);
   fprintf(Flog, "NOTICE: %16ld - messages sent\n", p_usage.ru_msgsnd);
   fprintf(Flog, "NOTICE: %16ld - messages received\n", p_usage.ru_msgrcv);
   fprintf(Flog, "NOTICE: %16ld - signals received\n", p_usage.ru_nsignals);
   fprintf(Flog, "NOTICE: %16ld - voluntary context switches\n", p_usage.ru_nvcsw);
   fprintf(Flog, "NOTICE: %16ld - involuntary context switches\n", p_usage.ru_nivcsw);

   // @@@ OUTPUT (log): Summary pwalk stats ...
   fprintf(Flog, "NOTICE: Summary pwalk stats ...\n");
   fprintf(Flog, "NOTICE: %16llu - push%s\n", FIFO_PUSHES, (FIFO_PUSHES != 1) ? "es" : "");
   fprintf(Flog, "NOTICE: %16llu - warning%s\n", GS.NWarnings, (GS.NWarnings != 1) ? "s" : "");
   fprintf(Flog, "NOTICE: %16llu - worker wakeup%s\n",
           N_Worker_Wakeups, (N_Worker_Wakeups != 1) ? "s" : "");
   if (GS.NPythonCalls > 0) 
      fprintf(Flog, "NOTICE: %16llu - Python call%s from -audit\n",
         GS.NPythonCalls, (GS.NPythonCalls != 1) ? "s" : "");

   // @@@ OUTPUT (log): Summary File stats ...
   fprintf(Flog, "NOTICE: Summary file stats ...\n");
   // NStatCalls should equal (NDiropens + NFiles + NOthers + NStatErrors) ...
   fprintf(Flog, "NOTICE: %16llu - stat() call%s in readdir_r loops\n", GS.NStatCalls, (GS.NStatCalls != 1) ? "s" : "");
   fprintf(Flog, "NOTICE: %16llu -> stat () error%s\n", GS.NStatErrors, (GS.NStatErrors != 1) ? "s" : "");
   fprintf(Flog, "NOTICE: %16llu -> director%s\n", GS.NDiropens, (GS.NDiropens != 1) ? "ies" : "y");
   fprintf(Flog, "NOTICE: %16llu -> file%s\n", GS.NFiles, (GS.NFiles != 1) ? "s" : "");
   fprintf(Flog, "NOTICE: %16llu -> other%s\n", GS.NOthers, (GS.NOthers != 1) ? "s" : "");
   fprintf(Flog, "NOTICE: %16llu - byte%s allocated (%4.2f GB)\n",
      GS.NBytesAllocated, (GS.NBytesAllocated != 1) ? "s" : "", GS.NBytesAllocated / 1000000000.);
   fprintf(Flog, "NOTICE: %16llu - byte%s nominal (%4.2f GB)\n",
      GS.NBytesNominal, (GS.NBytesNominal != 1) ? "s" : "", GS.NBytesNominal / 1000000000.);
   if (GS.NBytesNominal > 0) {	// protect divide ...
      fprintf(Flog, "NOTICE: %15.5f%% - overall overhead ((allocated-nominal)*100.)/nominal)\n",
         ((GS.NBytesAllocated - GS.NBytesNominal)*100.)/GS.NBytesNominal);
   }

   // @@@ OUTPUT (log): +crc and +denist stats ...
   if (Cmd_DENIST || P_CRC32 || Cmd_RM_ACLS) {
      fprintf(Flog, "NOTICE: Summary (READONLY) file data stats ...\n");
      fprintf(Flog, "NOTICE: %16llu - zero-length file%s\n", GS.READONLY_Zero_Files, (GS.READONLY_Zero_Files != 1) ? "s" : "");
      fprintf(Flog, "NOTICE: %16llu - open() call%s\n", GS.READONLY_Opens, (GS.READONLY_Opens != 1) ? "s" : "");
      fprintf(Flog, "NOTICE: %16llu - open() or read() error%s\n", GS.READONLY_Errors, (GS.READONLY_Errors != 1) ? "s" : "");
      if (P_CRC32)
         fprintf(Flog, "NOTICE: %16llu - CRC byte%s read\n", GS.READONLY_CRC_Bytes, (GS.READONLY_CRC_Bytes != 1) ? "s" : "");
      if (Cmd_DENIST)
         fprintf(Flog, "NOTICE: %16llu - DENIST byte%s read\n", GS.READONLY_DENIST_Bytes, (GS.READONLY_DENIST_Bytes != 1) ? "s" : "");
   }

   // @@@ OUTPUT (log): ACL-related stats ...
   if (Cmd_XACLS || Cmd_WACLS || Cmd_RM_ACLS) {
      fprintf(Flog, "NOTICE: %16llu - ACL%s processed\n", GS.NACLs, (GS.NACLs != 1) ? "s" : "");
   }

   // @@@ OUTPUT (log): Command line recap ...
   fprintf(Flog, "NOTICE: cmd =");
   for (i=0; i<argc; i++) fprintf(Flog, " %s", argv[i]);
   fprintf(Flog, "\n");

   // @@@ OUTPUT (log): CPU usage ...
   (void) times(&cpu_usage);
   fprintf(Flog, "NOTICE: %5.3fs usr, %5.3fs sys cpu\n",
           ((cpu_usage.tms_utime + cpu_usage.tms_cutime) / (double) CLK_TCK),
           ((cpu_usage.tms_stime + cpu_usage.tms_cstime) / (double) CLK_TCK) );

   // @@@ OUTPUT (log): Elapsed time as HH:MM:SS.ms ...
   t_elapsed_sec = (T_FINISH - T_START) / 1000000000.; // convert nanoseconds to seconds
   t_h = trunc(t_elapsed_sec / 3600.);
   t_m = trunc(t_elapsed_sec - t_h*3600) / 60;
   t_s = fmod(t_elapsed_sec, 60.);
   fprintf(Flog, "NOTICE: %5.3f seconds (%d:%02d:%06.3f) elapsed, %3.0f files/sec\n",
      t_elapsed_sec, t_h, t_m, t_s,
      (t_elapsed_sec > 0.) ? ((GS.NFiles+GS.NDirs+GS.NOthers)/(t_elapsed_sec)) : 0.);

   // @@@ Final Sanity Checks and final warnings ...
   if (FIFO_POPS != FIFO_PUSHES) {	// (Old debug code)
      fprintf(Flog, "WARNING: FIFO_POPS(%llu) != FIFO_PUSHES(%llu)\n",
         FIFO_PUSHES, FIFO_POPS);
      exit_status = -1;
   }
   if (GS.NPythonErrors > 0) {
      fprintf(Flog, "WARNING: %llu Python call errors encountered!\n", GS.NPythonErrors);
      exit_status = -2;
   }
   fflush(Flog);

   // @@@ Close auxillary outputs ...
   close_all_outputs();

   // @@@ Cleanup all worker threads ...
   for (i=0; i<N_WORKERS; i++)
      pthread_cancel(WorkerData[i].thread);
   for (i=0; i<N_WORKERS; i++)
      pthread_join(WorkerData[i].thread, NULL);

   exit(exit_status);
}
