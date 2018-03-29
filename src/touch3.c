// touch3.c - Utility to set a file's atime, mtime, and birthtime, subject to platform constraints.
// It invokes some variant of the classic Unix utimes(2) call, which includes;
//
//	utimes(2) - The old standard Unix utimes(2) syscall will ALWAYS set both atime and mtime,
//		but is constrained to use microsecond resolution. When the intention is to leave
//		either atime or mtime unchanged, the caller must fetch the existing value from the
//		file and arrange for it to be re-asserted. This re-assertion of a timestamp will
//		typically cause its value to suffer loss of precision.
//	lvtimes(3) - OneFS-only; API to set atime, mtime, and birthtime values independently, with
//		full nanosecond-level precision
//	utimensat(2), futimens(3) - Linux-only; APIs to set atime and mtime independently, with
//		full nanosecond-level precision. Includes reserved time constants UTIME_NOW and
//		UTIME_OMIT to specify current time (at server) or to not disturb existing value.
//		SADLY, these reserved values are defined as 32-bit values which would otherwise
//		represent perfectly valid 64-bit signed Unix epoch values;
//
//		UTIME_NOW  = 0x3fffffff = 1073741823 = Saturday, January 10, 2004 1:37:03 PM UTC
//		UTIME_OMIT = 0x3ffffffe = 1073741822 = Saturday, January 10, 2004 1:37:02 PM UTC
//
//		
// NOTE: No platforms provide an API for setting st_ctime; it's always time-of-last-change.
// NOTE: Use 'export TZ=UTC0UTC' to have UTC displayed, otherwise times will be localized.
// NOTE: Linux does not support st_birthtime via stat(2)!
// NOTE: OSX supports st_birthtime, but its NFS client code just copies st_ctime into it.
// NOTE: SMB protocol uses NTFS timestamp values, which use an epoch of January 1, 1601 UTC.
//	See also: https://www.meridiandiscovery.com/articles/date-forgery-analysis-timestamp-resolution/
//	See also: https://www.sans.org/reading-room/whitepapers/forensics/filesystem-timestamps-tick-36842
// NOTE: OSX SMB supports st_birthtime, but the value can be mangled translating between Unix epoch
//	times and NTFS timestamp values.

#include <stdio.h>
#include <time.h>
#include <utime.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>
#include <limits.h>
#include <math.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <errno.h>

static struct stat SB;		// Buffer for lstat() results
static int HaveStat = 0;	// One-shot trigger for lstat() call
static char *PathName;		// File to touch

// OneFS does not have single clean manifest constant for the platform, so we have this ...
#if defined(OneFS_ABI_version_v1) || defined(OneFS_ABI_version_v2)
#define __ONEFS__ 1
#endif

#if defined(__ONEFS__)
#include <sys/isi_enc.h>	// for lvtimes() (OneFS private)
#else				// fake/stub values
#define VT_ATIME 1
#define VT_MTIME 2
#define VT_BTIME 4
int
lvtimes(const char * path, struct timespec * times, int mask)
{
   errno = ENOTSUP;
   return -1;
}
#endif

// ctime_extended() - replaces ctime() and ctime_r() to always return a valid translation
// of the passed time.  Passed buffer should be at least 32 bytes, or if NULL is passed,
// the result will be a pointer to local static buffer (non-re-entrant).

// Crude approximation for large values ignores leap seconds or when 1st leap year occurs
#define SECS_PER_YEAR (365.242199L*24*60*60)

char *
ctime_extended(struct timespec *ts, char *ubuf)
{
   static char lbuf[32];	// Non-Reentrant result buf for when passed ubuf is NULL
   char *rbuf;			// Result buffer pointer (either passed ubuf or local lbuf)
   long year;			// For large dates, past and future

   rbuf = (ubuf == NULL) ? lbuf : ubuf;

   // Try getting a good value from ctime_r() (localized) ...
   // On some systems, the year must be in the range -999 to 9999. On others, larger year
   // values may be returned.
   if (ctime_r((time_t *) &ts->tv_sec, rbuf) != NULL) {
       *(index(rbuf, '\n')) = '\0';
   } else {
       strcpy(rbuf, "?");
       // Large or negative values not formatted by ctime() SHOULD be VERY LARGE ...
       year = 1970 + ts->tv_sec/SECS_PER_YEAR;
       sprintf(rbuf, "%ld %s", (year >= 0) ? year : -year, (year < 0) ? "BCE" : "CE");
       if (ts->tv_sec == 0x8000000000000000) strcat(rbuf, " MAX_NEG");
       else if (ts->tv_sec == 0x7FFFFFFFFFFFFFFF) strcat(rbuf, " MAX_POS");
   }

   return rbuf;
}

void
usage(void)
{
   printf("\n");
   printf("Usage: touch3 <comment> <atime> <mtime> <birthtime> <pathname>\n");
   printf("Where: EXACTLY 5 arguments must be provided;\n");
   printf("	<comment> - any string value\n");
   printf("	<atime>, <mtime>, <birthtime> - each one of;\n");
   printf("		'-' (to skip)\n");
   printf("		'a' for the existing atime (access time)\n");
   printf("		'm' for the existing mtime (modify time)\n");
   printf("		'c' for the existing ctime (change time)\n");
   printf("		'b' for the existing birthtime (creation time)\n");
   printf("		A Unix epoch time value (seconds since January 1, 1970 00:00 UTC)\n");
   printf("	<pathname> - a single file to be touched\n");
   printf("\n");
   printf("NOTE: Unix epoch times can be specified either as a signed decimal or hexadecimal\n");
   printf("value (0x...) of up to 64 bits significance, with an optional decimal fractional\n");
   printf("seconds value up to 9 decimal digits (nanoseconds).  This allows for applying all\n");
   printf("possible legal timestamp values.\n");
   printf("\n");
   exit(-1);
}

// return 0 for 'no change', return 1 for 'change', and die in usage() on error

int
stat_time(char selector, struct timespec *ts)
{
   struct timespec *tsp;

   // One-shot lstat() call ...
   if (!HaveStat) {
      if (lstat(PathName, &SB)) {
         printf("ERROR: Cannot lstat(\"%s\")!\n", PathName);
         exit(-1);
      }
      HaveStat = 1;
   }
   // Point to selected value ...
   switch (selector) {
      case 'a': tsp = &SB.st_atimespec; break;
      case 'm': tsp = &SB.st_mtimespec; break;
      case 'c': tsp = &SB.st_ctimespec; break;
      case 'b': tsp = &SB.st_birthtimespec; break;
      default: usage();
   }
   // Copy selected value ...
   ts->tv_sec = tsp->tv_sec;
   ts->tv_nsec = tsp->tv_nsec;
   return 1;
}

int
parse_timespec(char *str, struct timespec *ts)
{
   long sec, nsec;
   char *p;
   int rc, mult;

   // 'No change' option ...
   if (strcmp(str, "-") == 0) return 0;

   // Pick an existing value from file ...
   if (strcmp(str, "a") == 0) return stat_time('a', ts);
   if (strcmp(str, "m") == 0) return stat_time('m', ts);
   if (strcmp(str, "c") == 0) return stat_time('c', ts);
   if (strcmp(str, "b") == 0) return stat_time('b', ts);

   // Get sec value or die (hex or signed decimal) ...
   // klooge: could be more robust ...
   if (strncmp(str, "0x", 2) == 0)
      rc = sscanf(str, "%lx", &sec);
   else
      rc = sscanf(str, "%ld", &sec);
   if (rc != 1) usage();
   ts->tv_sec = sec;

   // Parse (optional) mantissa into nsec ...
   if ((p=index(str, '.')) == NULL) {
      ts->tv_nsec = 0;
   } else  {
      mult = 100000000;
      nsec = 0;
      for (p += 1; isdigit(*p) & (mult > 0); p++) {
         nsec += ((*p - '0') * mult);
         mult /= 10;
      }
      if (*p != '\0') usage();
      ts->tv_nsec = nsec;
   }

   // If we got here, we have a value ...
   return 1;
}

int
main(int argc, char *argv[])
{
   int set_atime, set_mtime, set_btime;	// booleans
   char ctimebuf[128];			// formatted times (non re-entrant)
   struct timespec ts_ttime[3];		// (sec,nsec) values for vtimes()
   struct timeval tv_ttime[2];		// (sec,usec) values for utimes()
   int rc, mask;
  
   // Require 6 args (5 in lay terms, excluding argv[0]) ...
   if (argc != 6) usage();

   // Booleans ...
   set_atime = set_mtime = set_btime = 0;

   // argv[5] = <pathname> (capture first in case we need to lstat())
   PathName = argv[5];
   // argv[1] = <comment> (ignored)
   // argv[2] = <atime>
   set_atime = parse_timespec(argv[2], &ts_ttime[0]);
   // argv[3] = <mtime>
   set_mtime = parse_timespec(argv[3], &ts_ttime[1]);
   // argv[4] = <birthtime>
   set_btime = parse_timespec(argv[4], &ts_ttime[2]);

   // Populate tv_ttime[] in case we want to use utimes() ...
   tv_ttime[0].tv_sec = ts_ttime[0].tv_sec;
   tv_ttime[0].tv_usec = ts_ttime[0].tv_nsec / 1000;
   tv_ttime[1].tv_sec = ts_ttime[1].tv_sec;
   tv_ttime[1].tv_usec = ts_ttime[1].tv_nsec / 1000;

   // Build lvtimes() mask value ...
   mask = 0;
   if (set_atime) mask |= VT_ATIME;
   if (set_mtime) mask |= VT_MTIME;
   if (set_btime) mask |= VT_BTIME;

   // Show what we are about to do ...
   if (set_atime)
      printf("     st_atime=%21ld.%09lu (%016lX) %s\n", ts_ttime[0].tv_sec, ts_ttime[0].tv_nsec,
         ts_ttime[0].tv_sec, ctime_extended(&(ts_ttime[0]), NULL));
   if (set_mtime)
      printf("     st_mtime=%21ld.%09lu (%016lX) %s\n", ts_ttime[1].tv_sec, ts_ttime[1].tv_nsec,
         ts_ttime[1].tv_sec, ctime_extended(&(ts_ttime[1]), NULL));
   if (set_btime)
      printf(" st_birthtime=%21ld.%09lu (%016lX) %s\n", ts_ttime[2].tv_sec, ts_ttime[2].tv_nsec,
         ts_ttime[2].tv_sec, ctime_extended(&(ts_ttime[2]), NULL));

   // Set all specified values ...
#if defined(__ONEFS__)		// Use lvtimes(3) ...
   if (ts_ttime[0].tv_sec == -1 || ts_ttime[1].tv_sec == -1 || ts_ttime[2].tv_sec == -1)
      printf("WARNING: OneFS may not set '-1' timestamp values!\n");
   // int lvtimes(const char *path, struct timespec times *, int flags);
   rc = lvtimes(PathName, ts_ttime, mask);		// OneFS proprietary
   if (rc) printf("touch3: lvtimes() failed; %s\n", strerror(errno));
#else				// Use utimes(2) and complain if birthtime specified ...
   if (set_btime) printf("WARNING: birthtime not directly settable!\n");
   rc = utimes(PathName, tv_ttime);
   if (rc) printf("touch3: utimes() failed; %s\n", strerror(errno));
#endif
}
