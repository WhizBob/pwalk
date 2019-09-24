#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>

char *
onefs_inode_str(unsigned long ival)
{
   static char str[24];

   sprintf(str, "%lx:%04lx:%04lx", ((ival & 0xffffffff00000000) >> 32), ((ival & 0xffff0000) >> 16), ival & 0xffff);
   return str;
}

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
printf_st_flags(unsigned flags)
{
   int nflags = 0;
#define DOCOMMA (++nflags == 1 ? "" : ",")

   if (flags) {
      printf(" (");
#if defined(__LINUX__)
#elif defined(__APPLE__)
      if (flags & SF_ARCHIVED) printf("%sarchived", DOCOMMA);
      if (flags & UF_OPAQUE) printf("%sopaque", DOCOMMA);
      if (flags & UF_NODUMP) printf("%snodump", DOCOMMA);
      if (flags & SF_APPEND) printf("%ssappend", DOCOMMA);
      if (flags & UF_APPEND) printf("%suappend", DOCOMMA);
      if (flags & SF_IMMUTABLE) printf("%ssimmutable", DOCOMMA);
      if (flags & UF_IMMUTABLE) printf("%suimmutable", DOCOMMA);
      if (flags & UF_HIDDEN) printf("%shidden", DOCOMMA);
#elif defined(__ONEFS__)
      // Mask values here snapshotted from 8.1.2 /usr/include/sys/stat.h ....
      // #define SF_SETTABLE     0x0fff0000      // mask of root-changeable flags ...
      if (flags & SF_BACKUP_DOM_SPARSE) printf("%sbackup_dom_sparse", DOCOMMA);		// 0x08000000
      if (flags & SF_PARENTS_UPGRADED) printf("%sparents_upgraded", DOCOMMA);		// 0x04000000
      if (flags & SF_HASNTFSOG) printf("%shasntfsog", DOCOMMA);				// 0x02000000
      if (flags & SF_HASNTFSACL) printf("%shasntfsacl", DOCOMMA);			// 0x01000000
      if (flags & SF_CACHED_STUB) printf("%scached_stub", DOCOMMA);			// 0x00800000
      if (flags & SF_NOCOW) printf("%snocow", DOCOMMA);					// 0x00400000
      if (flags & SF_SNAPSHOT) printf("%ssnapshot", DOCOMMA);				// 0x00200000
      if (flags & SF_NOUNLINK) printf("%ssunlink", DOCOMMA);				// 0x00100000
      if (flags & SF_FILE_STUBBED) printf("%sstubbed", DOCOMMA);			// 0x00080000
      if (flags & SF_APPEND) printf("%ssappend", DOCOMMA);				// 0x00040000
      if (flags & SF_IMMUTABLE) printf("%ssimmutable", DOCOMMA);			// 0x00020000
      if (flags & SF_ARCHIVED) printf("%ssarchived", DOCOMMA);				// 0x00010000
      // #define UF_SETTABLE	0xf000ffff	// mask of user-settable flags ...
      if (flags & UF_DOS_SYSTEM) printf("%sdos_system", DOCOMMA);			// 0x80000000
      if (flags & UF_DOS_RO) printf("%sdos_readonly", DOCOMMA);				// 0x40000000
      if (flags & UF_DOS_HIDDEN) printf("%sdos_hidden", DOCOMMA);			// 0x20000000
      if (flags & UF_DOS_ARCHIVE) printf("%sdos_archive", DOCOMMA);			// 0x10000000
      if (flags & UF_DOS_OFFLINE) printf("%sdos_archive", DOCOMMA);			// 0x00008000
      if (flags & UF_DOS_NOINDEX) printf("%sdos_noindex", DOCOMMA);			// 0x00000100
      if (flags & UF_ISI_UNUSED1) printf("%sisi_unused1", DOCOMMA);			// 0x00004000
      if (flags & UF_REPARSE) printf("%sreparse", DOCOMMA);				// 0x00002000
      if (flags & UF_SPARSE) printf("%ssparse", DOCOMMA);				// 0x00001000
      if (flags & UF_WC_ENDURANT) printf("%swc_endurant", DOCOMMA);			// 0x00000800
      if (flags & UF_WC_INHERIT) printf("%swc_inherit", DOCOMMA);			// 0x00000080
      if (flags & UF_HASADS) printf("%shasads", DOCOMMA);				// 0x00000400
      if (flags & UF_ADS) printf("%sis_ads", DOCOMMA);					// 0x00000200
      if (flags & UF_WRITECACHE) printf("%swritecache", DOCOMMA);			// 0x00000040
      if (flags & UF_INHERIT) printf("%sinherit", DOCOMMA);				// 0x00000020
      if (flags & UF_NOUNLINK) printf("%suunlink", DOCOMMA);				// 0x00000010
      if (flags & UF_OPAQUE) printf("%sopaque", DOCOMMA);				// 0x00000008
      if (flags & UF_APPEND) printf("%suappend", DOCOMMA);				// 0x00000004
      if (flags & UF_IMMUTABLE) printf("%suimmutable", DOCOMMA);			// 0x00000002
      if (flags & UF_NODUMP) printf("%snodump", DOCOMMA);				// 0x00000001
#endif
      printf(")");
   }
   printf("\n");
}

// NOTE: OSX stat() returns nanosecond-resolution timespec values (tv_sec, tv_nsec), while
// utimes() on all *nix systems returns an array of two microsecond-resolution timeval values
// (tv_sec, tv_usec). Modern Linux also offers utimensat() to SET ns-granular timestamps,
// but evidently does not yet have a stat() alternative to observe them ... LOL.

int
main(int argc, char *argv[])
{
   struct stat sb;
   char *filename, atime_str[64], mtime_str[64], ctime_str[64], btime_str[64];
   char st_gen_str[32], st_flags_str[32];
   int fd, rc, i;

   for (i=1; i<argc; i++) {
      filename = argv[i];

      // Rather than lstat() here, we open() to bypass possible NFS stale cache ...
      fd = open(filename, O_RDONLY|O_NONBLOCK|O_NOFOLLOW);
      if (fd < 0) {
         printf("mystat: cannot open \"%s\" errno=%d \"%s\"\n", filename, errno, strerror(errno));
         continue;
      }
      if ((rc = fstat(fd, &sb))) {
         printf("mystat: cannot stat \"%s\" errno=%d \"%s\"\n", filename, errno, strerror(errno));
         continue;
      }
      close(fd);
   
      // Format stat(2) results ..
#if defined(__LINUX__)
      ctime_extended(&(sb.st_atim), atime_str);
      ctime_extended(&(sb.st_mtim), mtime_str);
      ctime_extended(&(sb.st_ctim), ctime_str);
      strcpy(btime_str, "n/a");
      strcpy(st_gen_str, "n/a");
      strcpy(st_flags_str, "n/a");
#else
      ctime_extended(&(sb.st_atimespec), atime_str);
      ctime_extended(&(sb.st_mtimespec), mtime_str);
      ctime_extended(&(sb.st_ctimespec), ctime_str);
      ctime_extended(&(sb.st_birthtimespec), btime_str);
      sprintf(st_gen_str, "%d", sb.st_gen);
      sprintf(st_flags_str, "0x%X", sb.st_flags);
#endif

      // Output ...
      printf("%s:\n", filename);
      printf("     st_mode=%07o st_nlink=%d st_uid=%d st_gid=%d\n",
                sb.st_mode, sb.st_nlink, sb.st_uid, sb.st_gid);
      printf("     st_size=%lld st_blocks=%llu st_blksize=%d\n",
                 sb.st_size, sb.st_blocks, sb.st_blksize);
      printf("     st_dev=%d st_rdev=%d st_ino=%s st_gen=%s\n",
		sb.st_dev, sb.st_rdev, onefs_inode_str(sb.st_ino), st_gen_str);
      printf("     st_flags=%s", st_flags_str);
#if defined(__LINUX__)
      printf("\n");
#else
      printf_st_flags(sb.st_flags);
#endif
      printf("     st_atime=%21ld.%09lu (%016lX) %s\n     st_mtime=%21ld.%09lu (%016lX) %s\n     st_ctime=%21ld.%09lu (%016lX) %s\n st_birthtime=%21ld.%09lu (%016lX) %s\n",
#if defined(__LINUX__)
   	sb.st_atim.tv_sec, sb.st_atim.tv_nsec, sb.st_atim.tv_sec, atime_str,
   	sb.st_mtim.tv_sec, sb.st_mtim.tv_nsec, sb.st_mtim.tv_sec, mtime_str,
   	sb.st_ctim.tv_sec, sb.st_ctim.tv_nsec, sb.st_ctim.tv_sec, ctime_str,
   	0L, 0, 0, btime_str);
#else
   	sb.st_atimespec.tv_sec, sb.st_atimespec.tv_nsec, sb.st_atimespec.tv_sec, atime_str,
   	sb.st_mtimespec.tv_sec, sb.st_mtimespec.tv_nsec, sb.st_mtimespec.tv_sec, mtime_str,
   	sb.st_ctimespec.tv_sec, sb.st_ctimespec.tv_nsec, sb.st_ctimespec.tv_sec, ctime_str,
   	sb.st_birthtimespec.tv_sec, sb.st_birthtimespec.tv_nsec, sb.st_birthtimespec.tv_sec, btime_str);
#endif
   }
}
