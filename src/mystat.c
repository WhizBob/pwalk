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

// NOTE: OSX stat() returns timespec values (tv_sec, tv_nsec), while utimes() uses an array
// of two timeval values (tv_sec, tv_usec).

int
main(int argc, char *argv[])
{
   struct stat sb;
   char atime_str[64], mtime_str[64], ctime_str[64], btime_str[64];
   int fd, rc;

   // Rather than lstat() here, we open() to bypass possible NFS stale cache ...
   fd = open(argv[1], O_RDONLY|O_NONBLOCK|O_NOFOLLOW);
   if (fd < 0) {
      printf("mystat: cannot open \"%s\" errno=%d \"%s\"\n", argv[1], errno, strerror(errno));
      exit(-1);
   }
   rc = fstat(fd, &sb);
   if (rc) {
      printf("mystat: cannot stat \"%s\" errno=%d \"%s\"\n", argv[1], errno, strerror(errno));
      exit(-1);
   }
   close(fd);

   // For reference, stat(1) shows ...
   // st_dev=16777220 st_ino=57980119 st_mode=0100644 st_nlink=1 st_uid=0 st_gid=20 st_rdev=0 st_size=0 st_atime=1449782702 st_mtime=1449782702 st_ctime=1449782702 st_birthtime=1449782702 st_blksize=4096 st_blocks=0 st_flags=0

   ctime_extended(&(sb.st_atimespec), atime_str);
   ctime_extended(&(sb.st_mtimespec), mtime_str);
   ctime_extended(&(sb.st_ctimespec), ctime_str);
   ctime_extended(&(sb.st_birthtimespec), btime_str);
   printf(" st_dev=%d st_ino=%s st_mode=%07o st_nlink=%d st_uid=%d st_gid=%d st_rdev=%d st_size=%lld st_blksize=%d st_blocks=%llu st_flags=%o\n     st_atime=%21ld.%09lu (%016lX) %s\n     st_mtime=%21ld.%09lu (%016lX) %s\n     st_ctime=%21ld.%09lu (%016lX) %s\n st_birthtime=%21ld.%09lu (%016lX) %s\n",
	sb.st_dev,
	onefs_inode_str(sb.st_ino),
	sb.st_mode,
	sb.st_nlink,
	sb.st_uid,
	sb.st_gid,
	sb.st_rdev,
	sb.st_size,
	sb.st_blksize,
	sb.st_blocks,
	sb.st_flags,
	sb.st_atimespec.tv_sec, sb.st_atimespec.tv_nsec, sb.st_atimespec.tv_sec, atime_str,
	sb.st_mtimespec.tv_sec, sb.st_mtimespec.tv_nsec, sb.st_mtimespec.tv_sec, mtime_str,
	sb.st_ctimespec.tv_sec, sb.st_ctimespec.tv_nsec, sb.st_ctimespec.tv_sec, ctime_str,
	sb.st_birthtimespec.tv_sec, sb.st_birthtimespec.tv_nsec, sb.st_birthtimespec.tv_sec, btime_str);
}