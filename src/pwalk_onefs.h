#if !defined(PWALK_ONEFS_H)
#define PWALK_ONEFS_H 1

#include <errno.h>

// OneFS-specific definitions ...
typedef struct {
   int w_committed;             // Three values from OneFS WORM state for LIN ...
   struct timeval w_ctime;		// (only time_t prior to OneFS 8.2?)
   time_t w_retention_date;
   time_t w_auto_offset;        // Five values from OneFS WORM domain ...
   time_t w_min_retention;
   time_t w_max_retention;
   time_t w_def_retention;
   time_t w_override_date;
// ==== exposed values from pctl2_get_expattr
// ==== calculated values ...
} worm_info_t;

#if !defined(_dirdesc)		// Needed in OneFS 8 ...
struct _dirdesc {
   int	dd_fd;			/* file descriptor associated with directory */
   long	dd_loc;			/* offset in current buffer */
   long	dd_size;		/* amount of data returned by getdirentries */
   char	*dd_buf;		/* data buffer */
   int	dd_len;			/* size of data buffer */
   long	dd_seek;		/* magic cookie returned by getdirentries */
   long	dd_rewind;		/* magic cookie for rewinding */
   int	dd_flags;		/* flags for readdir */
   struct pthread_mutex	*dd_lock;	/* lock */
   struct _telldir *dd_td;	/* telldir position recording */
};
#endif

// @@@ Forward declarations ...
void onefs_map_uid_to_sid(int uid, char *sid);
void onefs_map_gid_to_sid(int gid, char *sid);
void onefs_get_sids(int fd, char *owner_sid, char *group_sid);
int onefs_get_w_stat(const ino_t lin, worm_info_t *wi);
int onefs_rm_acls(int fd, char *pathname, struct stat *sb, char *errmsg);

// @@@ Non-OneFS proxies for OneFS-specific functions ...
#if !defined(__ONEFS__)			// Stubs for non-OneFS platforms ...
static int lvtimes(const char * path, struct timespec * times, int mask) { errno = ENOTSUP; return -1; }
static int vtimes(const char * path, struct timespec * times, int mask) { errno = ENOTSUP; return -1; }
#endif // !defined(__ONEFS__)

#endif // !defined(PWALK_ONEFS_H)
