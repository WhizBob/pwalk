#define PWALK_ONEFS_SOURCE 1

// DISCLAIMER:  The is FREE CODE for instructional purposes only.  There are no warranties,
// expressed or implied for this code, including any warrantees of correctness or suitability
// for any particular purpose.  Use at you own risk!

// <<< generic >>> ...
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>

// <<< pwalk-specific >>> ...
#include "pwalk.h"
#include "pwalk_onefs.h"

#if defined(__ONEFS__)

// <<< OneFS-specific >>> ...
#include <rest_client.h>			// enabler for PAPI REST functions
#include <sys/isi_persona.h>			// security descriptor access
#include <isi_acl/isi_sd.h>
#include <isi_acl/isi_acl_util.h>		// isi_acl_util.h aclu* helper functions

// klooge: Somebody forgot to externalize these? ...
//extern char *security_acl_to_text(struct ifs_security_acl *acl);
extern char *sd_to_text(struct ifs_security_descriptor *sd, ssize_t *size);
struct ifs_security_descriptor *get_sd(int fd, enum ifs_security_info secinfo);

// @@@ Debugging aids ...

// Non-MT ...
#define CHECK_ACL(acl) ({ \
int irc = aclu_validate_acl(acl, acl->acl_size); \
   if (irc) {\
      fprintf(stderr, "Failed to validate acl, error = %d", irc); \
      assert (irc == 0); \
   }; \
})

void
pwalk_debug_check(void)
{
   int rc;
   struct ifs_security_descriptor *p = (struct ifs_security_descriptor *) PBLK.ptr;

   fprintf(stderr, ">");
   if (p) {
      if (p->owner) fprintf(stderr, " owner=%08lx", (unsigned long) p->owner);
      if (p->group) fprintf(stderr, " group=%08lx", (unsigned long) p->group);
      if (p->sacl) fprintf(stderr, " sacl=%08lx[%d,%d]", (unsigned long) p->sacl, p->sacl->num_aces, p->sacl->acl_size);
      if (p->dacl) fprintf(stderr, " dacl=%08lx[%d,%d]", (unsigned long) p->dacl, p->dacl->num_aces, p->dacl->acl_size);
      CHECK_ACL(p->dacl);
   } else {
      fprintf(stderr, "> sdp is NULL");
   }
   fprintf(stderr, "\n");
}

void
pwalk_debug_sdp(struct ifs_security_descriptor *p, char *msg)
{
   int size;
   char *pcopy;

   if (PBLK.copy) free(PBLK.copy);
   size = sizeof(struct ifs_security_descriptor);
   if (msg) strcpy(PBLK.msg, msg);
   else strcpy(PBLK.msg, "<empty>");
   PBLK.ptr = p;
//    if (p && size > 0) {
//    assert ((PBLK.copy = malloc(size)));
//    memcpy(PBLK.copy, p, PBLK.size);
   pwalk_debug_check();
}

// @@@ OneFS-dependent functions ...

//#include <isi_util/isi_printf.h>
//#include <isi_util/multistring.h>
//#include <isi_gconfig/main_gcfg.h>

// onefs_map_uid_to_sid() - Get SID value of passed UID value.
// SID buffer is assumed to accomodate at least 63 characters plus NUL byte.
// Returned SID will be an empty string for any and all errors.

void
onefs_map_uid_to_sid(int uid, char *sid)	// klooge: PLACEHOLDER
{
   *sid = '\0';
}

// onefs_map_gid_to_sid() - Get SID value of passed GID value.
// SID buffer is assumed to accomodate at least 63 characters plus NUL byte.
// Returned SID will be an empty string for any and all errors.

void
onefs_map_gid_to_sid(int gid, char *sid)	// klooge: PLACEHOLDER
{
   *sid = '\0';
}

// onefs_get_sids() - Returns owner and group SID values for passed fd.
// These values are empty strings when the *on-disk* identities are not SIDs,
// or if the passed fd does not point to a file in /ifs.
// NOTE: Call unconditionally. Requisite conditions are embedded here;

void
onefs_get_sids(const int fd, char *owner_sid, char *group_sid)
{
   int error, rc;
   struct ifs_security_descriptor *sd = NULL;
   struct persona *p_own, *p_grp;
   char *p;
   struct fmt FMT_INIT_CLEAN(fmt);

   owner_sid[0] = group_sid[0] = '\0';

   if (PWget_MASK & PWget_SD) {
      sd = get_sd(fd, IFS_SEC_INFO_OWNER|IFS_SEC_INFO_GROUP);
      if (sd == NULL) return;

      // p_own = sd->owner;
      // p_grp = sd->group;
      // fmt_clean(&fmt);
      // fmt_print(&fmt, "%{}", persona_fmt((const struct persona *)p_own));
      // fprintf(stderr, "owner=%s\n", fmt_string(&fmt));
      // fmt_clean(&fmt);
      // fmt_print(&fmt, "%{}", sd_fmt(sd));
      // fprintf(stderr, "sd_fmt=%s\n", fmt_string(&fmt));

      error = persona_get_sid_string(sd->owner, owner_sid, 64);
      error = persona_get_sid_string(sd->group, group_sid, 64);
      if (sd) free(sd);
   }
}

// get_worm_state(ifs_lin_t lin,
// 	ifs_snapid_t snapid,		// 0 for HEAD
// 	struct worm_state *worm_out,
// 	bool *compliance,
// 	struct isi_error **error_out)

// * Get domain info for a LIN. In order to determine if a LIN is governed by
// * a particular domain type, pass in an ae_out param and check
// * ae_out->entry->d_flags. If the WORM state does not exist for a LIN,
// * *worm_out will be initialized to {} if worm_out is passed in.
// int
// bam_domain_getinfo(struct ifs_op *io,
// 	struct bam_agg_domain_entry *ae_out,
// 	struct domain_set *doms_out,
// 	struct domain_set *ancestors_out,
// 	struct worm_state *worm_out)

int
onefs_get_w_stat(const ino_t lin, worm_info_t *wi)	// klooge: PLACEHOLDER
{
   // int w_committed;		// Three values from WORM state for LIN ...
   // time_t w_ctime;
   // time_t w_retention_date;
   // time_t w_auto_offset;	// Five values from LIN's WORM domain ...
   // time_t w_min_retention;
   // time_t w_max_retention;
   // time_t w_def_retention;
   // time_t w_override_date;
   return (0);
}

// onefs_rm_acls() - removes non-inherited non-heritable ACEs from ACLs. If resulting ACL
// is empty, it will be removed and replaced with the current apparent mode bits.
//
// RETURNS:
//	-3 - "error removing DACL, rc=<n>"
//	-2 - "error writing DACL, rc=<n>"
//	-1 - "error reading DACL, rc=<n>"
//	0 - NOP - DACL unmodified
//	1 - FIX - DACL fixed (was empty on NULL)
//	2 - MOD - DACL modified
//	3 - REM - DACL removed (was degenerate)
//	Also, *errstr is set to error message string when return value is negative..
//
// ------------------------------------------------------------------------------------------
// We DO NOT want to do THIS, because a NULL DACL results in "WIDE OPEN" permissions!
//
// if (n_inherited_aces == 0) {
//   aclu_free_acl(sdp->dacl);
//   sdp->dacl = NULL;
//   aclu_rc = aclu_set_fd_sd(fd, IFS_SEC_INFO_DACL, sdp, SMAS_FLAGS_NONE);
//   if (aclu_rc) { strcpy(rc_msg, "error removing DACL"); rc = -3; goto out; }
//   chmod_rc = fchmod(fd, sb->st_mode);
//   if (chmod_rc) { strcpy(rc_msg, "error in chmod()"); rc = -4; goto out; }
//   goto out;
//}
//
// As a point of reference, replacing an ACL with mode bits on OneFS by using the command
// 'chmod -b 070 <path>' creates this truss output ...
//    open("/ifs/bob/rm_acls/d",O_RDONLY,037777600070) = 4 (0x4)
//    modfind(0x40571d,0x8038,0x7fffffffffff0038,0x8006d92a0,0x0,0x1) = 305 (0x131)
//    modstat(0x131,0x7fffffffd960,0x7fffffffffff0038,0x8006d92a0,0x0,0x1) = 0 (0x0)
//    lkmnosys(0x4,0x0,0x8038,0xffffffff,0xffffffff,0x800000000) = 0 (0x0)
//    close(4)					 = 0 (0x0)
//
// The lkmnosys() call is a OneFS syscall extension to its BSD base.
// ------------------------------------------------------------------------------------------
//
// struct ifs_security_descriptor {
// 	enum ifs_sec_desc_rev revision;
// 	enum ifs_sec_desc_control control;
// 	struct persona *owner;	/* user, group, everyone, or NULL */
// 	struct persona *group;	/* group, everyone, or NULL */
// 	struct ifs_security_acl *dacl;
// 	struct ifs_security_acl *sacl;
// };

int
onefs_rm_acls(int fd, char *pathname, struct stat *sb, char *rc_msg)
{
   int rc, aclu_rc, chmod_rc, ifs_rc, i;
   struct ifs_sec_desc_buf sdb = {};;
   struct ifs_security_descriptor *sdp = NULL;
   struct ifs_ace *ace_p;
   int n_aces, n_inherited_aces = 0, n_noninherited_aces = 0;
   // Debug ...
   char *sd_text;
   ssize_t sd_text_size;

   // If no NTFS ACL present (ie: shows as 'SYNTHETIC ACL'), skip file entirely ...
   // We do not even create a single line of DEBUG output for these files.
   if (!(sb->st_flags & SF_HASNTFSACL)) {
      strcpy(rc_msg, "NOP"); rc = 0; return(rc);
   }

   if (PWdebug) fprintf(stderr, "@@@ onefs_rm_acls(%d, \"%s\") ...\n", fd, pathname);

   // @@@ Get current Security Descriptor (SD) which contains a SACL and a DACL ...
   // This should ALWAYS succeed under OneFS for files in /ifs! The fetched DACL could
   // actually be a 'SYNTHETIC ACL', but we've aleady screened for that (SF_HASNTFSACL).
   // On success, we'll have dynamically-allocated SD that must be freed before we return!
   // NOTE: NTFS SDs are not applicable outside of /ifs!

   if ((rc = aclu_get_fd_sd(fd, IFS_SEC_INFO_DACL, &sdb))) {
      sprintf(rc_msg, "error reading DACL, rc=%d", errno); rc = -1; return(rc);
   }
   sdp = sdb.sd;

   // NOTE: Our ONLY return path must now be through the 'out' label where this SD (or more
   // precisely, the ifs_sec_desc_buf) will be freed ...

   if (PWdebug > 1) {	// We now have an SD ...
      if ((sd_text = sd_to_text(sdp, &sd_text_size))) {
         fputs(sd_text, stderr);
         free(sd_text);
         fputs("\n", stderr);
      } else {
         fputs("ERROR: sd_to_text()\n", stderr);
      }
   }

   // @@@ Evaluate DACL ...
   // If permissions are WIDE OPEN (NULL DACL), we will revert file to using mode bits.
   if (sdp->dacl == NULL) {
      n_aces = 0;
      strcpy(rc_msg, "FIX");
   } else {
      n_aces = sdp->dacl->num_aces;
   }
   // Count inherited vs. non-inherited ACEs ...
   for (i=0; i<n_aces; i++) {
      assert(aclu_get_ace_at(sdp->dacl, i, &ace_p) == 0);
      if (PWdebug > 1) fprintf(stderr, "# ace %d flags 0x%x\n", i, ace_p->flags);
      if (ace_p->flags & IFS_ACE_FLAG_INHERITED_ACE) n_inherited_aces += 1;
      else n_noninherited_aces += 1;
   }
   if (PWdebug) fprintf(stderr, "@@ old n_aces=%d acl_size=%d sdp->control=0x%08x ia=%d nonia=%d\n",
      n_aces, sdp->dacl ? sdp->dacl->acl_size : 0, sdp->control, n_inherited_aces, n_noninherited_aces);

   // @@@ If there or zero non-inherited ACEs, return NOW as NOP ...
   // ... unless the DACL is NULL (n_aces == 0), in which case we'll FIX it.
   if (n_aces > 0 && n_noninherited_aces == 0) {
      strcpy(rc_msg, "NOP"); rc = 0; goto out;	// 'NOP' - DACL unmodified ...
   }

   // @@@ If no ACEs would remain, replace the ACL with mode bits ...
   if (n_aces == n_noninherited_aces) {
      ifs_rc = PWdryrun ? 0 : ifs_set_mode_and_sd(fd, SMAS_FLAGS_NONE, sb->st_mode & 07777, -1, -1, 0, NULL);
      if (ifs_rc) {
         strcpy(rc_msg, "error applying mode bits, rc=%d"); rc = -3;
      } else {
         if (rc_msg[0] == 'F') rc = 1;		// 'FIX' - DACL FIXed
         else strcpy(rc_msg, "REM"); rc = 3;	// 'REM' - DACL REMoved
      }
      goto out;
   }

   // @@@ Remove all the non-inherited ACEs from the DACL ...
   for (i=0; i<n_aces; i++) {
      assert(aclu_get_ace_at(sdp->dacl, i, &ace_p) == 0);
      if (ace_p->flags & IFS_ACE_FLAG_INHERITED_ACE) {
         assert (aclu_remove_ace(sdp->dacl, ace_p) == 0);
         n_aces -= 1;
         i -= 1;
      }
   }
   assert(n_aces >= 0);

   // @@@ Apply our MODified DACL ...
   aclu_rc = PWdryrun ? 0 : aclu_set_fd_sd(fd, IFS_SEC_INFO_DACL, sdp, SMAS_FLAGS_NONE);
   if (PWdebug) fprintf(stderr, "@@ aclu_set_fd_sd() = %d\n", aclu_rc);
   if (aclu_rc) {
      sprintf(rc_msg, "error modifying DACL, rc=%d", aclu_rc); rc = -2;
   } else {
      strcpy(rc_msg, "MOD"); rc = 2;		// 'MOD' - DACL modified ...
   }

out:
   if (PWdebug) {
      fprintf(stderr, "@ sdp@0x%08lx={%x,%x,0x%08lx,0x%08lx,0x%08lx,0x%08lx} \"%s\"\n",
         (unsigned long) sdp,
         sdp == NULL ? 0 : sdp->revision,
         sdp == NULL ? 0 : sdp->control,
         sdp == NULL ? 0 : (unsigned long)  sdp->owner,
         sdp == NULL ? 0 : (unsigned long)  sdp->group,
         sdp == NULL ? 0 : (unsigned long)  sdp->dacl,
         sdp == NULL ? 0 : (unsigned long)  sdp->sacl,
         rc_msg
      );
   }

   aclu_free_sd_buf(&sdb, 0);
   if (PWdebug) fprintf(stderr, "@@ \"%s\" rc=%d\n", rc_msg, rc);
   return(rc);
}

#else // !defined(__ONEFS__)

// Just stubs here ...

void
onefs_get_sids(int fd, char *owner_sid, char *group_sid)
{
   owner_sid[0] = group_sid[0] = '\0';
}

#endif // defined(__ONEFS__)
