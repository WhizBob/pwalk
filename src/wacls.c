// DESCRIPTION: OneFS-specific 'wacls' (Write ACLs) program receives a stream of binary
// [acl4, path] tuples from 'xacls' or 'pwalk ... +xacls=nfs4' on stdin and applies them.
// NFS4 ACLs are first first to IFS ACLs in an IFS Security Descriptor (SD), optionally
// merged with existing ACEs (with -merge), then applied.

// DISCLAIMER:  The is FREE CODE for instructional purposes only.  There are no warranties,
// expressed or implied for this code, including any warrantees of correctness or suitability
// for any particular purpose.  Use at you own risk!

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

// Lots gets hauled in to use isi_acl_util (aclu_*) functions ...
#include <sys/isi_persona.h>
#include <isi_acl/isi_sd.h>
#include <isi_acl/isi_acl_util.h>	// isi_acl_util.h aclu* helper functions
// klooge: Somebody forgot to externalize these ...
extern char *security_acl_to_text(struct ifs_security_acl *acl);
extern char *sd_to_text(struct ifs_security_descriptor *sd, ssize_t *size);
struct ifs_security_descriptor *get_sd(int fd, enum ifs_security_info secinfo);
//#include <isi_util/isi_printf.h>
//#include <isi_util/multistring.h>
//#include <isi_gconfig/main_gcfg.h>

#include <rpcsvc/nfs4_prot.h>		// OneFS 7.2 nfs41_prot.h gives unresolved auth_sys.h issue
#ifndef ACE4_INHERITED_ACE
#define	ACE4_INHERITED_ACE 0x00000080
#endif
#include "pwalk_acls.h"

// INPUT PATHNAMES: To assure that this program operates *only* on /ifs files;
// (This strategy not implemented.)
//	1. We chroot(2) to '/ifs' when we initialize (which requires root privilege), [ klooge ]
//	   then chdir(2) to '/', so that is the context of path interpretation.
//	2. If a '-cd <dir>' argument is supplied, it will be evaluated relative to
//	   '/ifs' being '/', so such arguments must *not* begin with '/ifs' unless
//	   they intend to reference a OneFS CWD of '/ifs/ifs/...'
// (This strategy is used.)
//	wacls will exit with an ERROR if the CWD is not "/ifs" or does not begin with "/ifs/".
//	Although this is an imperfect test, the APIs used to get and set IFS Security Descriptors
//	ONLY work in /ifs anyway, so there's no danger of messing up non-/ifs ACLs.

// OUTPUT: No output is be produced unless the directory '/ifs/wacls' exists and is writable,
// in which case all output will be to log files written in that directory;
//
//	1. Log files will be named '/wacls/wacls_<pid>.log', and only created if needed.
//         (In other words, realpath is /ifs/wacls/wacls_<pid>.log ...)
//	2. Only errors are normally logged [ === change to log start/stop & counters === ]
//	3. With "-v", pathnames are logged

// To build on OneFS (EMC Isilon unsupported; requires engineering tools install):
//
//	# Compile and link ..
//      cc wacls7.c -o wacls ... (See Makefile for numerous dependencies)
//	chown root wacls
//	chmod 700 wacls
//	# Copy wacls binary to /usr/local/bin on all cluster nodes, perhaps as follows ...
//	mkdir -p /ifs/wacls
//	cp -p wacls /ifs/wacls
//	isi_for_array -X cp -p /ifs/wacls/wacls /usr/local/bin
//	# Control access to wacls via 'sudo' using 'sudoedit', or make it setuid-root
//
// To debug on OneFS with gdb ...
//      NOTE: use -g 
//      LINUX NOTE: debug with 'gdb xacl core.<pid>' ... 'bt'

static int DEBUG = 0;			// Override with "-d"
static int VERBOSE = 0;			// Override with "-v"
static int DO_MERGE = 0;		// Override with "-merge"
static char *CD_ARG = NULL;		// Override with "-cd <value>"
static char WACL_MSG[8192];		// Ample buffer for log messages
static FILE *WACL_LOG = NULL;		// Destination of all output
static unsigned N_Apply_Successes = 0;
static unsigned N_Apply_Failures = 0;
static unsigned N_Errors = 0;

// wacl_log() - Only source of output; dynamically creates output file, or else does nothing.
// NOTE: The log file pathname must be relative to '/ifs' being the virtual filesystem root!

void
wacl_log(char *msg)
{
    char logfile[128];

    if (WACL_LOG == NULL) {
        sprintf(logfile, "/ifs/wacls/wacls_%d.log", getpid());
        WACL_LOG = fopen(logfile, "we");
        if (WACL_LOG == NULL) {		// Intolerable!
            if (isatty(fileno(stderr))) fprintf(stderr, "FATAL: Cannot open %s!\n", logfile);
            exit (-1);
        } else if (VERBOSE || DEBUG) {
            if (isatty(fileno(stdout))) printf("LOG: %s\n",  logfile);
            fprintf(WACL_LOG, "LOG: %s\n", logfile);
        }
    }

    if (msg != NULL) {
        fputs(msg, WACL_LOG);
        if (msg[0] == '\n') fflush(WACL_LOG);
    } else {	// If no string passed, output globalized string ...
        fputs(WACL_MSG, WACL_LOG);
        fflush(WACL_LOG);
    }
}

// WACL_ERR macro for all errors prevents always does a 'goto out' ...
#define WACL_ERR(x) { sprintf(WACL_MSG,"ERROR: %s [%s] \"%s\"\n",x,strerror(errno),path); wacl_log(NULL); retval = -1; goto out; }

// apply_acl4() - Very OneFS-specific code for applying passed-in NFS4 ACL to a OneFS file.
//
// Step #0: PRELIMINARIES - Confirm existance of target file and gather information about it. If
//	-merge was specified, also gather the file's existing ACL.
// Step #1: TRANSLATE NFS4 ACL TO IFS NATIVE ACL - Translate the passed-in NFS4 ACL to OneFS-specific
//	IFS ACL format (which is an opaque binary representation of type 'struct ifs_security_acl'),
// Step #2: MERGE (OPTIONAL) - If -merge was specified and target file has a pre-existing ACL,
//	merge the existing ACL into the IFS ACL just created from the passed-in NFS4 ACL.
// Step #3: APPLY NEW SD - Apply the OneFS Security Descriptor (SD) to the passed path.
//
// On any error, bail using WACL_ERR("<text>") macro. This macro consistently passed control
// to the "out:" label where all dynamic data allocations are freed. Freeing the dynamic values
// is essential to prevent memory leaks on highly-iterated calls to this function.
//
// NOTE: The functions calls used here can *only* operate on files in /ifs ... so there's no risk
// of perverting permissions on any files in OneFS boot filesystems.

int
apply_acl4(const acl4_t *acl4, const char *path)
{
    int i, id, hasacl, isdir, fstat_rc, get_sd_rc,  retval;
    ssize_t size;
    uint16_t size_16;
    struct stat statbuf;
    char emsg[2048];
    char *p;
    ace4_t *ace4_p;
    struct ifs_ace *ace_p;
    unsigned char ace_type;
    unsigned char ace_flags;
    unsigned char ifs_flags;
    int ace_mask;
    char whotype;					// ACE4 who[0] -> 'O','G','E',or '[0-9]' (in our case)
    // TEMP values to fill Security Descriptor ...
    int sd_flags;
    enum ifs_smas_flags sd_sflags;
    struct ifs_security_acl *new_acl;
    struct ifs_security_descriptor new_sd = {};		// New IFS SD (do not free base)
    // Clean these up on exit! ...
    struct ifs_security_descriptor *old_sdp = NULL;	// Old IFS SD (old SD with ACL to be merged)
    struct ifs_security_descriptor *new_sdp = &new_sd;	// New IFS SD (NFS4 ACEs plus -merge ACEs)
    struct persona *trustee_p = NULL;
    int fd = -1;
    int do_merge = 0;					// -merge specified && "target has existing ACL"

    // >>>>>> Step #0: PRELIMINARIES <<<<<<
    if (DEBUG) {
        sprintf(emsg, "DEBUG: apply_acl4(ENTER) stack=0x%08x\n", (unsigned) &i);
        wacl_log(emsg);
    }

    // Nothing to do?
    if (acl4 == NULL || acl4->n_aces == 0)
        return (0);

    // Fetch file handle for get/set SD and get current stat() info ...
    if ((fd = open(path, O_RDONLY|O_NOFOLLOW|O_OPENLINK)) < 0)
        WACL_ERR("open()");
    if ((fstat_rc = fstat(fd, &statbuf)))
        WACL_ERR("fstat()");
    isdir = S_ISDIR(statbuf.st_mode);
    hasacl = ((statbuf.st_flags & SF_HASNTFSACL) != 0);

    // Prepare for -merge ...
    if (DO_MERGE && hasacl) {
        old_sdp = get_sd(fd, IFS_SEC_INFO_DACL);
        if (old_sdp == NULL)					// Get SD error ...
            WACL_ERR("aclu_get_fd_sd()");
        if (old_sdp->dacl && (old_sdp->dacl->num_aces > 0)) {	// Prepare for merge ...
            do_merge = 1;
        } else {
            do_merge = 0;
            if (DEBUG) wacl_log("DEBUG: No ACL entries to merge\n");
        }

        if (DEBUG && do_merge) {
            sprintf(WACL_MSG, "@@ -merge %d ACEs ...\n", old_sdp->dacl->num_aces);
            wacl_log(NULL);
            if ((p = sd_to_text(old_sdp, &size))) {
                wacl_log("DEBUG: sd_to_text(OLD) -> ");
                wacl_log(p);
                wacl_log("\n");
                free(p);
            } else {
                WACL_ERR("security_acl_to_text()");
            }
        }
    }

    if (DEBUG) {
        sprintf(emsg, "DEBUG: fstat() rc=%d, mode=0%o%s, uid=%d, gid=%d, DO_MERGE=%d do_merge=%d\n",
            fstat_rc, statbuf.st_mode, isdir ? " (dir)" : "",
            statbuf.st_uid, statbuf.st_gid, DO_MERGE, do_merge);
        wacl_log(emsg);
    }

    // >>>>>> Step #1: TRANSLATE NFS4 ACL TO IFS NATIVE ACL <<<<<<

    // Here's what the ACEs in a OneFS native ACL look like ...
    //
    // struct ifs_ace {
    //		uint8_t size;
    //		enum ifs_ace_type type: 8;
    //		enum ifs_ace_flags flags: 8;
    //		enum ifs_internal_ace_flags ifs_flags: 8;
    //		enum ifs_ace_rights access_mask;
    //		/* struct persona trustee[]; */
    // };
    // struct ifs_security_acl {
    //		enum ifs_acl_revision revision;
    //		uint16_t num_aces;
    //		uint16_t acl_size;
    //		struct ifs_ace aces[0];
    //};

    // Initialize New IFS Security Descriptor (SD) ...
    //
    // The primary way to apply a OneFS Security Descriptor is ifs_set_security_descriptor(fd, sd, ...),
    // but aclu_ wrapper functions are a bit simpler, so that's what we use here.
    // 
    // aclu_initialize_sd(
    //		struct ifs_security_descriptor *sd,	// create SD
    //		enum ifs_sec_desc_control control,	// no setting control
    //		const struct persona *owner,		// no setting owner [ FUTURE? ]
    //		const struct persona *group,		// no setting group [ FUTURE? ]
    //		struct ifs_security_acl **dacl,		// setting DACL
    //		struct ifs_security_acl **sacl,		// no setting SACL (can't anyway?)
    //		bool copy_acls);			// copying ACLs
    if (aclu_initialize_sd(new_sdp, 0, NULL, NULL, NULL, NULL, 0))
        WACL_ERR("aclu_initialize_acl()");

    // Initialize empty IFS ACL ...
    // * 
    // * int aclu_initialize_acl(struct ifs_security_acl **acl,
    // *                        struct ifs_ace **aces,
    // *                        uint16_t num_aces, uint16_t acl_size)
    // *
    // * Helper function to alloc and compose an acl
    // *
    // * @param[in,out]	acl	pptr to acl to fill in
    // * @param[in]		aces		aces to include in acl, can be NULL
    // * @param[in]		num_aces	number of aces to include in acl
    // * @param[in]		acl_size	The size of the ACL.  If non-zero,
    // *                                      the size MUST be enough to store the
    // *                                      aces.  If zero, the acl will be large
    // *                                      enough to store the aces.
    // *
    // * @return 0 unless allocation fails (user mode only) or EINVAL
    //
    if (aclu_initialize_acl(&new_sdp->dacl, NULL, 0, IFS_MAX_SECURITY_ACL_SIZE))
        WACL_ERR("aclu_initialize_acl()");

    // Populate IFS ACL ACEs, translating NFS4 ACEs one-to-one ...
    for (i=0; i < acl4->n_aces; i++) {
        // if (DEBUG) { sprintf(emsg, "DEBUG: ... ACE %d ...\n", i+1); wacl_log(emsg); }
        ace4_p = (ace4_t *) acl4->ace4 + i;

        // @@@@ ACE4 <acetype4> -> IFS <type> (ALLOW or DENY) @@@@
        if (ace4_p->type == ACE4_ACCESS_ALLOWED_ACE_TYPE)
            ace_type = IFS_ACE_TYPE_ACCESS_ALLOWED;
        else
            ace_type = IFS_ACE_TYPE_ACCESS_DENIED;

        // @@@@ ACE4 <aceflag4> -> IFS <flags> @@@@
        // NOTE: We never see IFS_ACE_FLAG_INHERITED_ACE, because POSIX ACEs never show that, but we
        // translate all the flag bits here nevertheless.
        ace_flags = ifs_flags = 0;
        if (ace4_p->flags & ACE4_FILE_INHERIT_ACE        ) ace_flags |= IFS_ACE_FLAG_OBJECT_INHERIT;
        if (ace4_p->flags & ACE4_DIRECTORY_INHERIT_ACE   ) ace_flags |= IFS_ACE_FLAG_CONTAINER_INHERIT;
        if (ace4_p->flags & ACE4_NO_PROPAGATE_INHERIT_ACE) ace_flags |= IFS_ACE_FLAG_NO_PROPAGATE_INHERIT;
        if (ace4_p->flags & ACE4_INHERIT_ONLY_ACE        ) ace_flags |= IFS_ACE_FLAG_INHERIT_ONLY;
        if (ace4_p->flags & ACE4_INHERITED_ACE           ) ace_flags |= IFS_ACE_FLAG_INHERITED_ACE;

        // @@@@ ACE4 <n/a> -> IFS <ifs_flags> @@@@
        ifs_flags = IFS_INTERNAL_ACE_FLAG_KNOWN_MASK;

        // @@@@ ACE4 <acemask4> -> IFS <access_mask> @@@@
        // NOTE: IFS mask bits closely match Microsoft permissions mask
        ace_mask = 0;
        if (ace4_p->mask & ACE4_READ_DATA        ) ace_mask |= IFS_RTS_FILE_READ_DATA;
        if (ace4_p->mask & ACE4_WRITE_DATA       ) ace_mask |= IFS_RTS_FILE_WRITE_DATA;
        if (ace4_p->mask & ACE4_APPEND_DATA      ) ace_mask |= IFS_RTS_FILE_APPEND_DATA;
        if (ace4_p->mask & ACE4_READ_NAMED_ATTRS ) ace_mask |= IFS_RTS_FILE_READ_EA;
        if (ace4_p->mask & ACE4_WRITE_NAMED_ATTRS) ace_mask |= IFS_RTS_FILE_WRITE_EA;
        if (ace4_p->mask & ACE4_EXECUTE          ) ace_mask |= IFS_RTS_FILE_EXECUTE;
        if (ace4_p->mask & ACE4_DELETE_CHILD     ) ace_mask |= IFS_RTS_DIR_DELETE_CHILD; // only on directories
        if (ace4_p->mask & ACE4_READ_ATTRIBUTES  ) ace_mask |= IFS_RTS_FILE_READ_ATTRIBUTES;
        if (ace4_p->mask & ACE4_WRITE_ATTRIBUTES ) ace_mask |= IFS_RTS_FILE_WRITE_ATTRIBUTES;
        if (ace4_p->mask & ACE4_DELETE           ) ace_mask |= IFS_RTS_STD_DELETE;
        if (ace4_p->mask & ACE4_READ_ACL         ) ace_mask |= IFS_RTS_STD_READ_CONTROL;
        if (ace4_p->mask & ACE4_WRITE_ACL        ) ace_mask |= IFS_RTS_STD_WRITE_DAC;
        if (ace4_p->mask & ACE4_WRITE_OWNER      ) ace_mask |= IFS_RTS_STD_WRITE_OWNER;
        if (ace4_p->mask & ACE4_SYNCHRONIZE      ) ace_mask |= IFS_RTS_STD_SYNCHRONIZE;	// ignored by IFS

        // IFS ACL decoder ring ...

        /* Generic */
        // @ IFS_RTS_GENERIC_MASK	= 0xF0000000,
        // IFS_RTS_GENERIC_ALL		= 0x10000000,
        // IFS_RTS_GENERIC_EXECUTE	= 0x20000000,
        // IFS_RTS_GENERIC_WRITE	= 0x40000000,
        // IFS_RTS_GENERIC_READ		= 0x80000000,

        /* Standard */
        // @ IFS_RTS_STD_MASK		= 0x00FF0000,
        // @ IFS_RTS_STD_REQUIRED	= 0x000F0000,
        // @ IFS_RTS_STD_ALL		= 0x001F0000,
        // IFS_RTS_STD_DELETE		= 0x00010000,
        // IFS_RTS_STD_READ_CONTROL	= 0x00020000,
        // IFS_RTS_STD_WRITE_DAC	= 0x00040000,
        // IFS_RTS_STD_WRITE_OWNER	= 0x00080000,
        // IFS_RTS_STD_SYNCHRONIZE	= 0x00100000, /* ignored by IFS */

        // @ IFS_RTS_STD_EXECUTE	= IFS_RTS_STD_READ_CONTROL,
        // @ IFS_RTS_STD_READ		= IFS_RTS_STD_READ_CONTROL,
        // @ IFS_RTS_STD_WRITE		= IFS_RTS_STD_READ_CONTROL,

        // Filesystem specific (same bit values for _FILE_ and _DIR_) ...
        // @ IFS_RTS_SPECIFIC_MASK	= 0x0000FFFF,
        // @ IFS_RTS_FILE_ALL		= 0x000001FF,
        // @ IFS_RTS_DIR_ALL		= 0x000001FF,
        // NOTE: same bit values repeat for _FILE_ and _DIR_ symbols
        // IFS_RTS_FILE_READ_DATA		= 0x00000001,
        // IFS_RTS_FILE_WRITE_DATA		= 0x00000002,
        // IFS_RTS_FILE_APPEND_DATA		= 0x00000004,
        // IFS_RTS_FILE_READ_EA			= 0x00000008,
        // IFS_RTS_FILE_WRITE_EA		= 0x00000010,
        // IFS_RTS_FILE_EXECUTE			= 0x00000020,
        // IFS_RTS_FILE_UNKNOWN_DIR_ALIAS	= 0x00000040,
        // IFS_RTS_FILE_READ_ATTRIBUTES		= 0x00000080,
        // IFS_RTS_FILE_WRITE_ATTRIBUTES	= 0x00000100,

        // @@@@ ACE4 <who> -> IFS <trustee persona> @@@@
        //
        // NOTE: We ONLY have to deal with numeric IDs (UID, GID) and NFS4 'special IDs' here.
        //
        // NOTE: OneFS/BSD-specific values (OneFS 8.0 & later) ...
        //
        // ACL_USER_OBJ     Permissions apply to file owner					(OWNER@)
        // ACL_USER         Permissions apply to additional user specified by qualifier		(named user)
        // ACL_GROUP_OBJ    Permissions apply to file group					(GROUP@)
        // ACL_GROUP        Permissions apply to additional group specified by qualifier	(named group)
        // ACL_MASK         Permissions specify mask				(POSIX.1e ACLs only!)
        // ACL_OTHER        Permissions apply to other				(POSIX.1e ACLs only!)
        // ACL_OTHER_OBJ    Same as ACL_OTHER					(POSIX.1e ACLs only!)
        // ACL_EVERYONE     Permissions apply to everyone@					(EVERYONE@)
        //
        // NOTE: Legacy OneFS IFS values (pre-OneFS 8.0) ...
        //
        // All identities expressed internally as a OneFS 'persona' abstraction.
        //
        // IFS_ID_TYPE_UID			(named user)
        // IFS_ID_TYPE_GID			(named group)
        // IFS_ID_TYPE_EVERYONE	    		(EVERYONE@)
        // IFS_ID_TYPE_NULL			n/a
        // IFS_ID_TYPE_CREATOR_OWNER		(OWNER@)
        // IFS_ID_TYPE_CREATOR_GROUP		(GROUP@)

        whotype = ace4_p->who[0];	// (will either be a digit or a letter)
        id = atoi(ace4_p->who);		// (Only valid for numeric who[])

        // Special NFS4 identities ...
        // (Simplified here because all incoming trustee values are constrained to be either
        // numeric UID/GID values or these special identifiers.)
        if (whotype == 'E') {							// EVERYONE@ (SID S-1-1-0)
            persona_copy(&trustee_p, persona_everyone());
        } else if (whotype == 'O') {		 				// OWNER@
            // Per bug 69460, conditionally use creator_owner translation ...
            if (ace_flags & IFS_ACE_FLAG_INHERIT_ONLY) {	// SID S-1-3-0
                persona_copy(&trustee_p, persona_creator_owner());
            } else {	// Fall through to apply current owning uid ..
                id = statbuf.st_uid;
                whotype = '0';
            }
        } else if (whotype == 'G') {						// GROUP@
            // Per bug 69460, conditionally use creator_group translation ...
            if (ace_flags & IFS_ACE_FLAG_INHERIT_ONLY) {	// SID S-1-3-1
                persona_copy(&trustee_p, persona_creator_group());
            } else {	// Fall through to apply current owning gid ...
                id = statbuf.st_gid;
                whotype = '0';		// 'groupness' is in the persona?
            }
        }

        // Named users and groups (including OWNER@ and GROUP@ resolutions) ...
        if (isdigit(whotype)) {							// NAMED (numeric) ...
            if ((ace4_p->flags & ACE4_IDENTIFIER_GROUP) || (whotype == 'G')) {	// ... group!
                if ((trustee_p = persona_alloc_gid(id)) == NULL) {
                    sprintf(emsg,"Cannot map GID %d", id);
                    WACL_ERR(emsg);
                }
            } else {								// ... user!
                if ((trustee_p = persona_alloc_uid(id)) == NULL) {
                    sprintf(emsg,"Cannot map UID %d", id);
                    WACL_ERR(emsg);
                }
            }
        }

        // Add new ACE at end of ACL ...
        //
        // int aclu_add_new_ace(
        //	struct ifs_security_acl **acl,
        //	struct ifs_ace **acep,		// (optional) return pointer to ACE
        //	enum ifs_ace_type type,
        //	enum ifs_ace_rights access_mask,
        //	enum ifs_ace_flags flags,
        //      enum ifs_internal_ace_flags ifs_flags,
        //	const struct persona *trustee);
        if (aclu_add_new_ace(&new_sdp->dacl, NULL, ace_type, ace_mask, ace_flags, ifs_flags, trustee_p))
     	    WACL_ERR("aclu_add_new_ace()");
        if (trustee_p) persona_free(trustee_p);
        trustee_p = NULL;
    }

    if (DEBUG) {
        if ((p = security_acl_to_text(new_sdp->dacl))) {
            wacl_log("DEBUG: security_acl_to_text(NFS4) -> ");
            wacl_log(p);
            wacl_log("\n");
            free(p);
        } else {
            WACL_ERR("security_acl_to_text()");
        }
    }

    // Validate our freshly-computed IFS ACL derived from NFS4 ACEs ..
    if (aclu_validate_acl(new_sdp->dacl, new_sdp->dacl->acl_size))
        WACL_ERR("aclu_validate_acl()");

    // >>>>>> Step #2: MERGE (with -merge) <<<<<<

    // If -merge was specified and target had an existing ACL, merge INHERITED ACEs from
    // existing ACL into the ACL we are about to apply ...
    //
    //	IFS_SD_CTRL_OWNER_DEFAULTED		= 0x0001, YES
    //	IFS_SD_CTRL_GROUP_DEFAULTED		= 0x0002, YES
    //	IFS_SD_CTRL_DACL_PRESENT		= 0x0004, YES
    //	IFS_SD_CTRL_DACL_DEFAULTED		= 0x0008,
    //	IFS_SD_CTRL_SACL_PRESENT		= 0x0010,
    //	IFS_SD_CTRL_SACL_DEFAULTED		= 0x0020, YES
    //	IFS_SD_CTRL_DACL_AUTO_INHERIT_REQ	= 0x0100, YES
    //	IFS_SD_CTRL_SACL_AUTO_INHERIT_REQ	= 0x0200, YES
    //	IFS_SD_CTRL_DACL_AUTO_INHERITED		= 0x0400, YES
    //	IFS_SD_CTRL_SACL_AUTO_INHERITED		= 0x0800, YES
    //	IFS_SD_CTRL_DACL_PROTECTED		= 0x1000,
    //	IFS_SD_CTRL_SACL_PROTECTED		= 0x2000,
    //	IFS_SD_CTRL_RM_CONTROL_VALID		= 0x4000, /* ignored by IFS */
    //	IFS_SD_CTRL_SELF_RELATIVE		= 0x8000, /* always SET */ YES

    if (do_merge) {
        new_sdp->control = (
            IFS_SD_CTRL_OWNER_DEFAULTED|
            IFS_SD_CTRL_GROUP_DEFAULTED|
            IFS_SD_CTRL_DACL_PRESENT|
            IFS_SD_CTRL_SACL_DEFAULTED|
            IFS_SD_CTRL_DACL_AUTO_INHERIT_REQ|
            IFS_SD_CTRL_SACL_AUTO_INHERIT_REQ|
            IFS_SD_CTRL_DACL_AUTO_INHERITED|
            IFS_SD_CTRL_SACL_AUTO_INHERITED|
            IFS_SD_CTRL_SELF_RELATIVE
        );
        for (i=0; i<old_sdp->dacl->num_aces; i++) {
            if (aclu_get_ace_at(old_sdp->dacl, i, &ace_p))
     	        WACL_ERR("aclu_get_ace_at(OLD)");
            // We'd like to just -merge inherited_ace ACEs, but those bits may be missing!
            // if (ace_p->flags & IFS_ACE_FLAG_INHERITED_ACE) // damn! inherited_ace flag lost in PermissionRepair!
            if (aclu_add_new_ace(&new_sdp->dacl, NULL, 
                                 ace_p->type,
                                 ace_p->access_mask,
                                 ace_p->flags|IFS_ACE_FLAG_INHERITED_ACE,
                                 ace_p->ifs_flags,
                                 get_trustee(ace_p))
                ) WACL_ERR("aclu_add_new_ace(-merge)");
        }
        // Re-validate our freshly-computed IFS ACL post -merge ...
        if (aclu_validate_acl(new_sdp->dacl, new_sdp->dacl->acl_size))
            WACL_ERR("aclu_validate_acl()");
    }

    // if (do_merge) {
    //     if (aclu_merge_acls(&new_sdp->dacl, old_sdp->dacl))
    //  	    WACL_ERR("aclu_merge_acls()");
    //}

    // Check sd ...
    if (DEBUG) {
        // Validate our new IFS SD ...
        if ((p = sd_to_text(new_sdp, &size))) {
            wacl_log("DEBUG: sd_to_text(NEW) -> ");
            wacl_log(p);
            wacl_log("\n");
            free(p);
        } else {
            WACL_ERR("security_acl_to_text()");
        }
    }

    // //     if (DEBUG == 42) {
    // //         // void aclt_print_sd_comparison(
    // //         //	const struct ifs_security_descriptor *sd1,
    // //         //	const struct ifs_security_descriptor *sd2,
    // //         //	enum ifs_security_info secinfo,
    // //         //	bool isdir)
    // //         sd2_p = get_sd(fd, IFS_SEC_INFO_MAX);
    // //         aclt_print_sd_comparison(sd2_p, sd_p, IFS_SEC_INFO_MAX, isdir);
    // //     }

    // >>>>>> Step #3: APPLY SD <<<<<<

    // Apply DACL using derived SD ...
    //
    // int aclu_set_fd_sd(int fd, enum ifs_security_info secinfo,
    //     struct ifs_security_descriptor *sd, enum ifs_smas_flags sflags)
    //
    if (aclu_set_fd_sd(fd, IFS_SEC_INFO_DACL, new_sdp, SMAS_FLAGS_NONE))
        WACL_ERR("aclu_set_fd_sd()");

    // Success!
    retval = 0;

out: // This is ONLY path out, assuring release of all dynamically-allocated data ...
    if (fd >= 0) close(fd);
    if (old_sdp) aclu_free_sd(old_sdp, 0);
    if (new_sdp) aclu_free_sd(new_sdp, 0);
    if (trustee_p) persona_free(trustee_p);
    return (retval);
}

void
usage(void)
{
    printf("Usage: wacls [-d|h|v ...] [-cd=<directory>] [-merge]\n");
    printf("    Where: -d - Sets DEBUG mode\n");
    printf("           -h - Prints this usage() and exits\n");
    printf("           -v - Sets VERBOSE mode\n");
    printf("           -cd=<directory> - Sets CWD context for passed path names\n");
    printf("           -merge - Merge applied ACLs with existing ACLs\n");
    printf("NOTE: Operation *requires* root privilege!\n");
    exit (0);
}

// main() for 'wacls' - read incoming [acl4, path] pairs and apply the acl4 to the path.

// NOTE: Byte-ordering in the binary acl4_t values is not considered in this code, as
// both wacls and its dance partner are expected to be running on x64 hardware with the
// same byte ordering.

int
main(int argc, char *argv[])
{
    int arg, rc;
    int retval;				// 0 on success, else errno
    unsigned acl4size, pathsize;	// Two binary values for every ACL4 received
    acl4_t acl4;			// Our ONE NFS4 ACL buffer
    char path[2048];			// Our ONE (generous) path buffer
    char cwdpath[2048];			// Our ONE (generous) getcwd() buffer
    char emsg[1024];			// Formatting buffer
    time_t t_now;

    // Enforce that we are running as root (EUID == 0) ...
    // RFE: klooge: could check getuid() LUID to only work for permitted users, but we
    // rely on this program being controlled by sudo mechanism.
    if (geteuid() != 0)
        WACL_ERR("FATAL: Must run as root!");

    // Note CWD with respect to how path names are evaluated ...
    getcwd(cwdpath, sizeof(cwdpath));

    // Process args ...
    for (arg=1; arg<argc; arg++) {
        if (strcmp(argv[arg], "-d") == 0) {
            DEBUG = 1;
        } else if (strcmp(argv[arg], "-h") == 0) {
            usage();
        } else if (strcmp(argv[arg], "-v") == 0) {
            VERBOSE = 1;
        } else if (strncmp(argv[arg], "-cd=", 4) == 0) {
            if (strlen(argv[arg]+4) < 1)
                WACL_ERR("Missing -cd= <directory> value!");
            CD_ARG = argv[arg]+4;
        } else if (strcmp(argv[arg], "-merge") == 0) {
            DO_MERGE = 1;
        } else {
            WACL_ERR("Invalid arguments!");
        }
    }

    if (VERBOSE) {
        wacl_log("CWD: ");			// Before chdir()
        wacl_log(cwdpath);
        wacl_log("\n");
    }

    // chdir() to our -cd= parameter when specified ...
    if (CD_ARG) {
        strcpy(cwdpath, CD_ARG);
        if (chdir(cwdpath))
            WACL_ERR("chdir()");
        getcwd(cwdpath, sizeof(cwdpath));	// After chdir()
        if (VERBOSE) {
            wacl_log("-CD: ");
            wacl_log(cwdpath);
            wacl_log("\n");
        }
    }

    // Rough check that we ended up in /ifs ...
    if ((strncmp(cwdpath, "/ifs/", 5) != 0) && (strcmp(cwdpath, "/ifs") != 0))
        wacl_log("ERROR: Must operate within /ifs!\n");

    // Looks like we're good to BEGIN ...
    if (VERBOSE) {
        time(&t_now);
        sprintf(emsg, "BEGIN: %s", ctime(&t_now));
        wacl_log(emsg);
    }

    // Read binary acl4+path pairs from from stdin and apply them ...
    while (1) {
        // Read an acl4+path pair ...
        if (fread(&acl4size, 1, 4, stdin) != 4)			WACL_ERR("fread(<acl4size>)");
        if (acl4size == 0) break; // (normal termination)
        if (fread(&pathsize, 1, 4, stdin) != 4)			WACL_ERR("fread(<pathsize>)");
        if (acl4size == 0) break; // (ok termination)
        if (acl4size > sizeof(acl4_t))				WACL_ERR("acl4 overflow!");
        if (pathsize > sizeof(path))				WACL_ERR("path overflow!");
        if (fread(&acl4, 1, acl4size, stdin) != acl4size)	WACL_ERR("fread(<acl4>)");
        if (fread(path, 1, pathsize, stdin) != pathsize)	WACL_ERR("fread(<path>)");

        // Apply the acl4 (ignore errors; they were already logged) ...
	// NOTE: -merge happens in apply_acl4(), which also logs errors. We only log on success
        // unless VERBOSE is used.
        if (apply_acl4(&acl4, path)) {
            N_Apply_Failures++;
        } else {
            N_Apply_Successes++;
            if (VERBOSE) {
                sprintf(WACL_MSG, "@ \"%s\"\n", path);
                wacl_log(NULL);
            }
        }
    }
    retval = 0;		// Normal exit

out:
    if (N_Errors) {
        sprintf(emsg, "NOTE: %u ERRORS encountered\n", N_Errors);
        wacl_log(emsg);
    }
    if (VERBOSE || N_Apply_Failures) {
        sprintf(emsg, "NOTE: %u ACLs applied, %u ACLs FAILED\n", N_Apply_Successes, N_Apply_Failures);
        wacl_log(emsg);
        time(&t_now);
        sprintf(emsg, "FINISH: %s", ctime(&t_now));
        wacl_log(emsg);
    }
    return (retval);
}
