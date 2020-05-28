
// DESCRIPTION: 'xacls' utility and test harness for pwalk_acls.c module.

// DISCLAIMER:  The is FREE CODE for instructional purposes only.  There are no warranties,
// expressed or implied for this code, including any warrantees of correctness or suitability
// for any particular purpose.  Use at you own risk!

// BY: Bob.Sneed@isilon.com, July 2016

// To build 'xacls' on Linux:
// 	gcc xacls.c pwalk_acls.c -dH -lacl -o xacls
//	NOTE: -dH enables core dumps, may require 'ulimit -c unlimited'
//	NOTE: debug with 'gdb xacls core.<pid>' ... 'bt'

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#ifdef __linux__
#include <linux/types.h>
#include <linux/nfs4.h>
#include <acl/libacl.h>
#else
#include <sys/mount.h>
#include <nfs/nfs.h>
#include <sys/acl.h>
#endif
#include <sys/stat.h>
#include <assert.h>
#include "pwalk_acls.h"         // Data types & function prototypes

static int DEBUG = 0;

static void
PW_ACL_ERR(char *emsg)
{
    printf("# FATAL: %s [errno=%d] \"%s\"\n", emsg, errno, strerror(errno));
    exit (-1);
}

static void
usage(void)
{
    printf("Usage: xacls [-d|h|i|o|p|- ...] [-sp] [-sh] [-sn] [-[o|p] <path|cmd>] <path> [<path> ...] ...\n");
    printf("     Where: -d -> enable DEBUG trail\n");
    printf("            -h -> help; show this usage() and exit\n");
    printf("            -i -> input path names from stdin (ignore non-option args)\n");
    printf("            -o -> output to <path> as a file (instead of -p)\n");
    printf("            -p -> output to <cmd> as a pipe (instead of -o)\n");
    printf("            -- -> end option list; next args are path names\n");
    printf("            -sp -> show POSIX ACLs input\n");
    printf("            -sn -> show ACL4 values as nfs4_setfacl commands\n");
    printf("            -sh -> show ACL4 values in CHEX format\n");
    printf("            -s1 -> show ACL4 values in OneFS format\n");
    printf("     NOTE: Must usually be run as root to be able to read all ACLs!\n");
    exit (-1);
}

int
main(int argc, char *argv[])	// Linux 'xacls(1)'
{
    int arg, rc;
    char *path, pathbuf[2048];	// Generous buffer for stdin path names
    int pathlen;		// Size of path in pathbuf
    struct stat sb;
    int pw_stdin = 0;		// Unless '-i' or '--' is specified
    int show_posix = 0;		// Unless '-sp' used
    int show_nfs4_setfacl = 0;	// Unless '-sn' used
    int show_chex = 0;		// Unless '-sh' used
    int show_onefs = 0;		// Unless '-s1' used
    int write_acl4bin = 0;	// Unless '-o' or '-p' used

    // pw_acl_* ACL4 vbls ...
    int dir_flag;		// From S_ISDIR
    int aclstat;		// &4 == dacl, &2 == non-trivial acl, &1 == trivial_acl, 0 == none
    acl4_t acl4;
    char pw_acls_emsg[64] = "";
    int pw_acls_errno = 0;
    char acl4OUTwhere[1024];	// From -o or -p args (path or command)
    char acl4OUTmode;		// 'o' (file) or 'p' (pipe)
    FILE *acl4OUT = NULL;

    // Args ...
    if (argc < 2) usage();
    assert(getuid() == 0);

    // 'xacls' argument processing ...
    for (arg = 1; arg < argc; arg++) {
        // Options ...
        if (strcmp(argv[arg], "-d") == 0) {
            pw_acls_DEBUGin = pw_acls_DEBUGout = DEBUG = 1;
            continue;
        } else if (strcmp(argv[arg], "-h") == 0) {
            usage();
        } else if (strcmp(argv[arg], "-i") == 0) {
            pw_stdin = 1;
            continue;
        } else if ((strcmp(argv[arg], "-o") == 0) || (strcmp(argv[arg], "-p") == 0)) {
            acl4OUTmode = argv[arg][1];	// 'o' (file) or 'p' (pipe)
            write_acl4bin = 1;
            assert ((arg+1) < argc);
            strcpy(acl4OUTwhere, argv[arg+1]);
            arg++;
            continue;
        } else if (strcmp(argv[arg], "-sn") == 0) {
            show_nfs4_setfacl = 1;
            continue;
        } else if (strcmp(argv[arg], "-sp") == 0) {
            pw_acls_SHOW_POSIX = show_posix = 1;
            continue;
        } else if (strcmp(argv[arg], "-sh") == 0) {
            show_chex = 1;
            continue;
        } else if (strcmp(argv[arg], "-s1") == 0) {
            show_onefs = 1;
            continue;
        } else if (strcmp(argv[arg], "--") == 0) {
            pw_stdin = 1;
            continue;
        } else if (argv[arg][0] == '-') {
            PW_ACL_ERR("Invalid command option!");
        } else {
            break;	// no more options; must be first path name arg
        }
    }

    // Open acl4OUT if we intend to create binary output ...
    if (write_acl4bin) {
        if (acl4OUTmode == 'p') acl4OUT = popen(acl4OUTwhere, "we");      // pipe
        else                  acl4OUT = fopen(acl4OUTwhere, "we");       // file
        if (acl4OUT == NULL) {
	    printf("# FATAL: Cannot %s(\"%s\")! [errno=%d]\n", (acl4OUTmode == 'p') ? "popen" : "open", acl4OUTwhere, errno);
            exit(-1);
        }
    }

    // 'xacls' main loop for path names ...
    while (1) {
        // Get a path value ...
        if (pw_stdin) {	// ... from stdin
            if ((path = fgets(pathbuf, sizeof(pathbuf), stdin)) == NULL)
                break;
            pathlen = strlen(path);
            if (pathlen > 0) path[pathlen - 1] = '\0';	// strip '\n'!
        } else {	// ... from args
            if (arg >= argc)
                break;
            path = argv[arg];
            arg++;
        }

        // Process stat() info ...
	rc = lstat(path, &sb);
	if (rc) {
	    printf("# ERROR: Cannot stat(\"%s\")! [errno=%d]\n", path, errno);
	    continue;
	}
        dir_flag = S_ISDIR(sb.st_mode);

        // Show header for -sp or DEBUG ...
        if (DEBUG || show_posix) {
            printf("# -------------------------------------------------\n");
	    printf("# file: \"%s\"\n", path);
            printf("# owner: %d\n", sb.st_uid);
            printf("# group: %d\n", sb.st_gid);
            printf("# mode: 0%3o%s\n", sb.st_mode, dir_flag ? " (dir)" : "");
        }

        // INPUT & TRANSLATE: Translate POSIX ACL plus DACL to a single ACL4 ...
        pw_acl4_get_from_posix_acls(path, dir_flag, &aclstat, &acl4, pw_acls_emsg, &pw_acls_errno);
        if (pw_acls_errno) printf("ERROR: %s [%d - \"%s\"]\n", pw_acls_emsg, pw_acls_errno, strerror(pw_acls_errno));

//fprintf(stderr, "@ %s\n", path);
//fprintf(stderr, "@ %d\n", dir_flag);
//fprintf(stderr, "@ %s
//fprintf(stderr, "@ %s
//fprintf(stderr, "@ %d

        // Show post-translation results for -sp ...
        if (show_posix) {
             if (aclstat == 0) printf("# POSIX ACL%s not present\n", dir_flag ? " and DACL" : "");
             else printf("# POSIX ACL%s produced %d NFS4 ACEs\n", dir_flag ? " plus DACL" : "", acl4.n_aces);
        }

        // OUTPUT: ACL4 outputs (all are no-ops with an empty acl4) ...
        if (show_nfs4_setfacl)	// (to <stream>)
            pw_acl4_fprintf_nfs4_setfacl(&acl4, path, stdout);
        if (show_chex)		// (to stdout)
            pw_acl4_fprintf_chex(&acl4, path, &sb, stdout);
        if (show_onefs)		// (to stdout)
            pw_acl4_fprintf_onefs(&acl4, path, &sb, stdout);
        if (write_acl4bin)	// (to acl4OUT)
            pw_acl4_fwrite_binary(&acl4, path, &acl4OUT, acl4OUTmode, pw_acls_emsg, &pw_acls_errno);
    }
    // Gracefully shutdown/close acl4OUT ...
    pw_acl4_fwrite_binary(NULL, NULL, &acl4OUT, acl4OUTmode, pw_acls_emsg, &pw_acls_errno);
}
