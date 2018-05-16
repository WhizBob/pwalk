// pwalk_report.c - pwalk generic output reporting module.

#define PWALK_REPORT_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "pwalk.h"
#include "pwalk_report.h"
#include "pwalk_onefs.h"

static struct {
   char *name;
   void *value;
   char *format;
} RPT_LINE[64];

typedef struct {
   int mask;			// Source for data
   char *name;
   char *format;
   char *desc;
} RPT_FIELD;

static RPT_FIELD pwalk_report_fields[] = {
   { 0, "ifspath", "\"%s\"", "File pathname, rooted in /ifs" },
   { PWget_STAT, "ref_time", "%ld", "Time of metadata query" },
   { PWget_STAT, "st_atime", "%ld", "File access time" },
   { PWget_STAT, "st_mtime", "%ld", "File modify time" },
   { PWget_STAT, "st_ctime", "%ld", "File change time" },
   { PWget_STAT, "st_birthtime", "%ld", "File birth time" },	// Not accurate over NFS
   { PWget_STAT, "st_uid", "%lu", "File owner UID" },
   { PWget_STAT, "st_gid", "%lu", "File owner GID" },
   { PWget_STAT, "st_blks", "%llu", "File number of 1K blocks allocated" },
   { PWget_STAT, "st_size", "%llu", "File nominal file size" },
   { PWget_STAT, "st_mode", "%03o", "File mode bits (octal)" },
   { PWget_STAT, "st_mode_str", "%s", "File mode bits (as 'rwx' string)" },
   { PWget_STAT, "dir_sum_st_size", "%llu", "Directory sum of st_size" },
   { PWget_STAT, "dir_sum_st_blks", "%llu", "Directory sum of st_blks" },

   { PWget_OWNER, "owner_name", "%s", "Owner name" },
   { PWget_GROUP, "group_name", "%s", "Group name" },
   { PWget_ACL4, "NFS4_ACL_CHEX", "%x", "File ACL4 in hexadecimal format" },
   { PWget_ACL4, "NFS4_ACL_ONEFS_str", "%s", "File ACL4 in OneFS format (experimental)" },
   { PWget_STUB, "m_stubbed", "%d", "OneFS: File is stubbed (boolean)" },

//#ifdef __ONEFS__
   { PWget_SD, "owner_SID", "%s", "OneFS: owner SID" },
   { PWget_SD, "group_SID", "%s", "OneFS: group SID" },
   { PWget_WORM, "w_ctime", "%ld", "OneFS: SmartLock WORM ctime (Compliance mode only)" },
   { PWget_WORM, "w_committed", "%d", "OneFS: SmartLock WORM committed state (boolean)" },
   { PWget_WORM, "w_expiration_time", "%ld", "OneFS: SmartLock WORM committed state (boolean)" },
   { PWget_WORM, "w_compliance", "%d", "OneFS: SmartLock Compliance mode (boolean)" },
   { PWget_WORM, "eff_ctime", "%lu", "OneFS: Effective ctime for SmartLock" },
   { PWget_WORM, "eff_commit_str", "%c", "OneFS: SmartLock status code [-CcX]" },
   { PWget_WORM, "eff_expiration_time", "%ld", "OneFS: SmartLock expiration time" },
//#endif

// BEGIN st_flags ...
//#define	UF_SETTABLE	0xf000ffff	/* mask of owner changeable flags */
//#define	SF_SETTABLE	0x0fff0000	/* mask of superuser changeable flags */
   { PWget_STAT, "UF_NODUMP", "%d", "do not dump file" },
   { PWget_STAT, "UF_IMMUTABLE", "%d", "file may not be changed" },
   { PWget_STAT, "UF_APPEND", "%d", "writes to file may only append" },
   { PWget_STAT, "UF_OPAQUE", "%d", "directory is opaque wrt. union" },
   { PWget_STAT, "UF_NOUNLINK", "%d", "file may not be removed or renamed" },
   { PWget_STAT, "UF_INHERIT", "%d", "this flag is unused but set on" },
   { PWget_STAT, "UF_WRITECACHE", "%d", "writes are cached." },
   { PWget_STAT, "UF_WC_INHERIT", "%d", "unused but set on all new files." },
   { PWget_STAT, "UF_DOS_NOINDEX", "%d", "DOS attr: don't index." },
   { PWget_STAT, "UF_ADS	", "%d", "file is ADS directory or stream." },
   { PWget_STAT, "UF_HASADS", "%d", "file has ADS dir." },
   { PWget_STAT, "UF_WC_ENDURANT", "%d", "write cache is endurant." },
   { PWget_STAT, "UF_SPARSE", "%d", "file is sparse" },
   { PWget_STAT, "UF_REPARSE", "%d", "reparse point" },
   { PWget_STAT, "UF_ISI_UNUSED1", "%d", "ISI UNUSED FLAG VALUE" },
   { PWget_STAT, "UF_HIDDEN", "%d", "file is hidden" },
   { PWget_STAT, "SF_ARCHIVED", "%d", "file is archived" },
   { PWget_STAT, "SF_IMMUTABLE", "%d", "file may not be changed" },
   { PWget_STAT, "SF_APPEND", "%d", "writes to file may only append" },
   { PWget_STAT, "SF_FILE_STUBBED", "%d", "file is a stub of archived file" },
   { PWget_STAT, "SF_NOUNLINK", "%d", "file may not be removed or renamed" },
   { PWget_STAT, "SF_SNAPSHOT", "%d", "snapshot inode" },
   { PWget_STAT, "SF_NOCOW", "%d", "don't snapshot inode" },
   { PWget_STAT, "SF_CACHED_STUB", "%d", "stub has cached data" },
   { PWget_STAT, "SF_HASNTFSACL", "%d", "file has an NTFS ACL block" },
   { PWget_STAT, "SF_HASNTFSOG", "%d", "file has an NTFS owner/group block" },
   { PWget_STAT, "UF_DOS_ARCHIVE", "%d", "DOS Attribute: ARCHIVE bit" },
   { PWget_STAT, "UF_DOS_HIDDEN", "%d", "DOS Attribute: HIDDEN bit" },
   { PWget_STAT, "UF_DOS_RO", "%d", "DOS Attribute: READONLY bit" },
   { PWget_STAT, "UF_DOS_SYSTEM", "%d", "DOS Attribute: SYSTEM bit" },
// END st_flags ...
   { 0, NULL, NULL, NULL }
};

// save_string() - keep a string & return pointer to it, else die!

static char *
save_string(char *str)
{
   char *p;

   p = malloc(strlen(str)+1);
   assert (p != NULL);
   strcpy(p, str);
   return(p);
}

// pwalk_report_bind() - bind worker-specific addresses into RPT_LINE[]

void
pwalk_report_bind(char *path, struct stat *sb, worm_info_t *wi)
{
   int i, found;

   for (i=0; RPT_LINE[i].name; i++) {
      found = 0;
      if (strcmp(RPT_LINE[i].name, "ifspath") == 0)
         PWget_MASK |= pwalk_report_fields[i].mask;
      else if (strcmp(RPT_LINE[i].name, "ref_time") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "st_atime") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "st_mtime") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "st_ctime") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "st_birthtime") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "st_uid") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "st_gid") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "st_blks") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "st_size") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "st_mode") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "st_mode_str") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "dir_sum_st_size") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "dir_sum_st_blks") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "NFS4_ACL_MASK") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "NFS4_ACL_ONEFS_str") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "m_stubbed") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "w_ctime") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "w_committed") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "w_expiration_time") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "eff_ctime") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "eff_commit_str") == 0)
         ;
      else if (strcmp(RPT_LINE[i].name, "eff_expiration_time") == 0)
         ;
      else assert("RPT field name unknown!" == NULL);
   }
}

// clean_line() - normalize input string
// Input lines are:
//	# comment
//	// comment
//	<non-alphanumeric> comment
//	name <format>

static int
parse_line(char *line, char **p_name, char **p_format)
{
   char *p;

   *p_name = *p_format = NULL;

   // Eliminate newline and whitespace at end ...
   if ((p = index(line, '\n'))) *p = '\0';
   for (p -= 1; p >= line; p--) if (isspace(*p)) *p = '\0'; else break;
   // Eliminate whitespace at beginning ...
   for (p = line; *p; p++) if (isspace(*p)) *p = '\0'; else break;
   // If 1st non-white character is non-alphanumeric, entire line is a comment ...
   // If line is blank, treat like a comment ...
   if (*p == '\0') return(0); 
   if (!isalnum(*p)) return(0); 
   *p_name = p;
   strsep(&p, " \t");
   *p_format = p;
   
   return(1);
}

// csv_pfile_parse() - Parses -csv= input parameter file

int
csv_pfile_parse(char *pfile)
{
   FILE *fp;
   char line[1024]; // generous
   char *p_name, *p_format;
   int found, i, linenum, nf;
   
   if ((fp = fopen(pfile, "r")) == NULL)
     { fprintf(stderr, "ERROR: Cannot open -csv= file!\n"); exit(-1); }

   nf = linenum = 0;
   while (fgets(line, sizeof(line), fp)) {
      linenum += 1;
      if (parse_line(line, &p_name, &p_format) == 0) continue;	// comment or blank line
      for (i=0, found=0; pwalk_report_fields[i].name; i++) {
         if (strcmp(p_name, pwalk_report_fields[i].name) == 0) {
            found = 1;
            PWget_MASK |= pwalk_report_fields[i].mask;			// mask; aggregate source bits
            RPT_LINE[nf].name = pwalk_report_fields[i].name;		// name; field name
            if (p_format) {
               RPT_LINE[nf].format = save_string(p_format);		// format; dynamic, user-set
            } else {
               RPT_LINE[nf].format = pwalk_report_fields[i].format;	// format; static, default
            }
            break;
         }
      }
      if (!found) { fprintf(stderr, "ERROR: \"%s\" - bad field specification!\n", p_name); exit(-1); }
      nf += 1;
   }

   if (ferror(fp))
     { fprintf(stderr, "ERROR: Error reading -csv= file!\n"); exit(-1); }
   if (nf < 1)
     { fprintf(stderr, "ERROR: No valid fields in -csv= file!\n"); exit(-1); }

   if (VERBOSE > 1) {
      fprintf(stderr, "-csv with %d fields from these sources;\n", nf);
      if (PWget_MASK & PWget_STAT) fprintf(stderr, "\tPWget_STAT\n");
      if (PWget_MASK & PWget_WORM) fprintf(stderr, "\tPWget_WORM\n");
      if (PWget_MASK & PWget_STUB) fprintf(stderr, "\tPWget_STUB\n");
      if (PWget_MASK & PWget_ACLP) fprintf(stderr, "\tPWget_ACLP\n");
      if (PWget_MASK & PWget_ACL4) fprintf(stderr, "\tPWget_ACL4\n");
      if (PWget_MASK & PWget_SD) fprintf(stderr, "\tPWget_SD\n");
   }
   return (nf);
}
