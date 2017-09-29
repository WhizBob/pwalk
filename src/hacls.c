// 'SID:.....' case as 'user:...'
// Consider adding INHERITED SID: ACEs either in xacls or or-ing them in when wacls runs

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#define PWALK_ACLS_SOURCE 1
#include "pwalk_acls.h"

int DEBUG = 0;

// This program converts OneFS-formatted or CITI nfs4_getfacl ACL representations to a common format which
// represents the ace_mask and ace_flags values for each ACE in a compact hexadecimal (CHEX) format.
//
// *** EXAMPLE: OneFS 'ls -lend' ***
//
// # ls -lend acl_test_d.1
// drwxr-x--- +  2 0  0  0 Jul  9 06:10 acl_test_d.1		// INPUT: Trustees as NUMERIC (UID, GID, SID) values ...
//  OWNER: user:0
//  GROUP: group:0
//  0: user:0 allow dir_gen_execute,std_write_dac,list,add_file,add_subdir,dir_read_attr,dir_write_attr 
//  1: user:501 allow dir_gen_execute,list,dir_read_attr 
//  2: group:0 allow std_read_dac,std_synchronize,dir_read_attr 
//  3: SID:S-1-1-0 allow std_read_dac,std_synchronize,dir_read_attr 
//  4: SID:S-1-3-0 allow dir_gen_execute,std_write_dac,list,add_file,add_subdir,delete_child,dir_read_attr,dir_write_attr,object_inherit,container_inherit,inherit_only 
//  5: SID:S-1-3-1 allow dir_gen_execute,list,dir_read_attr,object_inherit,container_inherit,inherit_only 
//  6: SID:S-1-1-0 allow dir_gen_execute,dir_read_attr,object_inherit,container_inherit,inherit_only 
//
// # ls -lend acl_test_d.1 | hacls				// OUTPUT: CHEX format ...
// drwxr-x--- +  2 0  0  0 Jul  9 06:10 acl_test_d.1
//  OWNER: user:0
//  GROUP: group:0
//  0: A 1601a7.00 user:0 <OWNER@>
//  1: A 1200a1.00 user:501
//  2: A 120080.00 group:0 <GROUP@>
//  3: A 120080.00 everyone
//  4: A 1601e7.0b creator_owner
//  5: A 1200a1.0b creator_group
//  6: A 1200a0.0b everyone
// 
// # ls -led acl_test_d.1
// drwxr-x--- +  2 root  wheel  0 Jul  9 06:10 acl_test_d.1	// INPUT: Trustees as resolved NAMES ...
//  OWNER: user:root
//  GROUP: group:wheel
//  0: user:root allow dir_gen_execute,std_write_dac,list,add_file,add_subdir,dir_read_attr,dir_write_attr 
//  1: user:u501 allow dir_gen_execute,list,dir_read_attr 
//  2: group:wheel allow std_read_dac,std_synchronize,dir_read_attr 
//  3: everyone allow std_read_dac,std_synchronize,dir_read_attr 
//  4: creator_owner allow dir_gen_execute,std_write_dac,list,add_file,add_subdir,delete_child,dir_read_attr,dir_write_attr,object_inherit,container_inherit,inherit_only 
//  5: creator_group allow dir_gen_execute,list,dir_read_attr,object_inherit,container_inherit,inherit_only 
//  6: everyone allow dir_gen_execute,dir_read_attr,object_inherit,container_inherit,inherit_only
//
// # ls -led acl_test_d.1 | hacls
// drwxr-x--- +  2 root  wheel  0 Jul  9 06:10 acl_test_d.1	// OUTPUT: Trustees as resolved NAMES ...
//  OWNER: user:root
//  GROUP: group:wheel
//  0: A 1601a7.00 user:root <OWNER@>
//  1: A 1200a1.00 user:u501
//  2: A 120080.00 group:wheel <GROUP@>
//  3: A 120080.00 everyone
//  4: A 1601e7.0b creator_owner
//  5: A 1200a1.0b creator_group
//  6: A 1200a0.0b everyone
// 
// *** EXAMPLE: CITI nfs4_setfacl format examples ***
//
// nfs4_setfacl A:OWNER@:rwaxDtTdcCy,A:501:rxtcy,A:GROUP@:gtcy,A:EVERYONE@:tcy,A:OWNER@:fdirwaxDtTdcCy,A:GROUP@:fdirxtcy,A:EVERYONE@:fdixtcy "acltest.d/acl_nontrivial_700d"
// nfs4_setfacl A:OWNER@:rwaxDtTdcCy,A:501:rxtcy,A:502:rxtcy,A:GROUP@:gtcy,A:EVERYONE@:tcy,A:OWNER@:fdirwaxDtTdcCy,A:GROUP@:fdirxtcy,A:EVERYONE@:fdixtcy "acltest.d/acl_nontrivial_700d+"
// nfs4_setfacl A:OWNER@:rwatTdcCy,D:500:rwaTC,D:501:rxTC,A:500:xtcy,A:501:watdcy,A:502:rtcy,A:503:rwaxtdcy,A:GROUP@:grtcy,A:EVERYONE@:rtcy "acltest.d/acl_test.1"
// nfs4_setfacl A:OWNER@:rwaxDtTdcCy,A:501:rxtcy,A:GROUP@:gtcy,A:EVERYONE@:tcy,A:OWNER@:fdirwaxDtTdcCy,A:GROUP@:fdirxtcy,A:EVERYONE@:fdixtcy "acltest.d/acl_test_d.1"
// nfs4_setfacl A:OWNER@:rwaxDtTdcCy,A:GROUP@:grxtcy,A:EVERYONE@:rxtcy,A:OWNER@:fdirwaxDtTdcCy,A:GROUP@:fdirxtcy,A:EVERYONE@:fdixtcy "acltest.d/acl_trivial_d_755+"
//
// *** EXAMPLE: CITI nfs4_getfacl format example ***
//
// TODO

char CurrentOWNER[128] = "?";
char CurrentGROUP[128] = "?";

// parse_commalist() - Copy string to list, counting words.  Return word count, and also return chars used into nch.

int
parse_commalist(char *list, char *string, int *nch)
{
   char *src, *dst, *p;
   int nwords = 0;
   int nchars = 0;

   *nch = 0;
   if (isspace(string[0])) return(0);
   strcpy(list, string);
   for (p=list; *p; p++) if (isspace(*p)) { *p = '\0'; break; }
   //printf("list=\"%s\"\n", list);
   if (strlen(list) < 1) return(0);
   nwords = 1;
   nchars = strlen(list);
   for (p=list; *p; p++) if (*p == ',') { nwords += 1; *p = '\0'; }
   *nch = nchars;
   return(nwords);
}

// CITI nfs4_getfacl ACE format syntax;
//
// <ace> := <ace_type>:<ace_flags>:<trustee>:<ace_mask>
// <ace_type> :== (per below)
// <ace_flags> :== (per below)
// <trustee> :== <name>|<uid>|<gid>|<sid>		NOTE: May have spaces, as in 'Domain Users'
//	<sid> :== S-[-0-9][-0-9]*
//	<name> :== <alphanumeric>|<fqdn>|OWNER@|GROUP@|EVERYONE@
//	<uid> :== %u
//	<gid> :== %u
// <ace_mask> :== (per below)
//
// # nfs4_getfacl -H
// nfs4_getfacl 0.3.3 -- get NFSv4 file or directory access control lists.
// 
// An NFSv4 ACL consists of one or more NFSv4 ACEs, each delimited by commas or whitespace.
// An NFSv4 ACE is written as a colon-delimited, 4-field string in the following format:
// 
//     <type>:<flags>:<principal>:<permissions>
// 
//     * <type> - one of:	// NOTE: we only concern outselves with A)llow and D)eny ACEs here
//         'A'  allow
//         'D'  deny
//         'U'  audit
//         'L'  alarm
// 
//     * <flags> - zero or more (depending on <type>) of:
//         'f'  file-inherit
//         'd'  directory-inherit
//         'p'  no-propagate-inherit
//         'i'  inherit-only
//         'S'  successful-access
//         'F'  failed-access
//         'g'  group (denotes that <principal> is a group)
//         'O'  inherited-ace	// NOTE: not documented in man page
// 
//     * <principal> - named user or group, or one of: "OWNER@", "GROUP@", "EVERYONE@"
// 
//     * <permissions> - one or more of:
//         'r'  read-data / list-directory 
//         'w'  write-data / create-file 
//         'a'  append-data / create-subdirectory 
//         'x'  execute 
//         'd'  delete
//         'D'  delete-child (directories only)
//         't'  read-attrs
//         'T'  write-attrs
//         'n'  read-named-attrs
//         'N'  write-named-attrs
//         'c'  read-ACL
//         'C'  write-ACL
//         'o'  write-owner
//         'y'  synchronize
// 
// For more information and examples, please refer to the nfs4_acl (5) manpage.

int
nfs4_getfacl_ace(char *line, int *n_ace)
{
   char ace_type, ace_trustee[256];
   unsigned ace_flags = 0, ace_mask = 0;
   char *p, *pp, letter;
   int nch;

   pp = line;		// parsing pointer within line

   // <ace_type> ...
   if (pp[1] != ':') return(0);				// Bail ...
   if (pp[0] != 'A' && pp[0] != 'D') return(0);		// Bail ... ignore non-allow/deny ACEs
   ace_type = pp[0]; pp += 2;

   // <ace_flags> ...
   if (index(pp, ':') == NULL) return(0);		// Bail ...
   while ((letter=*pp++) != ':') switch (letter) {
      case 'f': ace_flags |= ACE4_FILE_INHERIT_ACE; break;
      case 'd': ace_flags |= ACE4_DIRECTORY_INHERIT_ACE; break;
      case 'p': ace_flags |= ACE4_NO_PROPAGATE_INHERIT_ACE; break;
      case 'i': ace_flags |= ACE4_INHERIT_ONLY_ACE; break;
      case 'S': ace_flags |= ACE4_SUCCESSFUL_ACCESS_ACE_FLAG; break;
      case 'F': ace_flags |= ACE4_FAILED_ACCESS_ACE_FLAG; break;
      case 'g': ace_flags |= ACE4_IDENTIFIER_GROUP; break;
      case 'O': ace_flags |= ACE4_INHERITED_ACE; break;
      default: return(0);				// Bail ...
   }

   // <ace_trustee> (<principal>) ...
   if ((p = index(pp, ':')) == NULL) return(0);		// Bail ...
   strncpy(ace_trustee, pp, p - pp);
   ace_trustee[p-pp] = '\0';
   pp = p+1;

   // <ace_mask> (<permissions>) ...
   while ((letter=*pp++)) switch (letter) {
      case 'r': ace_mask |= ACE4_READ_DATA; break;		// read-data / list-directory
      case 'w': ace_mask |= ACE4_WRITE_DATA; break;		// write-data / create-file
      case 'a': ace_mask |= ACE4_APPEND_DATA; break;		// append-data / create-subdirectory
      case 'x': ace_mask |= ACE4_EXECUTE; break;		// execute
      case 'd': ace_mask |= ACE4_DELETE; break;			// delete
      case 'D': ace_mask |= ACE4_DELETE_CHILD; break;		// delete-child (directories only)
      case 't': ace_mask |= ACE4_READ_ATTRIBUTES; break;	// read-attrs
      case 'T': ace_mask |= ACE4_WRITE_ATTRIBUTES; break;	// write-attrs
      case 'n': ace_mask |= ACE4_READ_NAMED_ATTRS; break;	// read-named-attrs
      case 'N': ace_mask |= ACE4_WRITE_NAMED_ATTRS; break;	// write-named-attrs
      case 'c': ace_mask |= ACE4_READ_ACL; break;		// read-ACL
      case 'C': ace_mask |= ACE4_WRITE_ACL; break;		// write-ACL
      case 'o': ace_mask |= ACE4_WRITE_OWNER; break;		// write-owner
      case 'y': ace_mask |= ACE4_SYNCHRONIZE; break;		// synchronize
      // Compound values used by nfs4_setfacl ...
      case 'R': ace_mask |= ACE4_GENERIC_READ; break;
      case 'W': ace_mask |= ACE4_GENERIC_WRITE; break;
      case 'X': ace_mask |= ACE4_GENERIC_EXECUTE; break;
      case 'A': ace_mask |= ACE4_MASK_ALL; break;
      // Why wait for NUL byte at EOL?
      case '\r':
      case '\n': break;
      default: return(0);				// Bail ...
   }

   printf(" %d: %c %06x.%02x \"%s\"\n", *n_ace, ace_type, ace_mask, ace_flags, ace_trustee);
   *n_ace += 1;
   return(1);
}

int
onefs_ace(char *line)
{
   int i, n, w, n_ace, nwords, nch;
   char tokbuf[2048], *pp;
   char ace_type_c, *ace_type_s, *p_ace_type, *p_keywords;
   char trustee[256], *trustee_prefix, trustee_name[256], *p_trustee_note;
   int trustee_len;
   int ace_mask = 0, ace_flags = 0;

   // Parsing pointer moves through line ...
   pp = line;

   // There MUST be an initial SPACE and a numerical ACE index followed by ": " ...
   if (*pp++ != ' ') return(0);
   if (sscanf(pp, "%d: %n", &n_ace, &nch) < 1) return(0);	// No ACE index present ...
   pp += nch;
   if (DEBUG) printf("Got <n_ace> \"%d\"\n", n_ace);

   // There MUST be a " deny " or " allow " string present ...
   // (We check this first, because the trustee may have embedded whitespace!)
   if ((p_ace_type = strstr(pp, " allow ")) != NULL) {
      p_keywords = p_ace_type + 7;
      ace_type_s = "allow";
      ace_type_c = 'A';
   } else if ((p_ace_type = strstr(pp, " deny ")) != NULL) {
      p_keywords = p_ace_type + 6;
      ace_type_s = "deny";
      ace_type_c = 'D';
   } else {
      return(0);						// No deny or allow present ...
   }

   // We MUST find valid trustee syntax next (user:%s, group:%s, SID:%s, or reserved names) ...
   // ... but we will preserve any trustee values represented in '<>' brackets ...
   // ... and we know the trustee value MAY start with a trustee type prefix ...
   if (strncmp(pp, "user:", 5) == 0) {
      trustee_prefix = "user:";
   } else if (strncmp(pp, "group:", 6) == 0) {
      trustee_prefix = "group:";
   } else if (strncmp(pp, "SID:", 4) == 0) {
      trustee_prefix = "SID:";
   } else {
      trustee_prefix = "";
   }
   nch = strlen(trustee_prefix);
   strncpy(trustee_name, pp + nch, p_ace_type - (pp+nch));	// up to " allow " or " deny "
   trustee_name[p_ace_type - (pp+nch)] = '\0';
   if (DEBUG) printf("@@: \"%s\" \"%s\"\n", trustee_prefix, trustee_name);

   if (nch) {							// Named trustees ...
      p_trustee_note = "";
      // Add footnote for trustees matching the object's owning OWNER and GROUP ...
      if (trustee_name[0] != '<') {
         if (strcmp(trustee_prefix, "user:") == 0 && strcmp(trustee_name, CurrentOWNER) == 0) {
            p_trustee_note = " <OWNER@>";
         } else if (strcmp(trustee_prefix, "group:") == 0 && strcmp(trustee_name, CurrentGROUP) == 0) {
            p_trustee_note = " <GROUP@>";
         } else if (strcmp(trustee_prefix, "SID:") == 0) {
            if (strcmp(trustee_name, CurrentOWNER) == 0) {
               p_trustee_note = " <OWNER@>";
            }
            if (strcmp(trustee_name, CurrentGROUP) == 0) {
               p_trustee_note = " <GROUP@>";
               ace_flags |= ACE4_IDENTIFIER_GROUP;	// By inference
            }
         }
      }
      sprintf(trustee, "%s%s%s", trustee_prefix, trustee_name, p_trustee_note);
   } else if (strncmp(pp, "everyone ", 9) == 0) {		// Special trustee identities ...
      strcpy(trustee, "everyone");
   } else if (strncmp(pp, "creator_owner ", 14) == 0) {
      strcpy(trustee, "creator_owner");
   } else if (strncmp(pp, "creator_group ", 14) == 0) {
      strcpy(trustee, "creator_group");
   } else if (strncmp(pp, "owner_rights ", 13) == 0) {
      strcpy(trustee, "owner_rights");
   } else {
      return(0);						// No trustee value recognized ...
   }

   // Convert well-known SIDs back to reserved names ...
   if (strcmp("SID:S-1-1-0", trustee) == 0) strcpy(trustee, "everyone");
   else if (strcmp("SID:S-1-3-0", trustee) == 0) strcpy(trustee, "creator_owner");
   else if (strcmp("SID:S-1-3-1", trustee) == 0) strcpy(trustee, "creator_group");
   else if (strcmp("SID:S-1-3-4", trustee) == 0) strcpy(trustee, "owner_rights");

   // OK, now we know all about the trustee value, period;
   if (DEBUG) printf("Got <trustee> \"%s\"\n", trustee);

   // Now we can parse the keywords that follow " allow " or " deny " ...
   pp = p_keywords;

   // First though, gobble up the 'inherited' keyword that may appear before the comma-delimited list ...
   // This keyword is redundant w/ 'inherited_ace', but we infer the ACE4_INHERITED_ACE flag here nevertheless.
   if (strncmp(pp, "inherited ", 10) == 0) {
      pp += 10;
      ace_flags |= ACE4_INHERITED_ACE;
      if (DEBUG) printf("Gobbled up 'inherited '\n");
   }

   // Aggregate all BSD words into ace_mask and ace_flags values ...
   nwords = parse_commalist(tokbuf, pp, &nch);
   pp = tokbuf;
   for (i=0; i<nwords; i++) {
      for (w=0; onefs_keyword_mask[w].word; w++) {
         if (strcmp(pp, onefs_keyword_mask[w].word) == 0) {
             if (onefs_keyword_mask[w].flags) ace_flags |= onefs_keyword_mask[w].mask;
             else                ace_mask |= onefs_keyword_mask[w].mask;
             break;
         }
      }
      if (onefs_keyword_mask[w].word == NULL) printf("Unknown keyword: \"%s\"\n", pp);
      pp += strlen(pp) + 1;
   }

   // Our output ordering is 'N: <type> <CHEX> <trustee>' ...
   printf(" %d: %c %06x.%02x %s\n", n_ace, ace_type_c, ace_mask, ace_flags, trustee);
   return(1);
}

void
usage()
{
   printf("Usage: hacls [-ogc] < <bsd_formatted_acls>|<nfs4_formatted_acls>\n");
   printf("  Where:   -ogc -> suppress output of OWNER:, GROUP:, and CONTROL: lines\n");
   exit(-1);
}

int
main(int argc, char *argv[])
{
   char line[2048], *p;
   int show_ogc = 1;
   int i, n_ace = 0;

   for (i=1; i<argc; i++) {
      if (strcmp(argv[i], "-ogc") == 0) {
         show_ogc = 0;
      } else {
         usage();
      }
   }

   while (fgets(line, sizeof(line), stdin)) {
      // Normalize line to eliminate newline or crlf ...
      if ((p=index(line, '\r')) || (p=index(line, '\n'))) *p = '\0';
      if (DEBUG) printf("@ %s\n", line); fflush(stdout);
      // Imperfect logic here, but intent is to skim owner and group values from input stream ...
      if (sscanf(line, " OWNER: user:%s", CurrentOWNER) ||
          sscanf(line, " GROUP: group:%s", CurrentGROUP) ||
          sscanf(line, " OWNER: SID:%s", CurrentOWNER) ||
          sscanf(line, " GROUP: SID:%s", CurrentGROUP))
      {
         if (!show_ogc) continue;
      }
      if (!show_ogc && strncmp(line, " CONTROL:", 8) == 0) continue;
      if (!onefs_ace(line) && !nfs4_getfacl_ace(line, &n_ace)) {
         fputs(line, stdout); fputc('\n', stdout);
         n_ace = 0;
      }
   }
}
