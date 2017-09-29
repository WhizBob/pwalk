#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BOOLMASK(m) mask = m; a = (f1&mask != 0); b=(f2&mask != 0); p=((a|b) != 0);
// CMP_S formats compare substring (0|1 0|1 ) for two-argument invocations ..
#define CMP_S if (argc == 3) sprintf(cmp_s, "%d %d ", a, b);
// MBG means 'Matched By Generic'...
// MBG_MASK accumulates in mbg_mask all bits that were matched by a generic R|W|X masks
#define MBG_MASK if (p) mbg_mask |= mask;
// MBG_C sets mbg_c to '*' when corresponding bit set in mbg_mask, else SPACE
#define MBG_C mbg_c = (p && ((mask&mbg_mask)==mask)) ? '*' : ' ';

void
usage(void)
{
   printf("Usage: chexcmp <CHEX val 1> [<CHEX val 2>]\n");
   printf("  Where: A CHEX value is a hexadecimal 'mask' or 'mask.flags' value\n");
   printf("         When one argument is passed, it is simply decomposed.\n");
   printf("         When two arguments are passed, they are bitwise compared.\n");
   printf("         All mask and flag values use RFC 7530 ACE4_* definitions.\n");
   exit(-1);
}

int
main(int argc, char *argv[])
{
   unsigned m1, m2, f1, f2, mask, mbg_mask;
   char mbg_c, cmp_s[16];
   int a, b, p;

   m1 = f1 = m2 = f2 = 0;
   if (argc < 2 || argc > 3) usage();
   if (sscanf(argv[1], "%x.%x", &m1, &f1) != 2)
      if (sscanf(argv[1], "%x", &m1) != 1)
         usage();
   if (argc != 3) goto begin;
   if (sscanf(argv[2], "%x.%x", &m2, &f2) != 2)
      if (sscanf(argv[2], "%x", &m2) != 1)
         usage();

begin:
   // Initial/default values ...
   cmp_s[0] = '\0';
   mbg_mask = 0;
   mbg_c = ' ';

   printf("-- Permissions --\n");
   // Compound ...
   mask = 0x120081; a=((m1&mask)==mask); b=((m2&mask)==mask); p=((a|b) != 0); CMP_S; MBG_MASK;
   if (p) printf("%s%06x *%s\n", cmp_s, mask,
      "GENERIC_READ                    'R' - generic read");
   mask = 0x160106; a=((m1&mask)==mask); b=((m2&mask)==mask); p=((a|b) != 0); CMP_S; MBG_MASK;
   if (p) printf("%s%06x *%s\n", cmp_s, mask,
      "GENERIC_WRITE                   'W' - generic write");
   mask = 0x1200A0; a=((m1&mask)==mask); b=((m2&mask)==mask); p=((a|b) != 0); CMP_S; MBG_MASK;
   if (p) printf("%s%06x *%s\n", cmp_s, mask,
      "GENERIC_EXECUTE                 'X' - generic execute");
   mask = 0x1F01FF; a=((m1&mask)==mask); b=((m2&mask)==mask); p=((a|b) != 0); CMP_S; MBG_MASK;
   if (p) printf("%s%06x  %s\n", cmp_s, mask,
      "MASK_ALL                        'A' - mask all");
   // Atomic ...
   mask=0x000001; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "READ_DATA / LIST_DIRECTORY      'r' - can (r)ead file data -or- list directory");
   mask=0x000002; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "WRITE_DATA / ADD_FILE           'w' - can (w)rite the file's data -or- create file in directory");
   mask=0x000004; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "APPEND_DATA / ADD_SUBDIRECTORY  'a' - can (a)ppend file data -or- create subdirectory");
   mask=0x000008; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "READ_NAMED_ATTRS                'n' - can read (n)AMED attr of file or directory");
   mask=0x000010; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "WRITE_NAMED_ATTRS               'N' - can write (N)amed attr of file or directory");
   mask=0x000020; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "EXECUTE                         'x' - can e(x)ecute file -or- traverse directory");
   mask=0x000040; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "DELETE_CHILD                    'D' - can (D)elete file or directory within a directory");
   mask=0x000080; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "READ_ATTRIBUTES                 't' - can read basic A(t)TRIBUTES (non-ACLs) of a file");
   mask=0x000100; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "WRITE_ATTRIBUTES                'T' - can write basic a(T)tributes (non-ACLs) of a file");
   mask=0x010000; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "DELETE                          'd' - can (d)elete file -or- rmdir directory");
   mask=0x020000; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "READ_ACL                        'c' - can read A(c)L");
   mask=0x040000; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "WRITE_ACL                       'C' - can write A(C)L");
   mask=0x080000; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "WRITE_OWNER                     'o' - can write (o)wner and owner_group attributes");
   mask=0x100000; a=((m1&mask) != 0); b=((m2&mask) != 0); p=((a|b) != 0); CMP_S; MBG_C;
   if (p) printf("%s%06x %c%s\n", cmp_s, mask, mbg_c,
      "SYNCHRONIZE                     'y' - can use object as s(y)nchronization primitive for IPC");

   if ((f1|f2) == 0) goto fini;
   printf("-- Flags --\n");
   mask = 0x000001; a = ((f1&mask) != 0); b=((f2&mask) != 0); p=((a|b) != 0); CMP_S;
   if (p) printf("%s%06x  %s\n", cmp_s, mask,
      "FILE_INHERIT_ACE                'f' - propagate ACE to (f)iles in directory");
   mask = 0x000002; a = ((f1&mask) != 0); b=((f2&mask) != 0); p=((a|b) != 0); CMP_S;
   if (p) printf("%s%06x  %s\n", cmp_s, mask,
      "DIRECTORY_INHERIT_ACE           'd' - propagate ACE to sub(d)irectorys in directory");
   mask = 0x000004; a = ((f1&mask) != 0); b=((f2&mask) != 0); p=((a|b) != 0); CMP_S;
   if (p) printf("%s%06x  %s\n", cmp_s, mask,
      "NO_PROPAGATE_INHERIT_ACE        'n' - do (n)ot propagate inheritance ACE (inherit ONCE)");
   mask = 0x000008; a = ((f1&mask) != 0); b=((f2&mask) != 0); p=((a|b) != 0); CMP_S;
   if (p) printf("%s%06x  %s\n", cmp_s, mask,
      "INHERIT_ONLY_ACE                'i' - (i)nherit ony ACE; do not evaluate during access");
   mask = 0x000010; a = ((f1&mask) != 0); b=((f2&mask) != 0); p=((a|b) != 0); CMP_S;
   if (p) printf("%s%06x  %s\n", cmp_s, mask,
      "SUCCESSFUL_ACCESS_ACE_FLAG      'S' - trigger alarm/audit when permission (S)ucceeds");
   mask = 0x000020; a = ((f1&mask) != 0); b=((f2&mask) != 0); p=((a|b) != 0); CMP_S;
   if (p) printf("%s%06x  %s\n", cmp_s, mask,
      "FAILED_ACCESS_ACE_FLAG          'F' - trigger alarm/audit when permission (F)ails");
   mask = 0x000040; a = ((f1&mask) != 0); b=((f2&mask) != 0); p=((a|b) != 0); CMP_S;
   if (p) printf("%s%06x  %s\n", cmp_s, mask,
      "IDENTIFIER_GROUP                'g' - trustee specifies a (g)ROUP");
   mask = 0x000080; a = ((f1&mask) != 0); b=((f2&mask) != 0); p=((a|b) != 0); CMP_S;
   if (p) printf("%s%06x  %s\n", cmp_s, mask,
      "INHERITED_ACE                   '-' - inherited ace (no CITI letter)");

fini:
   exit(0);
}
