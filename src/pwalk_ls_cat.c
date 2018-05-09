// pwalk_ls_cat.c - a simple command-line filter for post-processing pwalk -ls-special outputs.
//
// stdin input lines are pwalk -ls-special format.  Each input line starts with one of the
// follwing two-character sequences;
//	"@ " - absolute directory path for following files
//	"[-lspbc] " - file type letter (symlink, pipe, block-special, char-special, etc)
//	"*S" - per-directory subtotals
// stdout output lines are absolute pathnames to files.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TRUE 1
#define FALSE 0
#define NUL '\0'
#define PATHSEPCHR '/'

void
abend(char *msg)
{
   fprintf(stderr, "FATAL: %s\n", msg);
   exit(-1);
}

int
main(int argc, char **argv)
{
   char line[4096];
   char directory[4096] = "", *filename = NULL;
   int len;

   if (argc > 1) abend("No arguments allowed!");

   filename = line + 2;
   while (fgets(line, sizeof(line), stdin)) {
      len = strlen(line);
      if ((len > 0) && (line[len-1] == '\n'))
         line[--len] = NUL;
      if (line[0] == '@' && line[1] == ' ') {		// directory
         strcpy(directory, filename);
         printf("%s\n", directory);
      } else if (line[0] == '*' && line[1] == 'S') {	// subtotal
         continue;
      } else if (len < 3) {
         abend("Ill-formed input!");
      } else {						// filename (assumed)
         if (!directory[0]) abend("Ill-formed input! No directory!\n");
         printf("%s%c%s\n", directory, PATHSEPCHR, filename);
      }
   }
   exit(0);
}
