#include <stdio.h>
#include <sys/isi_acl.h>
#include "pwalk_acls.h"

// Natively on OneFS, produce map of OneFS native permission values ...
struct {
   char *sym_name;
   enum ifs_ace_rights mask;
   char *str_name;
} Masks[] = {
   {"IFS_RTS_GENERIC_MASK ..........", IFS_RTS_GENERIC_MASK, "generic_mask"},
   {"IFS_RTS_GENERIC_ALL", IFS_RTS_GENERIC_ALL, "generic_all"},
   {"IFS_RTS_GENERIC_EXECUTE", IFS_RTS_GENERIC_EXECUTE, "generic_execute"},
   {"IFS_RTS_GENERIC_WRITE", IFS_RTS_GENERIC_WRITE, "generic_write"},
   {"IFS_RTS_GENERIC_READ", IFS_RTS_GENERIC_READ, "generic_read"},
   {"IFS_RTS_STD_MASK ..............", IFS_RTS_STD_MASK, "std_mask"},
   {"IFS_RTS_STD_DELETE", IFS_RTS_STD_DELETE, "std_delete"},
   {"IFS_RTS_STD_READ_CONTROL", IFS_RTS_STD_READ_CONTROL, "std_read_control"},
   {"IFS_RTS_STD_WRITE_DAC", IFS_RTS_STD_WRITE_DAC, "std_write_dac"},
   {"IFS_RTS_STD_WRITE_OWNER", IFS_RTS_STD_WRITE_OWNER, "std_write_owner"},
   {"IFS_RTS_STD_SYNCHRONIZE", IFS_RTS_STD_SYNCHRONIZE, "std_synchronize"},
   {"IFS_RTS_STD_REQUIRED", IFS_RTS_STD_REQUIRED, "std_required"},
   {"IFS_RTS_STD_ALL", IFS_RTS_STD_ALL, "std_all"},
   {"IFS_RTS_STD_EXECUTE", IFS_RTS_STD_EXECUTE, "std_execute"},
   {"IFS_RTS_STD_READ", IFS_RTS_STD_READ, "std_read"},
   {"IFS_RTS_STD_WRITE", IFS_RTS_STD_WRITE, "std_write"},
   {"IFS_RTS_SPECIFIC_MASK .........", IFS_RTS_SPECIFIC_MASK, "specific_mask"},
   {"IFS_RTS_FILE_READ_DATA", IFS_RTS_FILE_READ_DATA, "file_read_data"},
   {"IFS_RTS_FILE_WRITE_DATA", IFS_RTS_FILE_WRITE_DATA, "file_write_data"},
   {"IFS_RTS_FILE_APPEND_DATA", IFS_RTS_FILE_APPEND_DATA, "file_append_data"},
   {"IFS_RTS_FILE_READ_EA", IFS_RTS_FILE_READ_EA, "file_read_ea"},
   {"IFS_RTS_FILE_WRITE_EA", IFS_RTS_FILE_WRITE_EA, "file_write_ea"},
   {"IFS_RTS_FILE_EXECUTE", IFS_RTS_FILE_EXECUTE, "file_execute"},
   {"IFS_RTS_FILE_UNKNOWN_DIR_ALIAS", IFS_RTS_FILE_UNKNOWN_DIR_ALIAS, "file_unknown_dir_alias"},
   {"IFS_RTS_FILE_READ_ATTRIBUTES", IFS_RTS_FILE_READ_ATTRIBUTES, "file_read_attributes"},
   {"IFS_RTS_FILE_WRITE_ATTRIBUTES", IFS_RTS_FILE_WRITE_ATTRIBUTES, "file_write_attributes"},
   {"IFS_RTS_FILE_ALL", IFS_RTS_FILE_ALL, "file_all"},
   {"IFS_RTS_DIR_LIST", IFS_RTS_DIR_LIST, "dir_list"},
   {"IFS_RTS_DIR_ADD_FILE", IFS_RTS_DIR_ADD_FILE, "dir_add_file"},
   {"IFS_RTS_DIR_ADD_SUBDIR", IFS_RTS_DIR_ADD_SUBDIR, "dir_add_subdir"},
   {"IFS_RTS_DIR_READ_EA", IFS_RTS_DIR_READ_EA, "dir_read_ea"},
   {"IFS_RTS_DIR_WRITE_EA", IFS_RTS_DIR_WRITE_EA, "dir_write_ea"},
   {"IFS_RTS_DIR_TRAVERSE", IFS_RTS_DIR_TRAVERSE, "dir_traverse"},
   {"IFS_RTS_DIR_DELETE_CHILD", IFS_RTS_DIR_DELETE_CHILD, "dir_delete_child"},
   {"IFS_RTS_DIR_READ_ATTRIBUTES", IFS_RTS_DIR_READ_ATTRIBUTES, "dir_read_attributes"},
   {"IFS_RTS_DIR_WRITE_ATTRIBUTES", IFS_RTS_DIR_WRITE_ATTRIBUTES, "dir_write_attributeS"},
   {"IFS_RTS_DIR_ALL", IFS_RTS_DIR_ALL, "dir_all"},
   {"IFS_RTS_FILE_GEN_READ", IFS_RTS_FILE_GEN_READ, "file_gen_read"},
   {"IFS_RTS_DIR_GEN_READ", IFS_RTS_DIR_GEN_READ, "dir_gen_read"},
   {"IFS_RTS_FILE_GEN_WRITE", IFS_RTS_FILE_GEN_WRITE, "file_gen_write"},
   {"IFS_RTS_DIR_GEN_WRITE", IFS_RTS_DIR_GEN_WRITE, "dir_gen_write"},
   {"IFS_RTS_FILE_GEN_EXECUTE", IFS_RTS_FILE_GEN_EXECUTE, "file_gen_execute"},
   {"IFS_RTS_DIR_GEN_EXECUTE", IFS_RTS_DIR_GEN_EXECUTE, "dir_gen_execute"},
   {"IFS_RTS_FILE_GEN_ALL", IFS_RTS_FILE_GEN_ALL, "file_gen_all"},
   {"IFS_RTS_DIR_GEN_ALL", IFS_RTS_DIR_GEN_ALL, "dir_gen_all"},
   {"IFS_RTS_FULL_CONTROL", IFS_RTS_FULL_CONTROL, "full_control"},
   {"IFS_RTS_SACL_ACCESS", IFS_RTS_SACL_ACCESS, "sacl_access"},
   {"IFS_RTS_MAXIMUM_ALLOWED", IFS_RTS_MAXIMUM_ALLOWED, "maximum_allowed"},
   {NULL, 0, NULL}
};

// Map of OneFS permissions keywaords extracted from msys/kern/isi_acl_util.c ...

/* encapsulates ace_right to name conversions */
static struct {
	// enum ifs_ace_rights mask;
	unsigned mask;
	const char *keyword;
	enum ifs_ace_rights_type type;;
} ace_rights[] = {
	/* Right to read or write the SACL */
	{IFS_RTS_SACL_ACCESS,		"read_write_sacl",	IFS_RTS_GENERIC_TYPE},

	/* Generic */
	{IFS_RTS_GENERIC_ALL,		"generic_all",		IFS_RTS_GENERIC_TYPE},
	{IFS_RTS_GENERIC_EXECUTE,	"generic_exec",		IFS_RTS_GENERIC_TYPE},
	{IFS_RTS_GENERIC_WRITE,		"generic_write",	IFS_RTS_GENERIC_TYPE},
	{IFS_RTS_GENERIC_READ,		"generic_read",		IFS_RTS_GENERIC_TYPE},

	/* Standard */
	{IFS_RTS_STD_REQUIRED,		"std_required",		IFS_RTS_GENERIC_TYPE},
	{IFS_RTS_STD_DELETE,		"std_delete",		IFS_RTS_GENERIC_TYPE},
	{IFS_RTS_STD_READ_CONTROL,	"std_read_dac",		IFS_RTS_GENERIC_TYPE},
	{IFS_RTS_STD_WRITE_DAC,		"std_write_dac",	IFS_RTS_GENERIC_TYPE},
	{IFS_RTS_STD_WRITE_OWNER,	"std_write_owner",	IFS_RTS_GENERIC_TYPE},
	{IFS_RTS_STD_SYNCHRONIZE,	"std_synchronize",	IFS_RTS_GENERIC_TYPE},

	/* Filesystem specific */
	{IFS_RTS_FILE_READ_DATA,	"file_read",		IFS_RTS_FILE_TYPE},
	{IFS_RTS_FILE_WRITE_DATA,	"file_write",		IFS_RTS_FILE_TYPE},
	{IFS_RTS_FILE_APPEND_DATA,	"append",		IFS_RTS_FILE_TYPE},
	{IFS_RTS_FILE_READ_EA,		"file_read_ext_attr",	IFS_RTS_FILE_TYPE},
	{IFS_RTS_FILE_WRITE_EA,		"file_write_ext_attr",	IFS_RTS_FILE_TYPE},
	{IFS_RTS_FILE_EXECUTE,		"execute",		IFS_RTS_FILE_TYPE},
	{IFS_RTS_FILE_UNKNOWN_DIR_ALIAS,"delete_child",		IFS_RTS_FILE_TYPE},
	{IFS_RTS_FILE_READ_ATTRIBUTES,	"file_read_attr",	IFS_RTS_FILE_TYPE},
	{IFS_RTS_FILE_WRITE_ATTRIBUTES,	"file_write_attr",	IFS_RTS_FILE_TYPE},

	{IFS_RTS_DIR_LIST,		"list",			IFS_RTS_DIR_TYPE},
	{IFS_RTS_DIR_ADD_FILE,		"add_file",		IFS_RTS_DIR_TYPE},
	{IFS_RTS_DIR_ADD_SUBDIR,	"add_subdir",		IFS_RTS_DIR_TYPE},
	{IFS_RTS_DIR_READ_EA,		"dir_read_ext_attr",	IFS_RTS_DIR_TYPE},
	{IFS_RTS_DIR_WRITE_EA,		"dir_write_ext_attr",	IFS_RTS_DIR_TYPE},
	{IFS_RTS_DIR_TRAVERSE,		"traverse",		IFS_RTS_DIR_TYPE},
	{IFS_RTS_DIR_DELETE_CHILD,	"delete_child",		IFS_RTS_DIR_TYPE},
	{IFS_RTS_DIR_READ_ATTRIBUTES,	"dir_read_attr",	IFS_RTS_DIR_TYPE},
	{IFS_RTS_DIR_WRITE_ATTRIBUTES,	"dir_write_attr",	IFS_RTS_DIR_TYPE},

	/* Typical Settings */
	{IFS_RTS_FILE_GEN_ALL,          "file_gen_all",		IFS_RTS_FILE_TYPE},
	{IFS_RTS_DIR_GEN_ALL,           "dir_gen_all",		IFS_RTS_DIR_TYPE},
	{IFS_RTS_FILE_GEN_READ,         "file_gen_read",	IFS_RTS_FILE_TYPE},
	{IFS_RTS_DIR_GEN_READ,          "dir_gen_read",		IFS_RTS_DIR_TYPE},
	{IFS_RTS_FILE_GEN_WRITE,        "file_gen_write",	IFS_RTS_FILE_TYPE},
	{IFS_RTS_DIR_GEN_WRITE,         "dir_gen_write",	IFS_RTS_DIR_TYPE},
	{IFS_RTS_FILE_GEN_EXECUTE,      "file_gen_execute",	IFS_RTS_FILE_TYPE},
	{IFS_RTS_DIR_GEN_EXECUTE,       "dir_gen_execute",	IFS_RTS_DIR_TYPE},
	{IFS_RTS_MODIFYING,             "modify",		IFS_RTS_GENERIC_TYPE},

	/* EXTRA: Force-fitting the ACE4 FLAG values into this table ... */
	/* NOTE: extrapolating the TYPE column here for file/dir distinction */
        {ACE4_FILE_INHERIT_ACE,		"object_inherit",	IFS_RTS_DIR_TYPE},
        {ACE4_DIRECTORY_INHERIT_ACE,	"container_inherit",	IFS_RTS_DIR_TYPE},
        {ACE4_NO_PROPAGATE_INHERIT_ACE, "no_prop_inherit",	IFS_RTS_DIR_TYPE},
        {ACE4_INHERIT_ONLY_ACE,		"inherit_only",		IFS_RTS_DIR_TYPE},
        {ACE4_INHERITED_ACE,		"inherited_ace",	IFS_RTS_FILE_TYPE},
	{0, NULL, 0}
};

int
is_flagword(const char *word)
{
   if (strcmp(word, "object_inherit") == 0) return(1);
   if (strcmp(word, "container_inherit") == 0) return(1);
   if (strcmp(word, "no_prop_inherit") == 0) return(1);
   if (strcmp(word, "inherit_only") == 0) return(1);
   if (strcmp(word, "inherited_ace") == 0) return(1);
   return(0);
}

int
main(int argc, char *argv)
{
   int i;
   struct fmt fmt = FMT_INITIALIZER;

   // Generate C comments for native OneFS mask values ...
   printf("\n");
   printf("// REFERENCE: Map of OneFS internal permissions ...\n");
   for (i=0; Masks[i].sym_name; i++)
      printf("// %-32s 0x%08X %s\n", Masks[i].sym_name, Masks[i].mask, Masks[i].str_name);
   printf("\n");

   // Generate C code with NFS4 permission keyword mapping to hex ...
   printf("#ifndef PWALK_ACLS_SOURCE               // Suppress conflicting extern decls\n");
   printf("struct {\n");
   printf("#else\n");
   printf("static struct {\n");
   printf("#endif\n");
   printf("   int mask;                           // ACE4 permissions mask value\n");
   printf("   char *word;\n");
   printf("   short isdir;                        // non-zero if word applies to directories\n");
   printf("   short flags;                        // non-zero if word applies to flags instead of mask\n");
   printf("} onefs_keyword_mask[] = {\n");
   for (i=0; ace_rights[i].mask; i++) {
      printf("   {0x%08X, \"%s\", %d, %d},\n",
              ace_rights[i].mask, ace_rights[i].keyword,
              (ace_rights[i].type == IFS_RTS_DIR_TYPE) ? 1 : 0,
              is_flagword(ace_rights[i].keyword) ? 1 : 0
            );
   }
   printf ("   {0, NULL, 0, 0}\n");
   printf ("};\n");

#ifdef NEVER
   // Experimenting with OneFS 'fmt' functions ...
   fmt_print(&fmt, "%b\n", -1, IFS_ACE_FLAGS_BITS_DESCRIPTION);
   printf("%s", fmt_string(&fmt));
#endif
}
