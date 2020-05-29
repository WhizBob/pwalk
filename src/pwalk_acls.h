#ifndef INCLUDED_PWALK_ACLS_H
#define INCLUDED_PWALK_ACLS_H 1

// *** COMMON data types for pwalk_acls.c and its consumers ***
// We use a fixed-max-size ACL4 definition here, to avoid the potential for memory leaks from constant
// thrashing of malloc()'d memory with dynamically-sized ACL4 allocations.  FWIW, the fixed size of an
// acl4_t with (PW_ACL_MAX_ACE4 == 64) is (4 + 64*(3*4 + 16)), which is 1796 bytes; not trivial, but
// for our intended usage, only one acl4_t will be allocated per pwalk thread.
//
// For reference, the ace4_t very closely resembles the standard nfsace4 structure (annotated);
//
//	struct nfsace4 {
//		acetype4          type;		// [ADUL]
//		eflag4            flag;		// [gdfinSF]
//		acemask4          access_mask;	// [rwadDxocCnNtTy]
//		utf8str_mixed     who;		// Grantee (UID/GID)
//	};


#define PW_ACL_MAX_ACE4 64              // Arbitrary fixed limit
typedef struct {                        // (Mirrors standard nfsace4 struct, but with a fixed ASCII 'who')
   unsigned short type;			// [ADUL]
   unsigned short flags;		// [gdfinSF]
   int mask;                            // [rwadDxocCnNtTy]
   char who[16];                        // Grantee (UID/GID/OWNER@/GROUP@/EVERYONE@)
} ace4_t;
typedef struct {			// ACE count, plus room for PW_ACL_MAX_ACE4 ACEs
   int n_aces;
   ace4_t ace4[PW_ACL_MAX_ACE4];
} acl4_t;

// *** EXPORTED data elements from pwalk_acls.c ***
#ifndef PWALK_ACLS_SOURCE		// Suppress conflicting extern decls
int pw_acls_DEBUGin = 0;
int pw_acls_DEBUGout = 0;
int pw_acls_SHOW_POSIX = 0;
#else
extern int pw_acls_DEBUGin;
extern int pw_acls_DEBUGout;
extern int pw_acls_SHOW_POSIX;
#endif

typedef struct stat stat_t;

// *** FORWARD declarations for pwalk_acls.c functions ***
void pw_acl4_fprintf_nfs4_setfacl(acl4_t *acl4p, const char *path, FILE *stream);
void pw_acl4_fprintf_chex(acl4_t *acl4p, const char *path, stat_t *sb_p, FILE *stream);
void pw_acl4_fprintf_onefs(acl4_t *acl4p, const char *path, stat_t *sb_p, int chmod, FILE *stream);
void pw_acl4_canonicalize(acl4_t *acl4);
int pw_acl4_fwrite_binary(acl4_t *acl4, const char *path, FILE **pwOutFILE, char bmode, char *emsg_p, int *err_p);
int pw_acl4_get_from_posix_acls(const char *abspath, const int dir_flag, int *aclstat, acl4_t *acl4p, char *emsg_p, int *err_p);

// *** NORMALIZE to RFC 7530 ACE4_* symbols (vice Linux NFS4_ACE symbols) ***
#if !defined(ACE4_READ_DATA)
// <acetype4> values ...
#define ACE4_ACCESS_ALLOWED_ACE_TYPE      0x00000000	// 'A' - Allow
#define ACE4_ACCESS_DENIED_ACE_TYPE       0x00000001	// 'D' - Deny
#define ACE4_SYSTEM_AUDIT_ACE_TYPE        0x00000002	// 'U' - aUdit
#define ACE4_SYSTEM_ALARM_ACE_TYPE        0x00000003	// 'L' - aLarm
// <aceflag4> values ...
#define ACE4_FILE_INHERIT_ACE             0x00000001	// 'f' - propagate ACE to file in directory
#define ACE4_DIRECTORY_INHERIT_ACE        0x00000002	// 'd' - propagate ACE to subdirectory
#define ACE4_NO_PROPAGATE_INHERIT_ACE     0x00000004	// 'n' - do not propagate inheritance
#define ACE4_INHERIT_ONLY_ACE             0x00000008	// 'i' - only inherit ACE; do not evaluate during access
#define ACE4_SUCCESSFUL_ACCESS_ACE_FLAG   0x00000010	// 'S' - trigger alarm/audit when permission Succeeds
#define ACE4_FAILED_ACCESS_ACE_FLAG       0x00000020	// 'F' - trigger alarm/audit when permission Fails
#define ACE4_IDENTIFIER_GROUP             0x00000040	// 'g' - 'who' specifies a gROUP
#define ACE4_INHERITED_ACE                0x00000080	// 'O' - NOTE: this letter usage is undocumented
// <acemask4> permission values ...
#define ACE4_READ_DATA                    0x00000001	// 'r' - can (r)ead the data of the file
#define ACE4_LIST_DIRECTORY               0x00000001	// 'r' - can (r)ead the contents of the directory (not just traverse)
#define ACE4_WRITE_DATA                   0x00000002	// 'w' - can (w)rite the file's data
#define ACE4_ADD_FILE                     0x00000002	// 'w' - can create ((w)rite) a new file in the directory
#define ACE4_APPEND_DATA                  0x00000004	// 'a' - can (a)ppend data (write starting at EOF)
#define ACE4_ADD_SUBDIRECTORY             0x00000004	// 'a' - can (a)dd a subdirectory
#define ACE4_READ_NAMED_ATTRS             0x00000008	// 'n' - can read (n)AMED attr of file or lookup named attrs directory
#define ACE4_WRITE_NAMED_ATTRS            0x00000010	// 'N' - can write (N)amed attr of file or create named attrs directory
#define ACE4_EXECUTE                      0x00000020	// 'x' - can e(x)ecute file or traverse/search directory
#define ACE4_DELETE_CHILD                 0x00000040	// 'D' - can (D)elete file or directory within a directory
#define ACE4_READ_ATTRIBUTES              0x00000080	// 't' - can read basic A(t)TRIBUTES (non-ACLs) of a file
#define ACE4_WRITE_ATTRIBUTES             0x00000100	// 'T' - can write basic a(T)tributes (non-ACLs) of a file
#define ACE4_DELETE                       0x00010000	// 'd' - can (d)elete file or directory
#define ACE4_READ_ACL                     0x00020000	// 'c' - can read A(c)L
#define ACE4_WRITE_ACL                    0x00040000	// 'C' - can write A(C)L
#define ACE4_WRITE_OWNER                  0x00080000	// 'o' - can write (o)wner and owner_group attributes
#define ACE4_SYNCHRONIZE                  0x00100000	// 'y' - can use object as s(y)nchronization primitive for IPC
// <acemask4> compound values ...
#define ACE4_GENERIC_READ                 0x00120081	// 'R' - 
#define ACE4_GENERIC_WRITE                0x00160106	// 'W' - 
#define ACE4_GENERIC_EXECUTE              0x001200A0	// 'X' - 
#define ACE4_MASK_ALL                     0x001F01FF	// 'A' - 
// OneFS compound words expressed as NFS4 bitmasks ...
#define ONEFS_std_required		0x0F0000
#define ONEFS_generic_all		0x1001BF
#define ONEFS_generic_read		0x100089
#define ONEFS_generic_write		0x100116
#define ONEFS_generic_exec		0x100040
#define ONEFS_dir_gen_all		0x1F01FF
#define ONEFS_dir_gen_read		0x120089
#define ONEFS_dir_gen_write		0x120116
#define ONEFS_dir_gen_execute		0x120020
#define ONEFS_file_gen_all		0x1F01FF
#define ONEFS_file_gen_read		0x120089
#define ONEFS_file_gen_write		0x120016
#define ONEFS_file_gen_execute		0x120020
#define ONEFS_modify			0x0D0156
#endif

// Machine-generated OneFS keywords (see pwalk_acls_h_generate.c) ...

// REFERENCE: Map of OneFS internal permissions ...
// IFS_RTS_GENERIC_MASK ..........  0xF0000000 generic_mask
// IFS_RTS_GENERIC_ALL              0x10000000 generic_all
// IFS_RTS_GENERIC_EXECUTE          0x20000000 generic_execute
// IFS_RTS_GENERIC_WRITE            0x40000000 generic_write
// IFS_RTS_GENERIC_READ             0x80000000 generic_read
// IFS_RTS_STD_MASK ..............  0x00FF0000 std_mask
// IFS_RTS_STD_DELETE               0x00010000 std_delete
// IFS_RTS_STD_READ_CONTROL         0x00020000 std_read_control
// IFS_RTS_STD_WRITE_DAC            0x00040000 std_write_dac
// IFS_RTS_STD_WRITE_OWNER          0x00080000 std_write_owner
// IFS_RTS_STD_SYNCHRONIZE          0x00100000 std_synchronize
// IFS_RTS_STD_REQUIRED             0x000F0000 std_required
// IFS_RTS_STD_ALL                  0x001F0000 std_all
// IFS_RTS_STD_EXECUTE              0x00020000 std_execute
// IFS_RTS_STD_READ                 0x00020000 std_read
// IFS_RTS_STD_WRITE                0x00020000 std_write
// IFS_RTS_SPECIFIC_MASK .........  0x0000FFFF specific_mask
// IFS_RTS_FILE_READ_DATA           0x00000001 file_read_data
// IFS_RTS_FILE_WRITE_DATA          0x00000002 file_write_data
// IFS_RTS_FILE_APPEND_DATA         0x00000004 file_append_data
// IFS_RTS_FILE_READ_EA             0x00000008 file_read_ea
// IFS_RTS_FILE_WRITE_EA            0x00000010 file_write_ea
// IFS_RTS_FILE_EXECUTE             0x00000020 file_execute
// IFS_RTS_FILE_UNKNOWN_DIR_ALIAS   0x00000040 file_unknown_dir_alias
// IFS_RTS_FILE_READ_ATTRIBUTES     0x00000080 file_read_attributes
// IFS_RTS_FILE_WRITE_ATTRIBUTES    0x00000100 file_write_attributes
// IFS_RTS_FILE_ALL                 0x000001FF file_all
// IFS_RTS_DIR_LIST                 0x00000001 dir_list
// IFS_RTS_DIR_ADD_FILE             0x00000002 dir_add_file
// IFS_RTS_DIR_ADD_SUBDIR           0x00000004 dir_add_subdir
// IFS_RTS_DIR_READ_EA              0x00000008 dir_read_ea
// IFS_RTS_DIR_WRITE_EA             0x00000010 dir_write_ea
// IFS_RTS_DIR_TRAVERSE             0x00000020 dir_traverse
// IFS_RTS_DIR_DELETE_CHILD         0x00000040 dir_delete_child
// IFS_RTS_DIR_READ_ATTRIBUTES      0x00000080 dir_read_attributes
// IFS_RTS_DIR_WRITE_ATTRIBUTES     0x00000100 dir_write_attributeS
// IFS_RTS_DIR_ALL                  0x000001FF dir_all
// IFS_RTS_FILE_GEN_READ            0x00120089 file_gen_read
// IFS_RTS_DIR_GEN_READ             0x00120089 dir_gen_read
// IFS_RTS_FILE_GEN_WRITE           0x00120116 file_gen_write
// IFS_RTS_DIR_GEN_WRITE            0x00120116 dir_gen_write
// IFS_RTS_FILE_GEN_EXECUTE         0x00120020 file_gen_execute
// IFS_RTS_DIR_GEN_EXECUTE          0x00120020 dir_gen_execute
// IFS_RTS_FILE_GEN_ALL             0x001F01FF file_gen_all
// IFS_RTS_DIR_GEN_ALL              0x001F01FF dir_gen_all
// IFS_RTS_FULL_CONTROL             0x001F01FF full_control
// IFS_RTS_SACL_ACCESS              0x01000000 sacl_access
// IFS_RTS_MAXIMUM_ALLOWED          0x02000000 maximum_allowed

#ifndef PWALK_ACLS_SOURCE	// Suppress conflicting extern decls
struct {
#else
static struct {
#endif
   unsigned mask;		// ACE4 permissions mask value
   char *word;
   short isdir;			// non-zero if word applies to directories
   short flags;			// non-zero if word applies to flags instead of mask
} onefs_keyword_mask[] = {
   {0x00000001, "file_read", 0, 0},		// OneFS
   {0x00000001, "list", 1, 0},			// OneFS directory
   {0x00000002, "add_file", 1, 0},		// OneFS directory
   {0x00000002, "file_write", 0, 0},		// OneFS
   {0x00000004, "add_subdir", 1, 0},		// OneFS directory
   {0x00000004, "append", 0, 0},		// OneFS
   {0x00000008, "dir_read_ext_attr", 1, 0},	// OneFS directory
   {0x00000008, "file_read_ext_attr", 0, 0},	// OneFS
   {0x00000010, "dir_write_ext_attr", 1, 0},	// OneFS directory
   {0x00000010, "file_write_ext_attr", 0, 0},	// OneFS
   {0x00000020, "execute", 0, 0},		// OneFS
   {0x00000020, "traverse", 1, 0},		// OneFS directory
   {0x00000040, "delete_child", 0, 0},		// OneFS
   {0x00000040, "delete_child", 1, 0},		// OneFS directory
   {0x00000080, "dir_read_attr", 1, 0},		// OneFS directory
   {0x00000080, "file_read_attr", 0, 0},	// OneFS
   {0x00000100, "dir_write_attr", 1, 0},	// OneFS directory
   {0x00000100, "file_write_attr", 0, 0},	// OneFS
   {0x00010000, "std_delete", 0, 0},		// OneFS
   {0x00020000, "std_read_dac", 0, 0},		// OneFS
   {0x00040000, "std_write_dac", 0, 0},		// OneFS
   {0x00080000, "std_write_owner", 0, 0},	// OneFS

   //{0x01000000, "read_write_sacl", 0, 0},	// OneFS special internal values
   //{0x10000000, "generic_all", 0, 0},		// OneFS
   //{0x20000000, "generic_exec", 0, 0},	// OneFS
   //{0x40000000, "generic_write", 0, 0},	// OneFS
   //{0x80000000, "generic_read", 0, 0},	// OneFS
   {0x000D0156, "modify", 0, 0},		// OneFS
   {0x000F0000, "std_required", 0, 0},		// OneFS
   {0x00100000, "std_synchronize", 0, 0},	// OneFS
   {0x00120020, "dir_gen_execute", 1, 0},	// OneFS
   {0x00120020, "file_gen_execute", 0, 0},	// OneFS
   {0x00120089, "dir_gen_read", 1, 0},		// OneFS
   {0x00120089, "file_gen_read", 0, 0},		// OneFS
   {0x00120116, "dir_gen_write", 1, 0},		// OneFS
   {0x00120116, "file_gen_write", 0, 0},	// OneFS
   {0x001F01FF, "dir_gen_all", 1, 0},		// OneFS
   {0x001F01FF, "file_gen_all", 0, 0},		// OneFS

   {0x00000001, "object_inherit", 1, 1},	// OneFS flags
   {0x00000002, "container_inherit", 1, 1},	// OneFS
   {0x00000004, "no_prop_inherit", 1, 1},	// OneFS
   {0x00000008, "inherit_only", 1, 1},		// OneFS
   {0x00000080, "inherited_ace", 0, 1},		// OneFS

   {0x00000001, "read", 0, 0},			// OSX perms
   {0x00000001, "list", 1, 0},			// OSX
   {0x00000002, "write", 0, 0},			// OSX
   {0x00000002, "add_file", 1, 0},		// OSX
   {0x00000004, "append", 0, 0},		// OSX
   {0x00000004, "add_subdirectory", 1, 0},	// OSX
   {0x00000008, "readextattr", 0, 0},		// OSX
   {0x00000010, "writeextattr", 0, 0},		// OSX
   {0x00000020, "execute", 0, 0},		// OSX
   {0x00000020, "search_dir", 1, 0},		// OSX
   {0x00000040, "delete_child", 1, 0},		// OSX
   {0x00000080, "readattr", 0, 0},		// OSX
   {0x00000100, "writeattr", 0, 0},		// OSX
   {0x00010000, "delete", 0, 0},		// OSX
   {0x00020000, "readsecurity", 0, 0},		// OSX
   {0x00040000, "writesecurity", 0, 0},		// OSX
   {0x00080000, "chown", 0, 0},			// OSX

   {0x00000001, "file_inherit", 1, 1},		// OSX flags
   {0x00000002, "directory_inherit", 1, 1},	// OSX
   {0x00000004, "limit_inherit", 1, 1},		// OSX
   {0x00000008, "only_inherit", 1, 1},		// OSX
   {0x00000080, "inherited", 0, 1},		// OSX


   {0, NULL, 0, 0}
};

// *** CITI nfstools letter vocabulary & ONEFS bitmasks ...
// NOTE: redundant 'r', 'w', and 'a' letters are retained here for style, but only first match matters
// NOTE: *** OVERLOADED *** 'd' and 'n' letters will never be matched, because only 1st match is used

#ifndef PWALK_ACLS_SOURCE		// Suppress conflicting extern decls
extern struct {
    char ch;				// CITI NFS4 tools letter
    int mask;				// ACE4 permissions mask value
    int flags;				// non-zero if word applies to flags instead of mask
} NFS4_ACL_letters[];
#else
struct {
    char ch;				// CITI NFS4 tools letter
    int mask;				// ACE4 permissions mask value
    int flags;				// non-zero if word applies to flags instead of mask
} NFS4_ACL_letters[] = {
    { 'r', ACE4_READ_DATA                 , 0 },         // 'r' - can (r)ead the data of the file
    { 'r', ACE4_LIST_DIRECTORY            , 0 },         // 'r' - can (r)ead the contents of the directory (not just traverse)
    { 'w', ACE4_WRITE_DATA                , 0 },         // 'w' - can (w)rite the file's data
    { 'w', ACE4_ADD_FILE                  , 0 },         // 'w' - can create ((w)rite) a new file in the directory
    { 'a', ACE4_APPEND_DATA               , 0 },         // 'a' - can (a)ppend data (write starting at EOF)
    { 'a', ACE4_ADD_SUBDIRECTORY          , 0 },         // 'a' - can (a)dd a subdirectory
    { 'n', ACE4_READ_NAMED_ATTRS          , 0 },         // 'n' - can read (n)AMED attr of file or lookup named attrs directory
    { 'N', ACE4_WRITE_NAMED_ATTRS         , 0 },         // 'N' - can write (N)amed attr of file or create named attrs directory
    { 'x', ACE4_EXECUTE                   , 0 },         // 'x' - can e(x)ecute file or traverse/search directory
    { 'D', ACE4_DELETE_CHILD              , 0 },         // 'D' - can (D)elete file or directory within a directory
    { 't', ACE4_READ_ATTRIBUTES           , 0 },         // 't' - can read basic A(t)TRIBUTES (non-ACLs) of a file
    { 'T', ACE4_WRITE_ATTRIBUTES          , 0 },         // 'T' - can write basic a(T)tributes (non-ACLs) of a file
    { 'd', ACE4_DELETE                    , 0 },         // 'd' - can (d)elete file or directory
    { 'c', ACE4_READ_ACL                  , 0 },         // 'c' - can read A(c)L
    { 'C', ACE4_WRITE_ACL                 , 0 },         // 'C' - can write A(C)L
    { 'o', ACE4_WRITE_OWNER               , 0 },         // 'o' - can write (o)wner and owner_group attributes
    { 'y', ACE4_SYNCHRONIZE               , 0 },         // 'y' - can use object as s(y)nchronization primitive for IPC
    // Compound bitmask groups ...
    { 'R', ACE4_SYNCHRONIZE               , 0 },	// ==== complete the compound letters
    { 'W', ACE4_SYNCHRONIZE               , 0 },
    { 'X', ACE4_SYNCHRONIZE               , 0 },
    // Masks for flags bitmasks ...
    { 'f', ACE4_FILE_INHERIT_ACE          , 1 },         // 'f' - propagate ACE to file in directory
    { 'd', ACE4_DIRECTORY_INHERIT_ACE     , 1 },         // 'd' - propagate ACE to subdirectory *** OVERLOADED 'd' ***
    { 'n', ACE4_NO_PROPAGATE_INHERIT_ACE  , 1 },         // 'n' - do not propagate inheritance *** OVERLOADED 'n' ***
    { 'i', ACE4_INHERIT_ONLY_ACE          , 1 },         // 'i' - only inherit ACE; do not evaluate during access
    { 'S', ACE4_SUCCESSFUL_ACCESS_ACE_FLAG, 1 },         // 'S' - trigger alarm/audit when permission Succeeds
    { 'F', ACE4_FAILED_ACCESS_ACE_FLAG    , 1 },         // 'F' - trigger alarm/audit when permission Fails
    { 'g', ACE4_IDENTIFIER_GROUP          , 1 },         // 'g' - 'who' specifies a gROUP
    { '?', ACE4_INHERITED_ACE             , 1 },         // n/a
    { '\0', 0, 0 }
};
#endif

#endif
