#if !defined(PWALK_REPORT_H)
#define PWALK_REPORT_H 1

// Forward declarations ...
int csv_pfile_parse(char *pfile);
void pwalk_report_dir_start(void);
void pwalk_report_dir_entry(void);
void pwalk_report_dir_end(void);

#endif // PWALK_REPORT_H
