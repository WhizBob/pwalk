#if !defined(PWALK_REPORT_H)
#define PWALK_REPORT_H 1

// Forward declarations ...
int pwalk_report_parse(char *ifile);
void pwalk_report_file(void);
void pwalk_report_dir_start(void);
void pwalk_report_dir_entry(void);
void pwalk_report_dir_end(void);

#endif // PWALK_REPORT_H
