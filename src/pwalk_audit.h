#ifndef PWALK_AUDIT_H
#define PWALK_AUDIT_H 1
void pwalk_audit_keys(void);
void pwalk_audit_file(char *ifspath, struct stat *st, int w_id);
#endif
