#ifndef LOG_H
#define LOG_H
#include <stdint.h>
#include <stddef.h>
void log_set_verbose(int v); void log_set_file(const char *path); void log_close(void);
void log_info(const char *fmt,...); void log_error(const char *fmt,...); void log_hex(const char *label,const uint8_t *buf,size_t len);
#endif
