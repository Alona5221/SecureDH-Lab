#ifndef COMMON_H
#define COMMON_H
#include <stdint.h>
#include <stddef.h>
#define SDH_MAGIC 0x53444831u
#define SDH_VERSION 1
#define MODE_WEAK 0
#define MODE_SECURE 1
#define MAX_PAYLOAD (1024*1024)
int random_bytes(uint8_t *buf, size_t len);
void secure_zero(void *p, size_t n);
int read_file_all(const char *path, uint8_t **out, size_t *out_len);
int write_file_bytes(const char *path, const uint8_t *buf, size_t len);
int daemonize_process(const char *log_path);
#endif
