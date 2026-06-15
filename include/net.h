#ifndef NET_H
#define NET_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
int send_all(int fd, const void *buf, size_t len);
int recv_all(int fd, void *buf, size_t len);
int tcp_listen(const char *host, uint16_t port, int backlog);
int tcp_connect(const char *host, uint16_t port);
#endif
