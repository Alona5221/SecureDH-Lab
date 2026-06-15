#ifndef AUTH_H
#define AUTH_H
#include <stdint.h>
#include <stddef.h>
void compute_server_auth(const uint8_t *psk,size_t psk_len,const uint8_t ch[28],const uint8_t sh_wo[26],uint8_t out[32]);
void compute_client_auth(const uint8_t *psk,size_t psk_len,const uint8_t ch[28],const uint8_t sh_wo[26],uint8_t out[32]);
int consttime_eq(const uint8_t *a,const uint8_t *b,size_t n);
#endif
