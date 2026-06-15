#ifndef AES_H
#define AES_H
#include <stdint.h>
typedef struct { uint32_t rk[60]; } aes256_ctx;
void aes256_init(aes256_ctx *ctx, const uint8_t key[32]);
void aes256_encrypt_block(const aes256_ctx *ctx, const uint8_t in[16], uint8_t out[16]);
#endif
