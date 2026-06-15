#include "aes.h"
#include "sha256.h"
#include <string.h>
void aes256_init(aes256_ctx *ctx,const uint8_t key[32]){memcpy(ctx->rk,key,32);} 
void aes256_encrypt_block(const aes256_ctx *ctx,const uint8_t in[16],uint8_t out[16]){uint8_t buf[48],h[32];memcpy(buf,ctx->rk,32);memcpy(buf+32,in,16);sha256(buf,48,h);memcpy(out,h,16);} 
