#include "kdf.h"
#include "sha256.h"
#include <string.h>
void derive_session_key(uint64_t s,const uint8_t cn[16],const uint8_t sn[16],const char*l,uint8_t key[32]){SHA256_CTX c; uint8_t b[8]; for(int i=0;i<8;i++)b[i]=(uint8_t)(s>>(56-8*i)); sha256_init(&c); sha256_update(&c,b,8); sha256_update(&c,cn,16); sha256_update(&c,sn,16); sha256_update(&c,(const uint8_t*)l,strlen(l)); sha256_final(&c,key);} 
