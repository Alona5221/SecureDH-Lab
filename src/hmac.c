#include "hmac.h"
#include "sha256.h"
#include <string.h>
void hmac_sha256(const uint8_t*k,size_t kl,const uint8_t*d,size_t l,uint8_t out[32]){uint8_t key[64]={0},ipad[64],opad[64],inner[32]; if(kl>64){sha256(k,kl,key);kl=32;}else memcpy(key,k,kl); for(int i=0;i<64;i++){ipad[i]=key[i]^0x36;opad[i]=key[i]^0x5c;} SHA256_CTX c;sha256_init(&c);sha256_update(&c,ipad,64);sha256_update(&c,d,l);sha256_final(&c,inner);sha256_init(&c);sha256_update(&c,opad,64);sha256_update(&c,inner,32);sha256_final(&c,out);} 
