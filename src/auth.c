#include "auth.h"
#include "hmac.h"
#include <stdlib.h>
#include <string.h>
static void calc(const char*role,const uint8_t*psk,size_t pl,const uint8_t ch[28],const uint8_t sh[26],uint8_t out[32]){size_t rl=strlen(role),n=rl+28+26;uint8_t*b=malloc(n);if(!b){memset(out,0,32);return;}memcpy(b,role,rl);memcpy(b+rl,ch,28);memcpy(b+rl+28,sh,26);hmac_sha256(psk,pl,b,n,out);free(b);} void compute_server_auth(const uint8_t*p,size_t l,const uint8_t ch[28],const uint8_t sh[26],uint8_t o[32]){calc("server",p,l,ch,sh,o);} void compute_client_auth(const uint8_t*p,size_t l,const uint8_t ch[28],const uint8_t sh[26],uint8_t o[32]){calc("client",p,l,ch,sh,o);} int consttime_eq(const uint8_t*a,const uint8_t*b,size_t n){uint8_t d=0;for(size_t i=0;i<n;i++)d|=a[i]^b[i];return d==0;}
