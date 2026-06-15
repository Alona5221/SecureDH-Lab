#include "dh.h"
#include "common.h"
uint64_t modexp_u64(uint64_t b,uint64_t e,uint64_t m){uint64_t r=1%m; b%=m; while(e){if(e&1)r=(uint64_t)((__uint128_t)r*b%m); b=(uint64_t)((__uint128_t)b*b%m); e>>=1;} return r;}
uint64_t dh_generate_private(void){uint64_t x=0; random_bytes((uint8_t*)&x,sizeof x); return 2+(x%(DH_P-3));}
uint64_t dh_compute_public(uint64_t priv){return modexp_u64(DH_G,priv,DH_P);} uint64_t dh_compute_shared(uint64_t peer,uint64_t priv){return modexp_u64(peer,priv,DH_P);}
