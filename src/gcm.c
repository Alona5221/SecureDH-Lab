#include "gcm.h"
#include "aes.h"
#include "hmac.h"
#include <string.h>
#include <stdlib.h>
static void ctr(const uint8_t key[32],const uint8_t nonce[12],const uint8_t*in,size_t n,uint8_t*out){aes256_ctx c; aes256_init(&c,key); uint8_t block[16]={0},ks[16]; memcpy(block,nonce,12); uint32_t ctr=1; for(size_t off=0;off<n;){block[12]=ctr>>24;block[13]=ctr>>16;block[14]=ctr>>8;block[15]=ctr; aes256_encrypt_block(&c,block,ks); size_t m=n-off<16?n-off:16; for(size_t i=0;i<m;i++)out[off+i]=in[off+i]^ks[i]; off+=m; ctr++;}}
static void tag_make(const uint8_t key[32],const uint8_t nonce[12],const uint8_t*aad,size_t al,const uint8_t*ct,size_t cl,uint8_t tag[16]){uint8_t mac_key[32],buf[16]; aes256_ctx c; aes256_init(&c,key); memset(buf,0,sizeof buf); aes256_encrypt_block(&c,buf,mac_key); uint8_t nb[16]={0}; memcpy(nb,nonce,12); aes256_encrypt_block(&c,nb,mac_key+16); size_t total=12+8+al+cl; uint8_t *tmp=malloc(total); if(!tmp){memset(tag,0,16);return;} memcpy(tmp,nonce,12); for(int i=0;i<8;i++)tmp[12+i]=(uint8_t)(((uint64_t)al+cl)>>(56-8*i)); memcpy(tmp+20,aad,al); memcpy(tmp+20+al,ct,cl); uint8_t h[32]; hmac_sha256(mac_key,32,tmp,total,h); memcpy(tag,h,16); free(tmp);} 
int aes256_gcm_encrypt(const uint8_t key[32],const uint8_t nonce[12],const uint8_t*aad,size_t al,const uint8_t*pt,size_t pl,uint8_t*ct,uint8_t tag[16]){ctr(key,nonce,pt,pl,ct);tag_make(key,nonce,aad,al,ct,pl,tag);return 0;}
int aes256_gcm_decrypt(const uint8_t key[32],const uint8_t nonce[12],const uint8_t*aad,size_t al,const uint8_t*ct,size_t cl,const uint8_t tag[16],uint8_t*pt){uint8_t t[16];tag_make(key,nonce,aad,al,ct,cl,t);uint8_t diff=0;for(int i=0;i<16;i++)diff|=t[i]^tag[i];if(diff)return -1;ctr(key,nonce,ct,cl,pt);return 0;}
