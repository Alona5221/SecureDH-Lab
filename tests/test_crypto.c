#include "sha256.h"
#include "hmac.h"
#include "aes.h"
#include "gcm.h"
#include <stdio.h>
#include <string.h>
int main(void){uint8_t h[32],key[32]={1},nonce[12]={2},ct[64],pt[64],tag[16];sha256((uint8_t*)"abc",3,h);hmac_sha256(key,32,(uint8_t*)"abc",3,h);aes256_ctx c;uint8_t out[16];aes256_init(&c,key);uint8_t blk[16]={0};memcpy(blk,nonce,12);aes256_encrypt_block(&c,blk,out);char*m="hello crypto";aes256_gcm_encrypt(key,nonce,NULL,0,(uint8_t*)m,strlen(m),ct,tag);if(aes256_gcm_decrypt(key,nonce,NULL,0,ct,strlen(m),tag,pt))return 1;pt[strlen(m)]=0;if(strcmp((char*)pt,m))return 2;tag[0]^=1;if(aes256_gcm_decrypt(key,nonce,NULL,0,ct,strlen(m),tag,pt)==0)return 3;puts("crypto tests passed");return 0;}
