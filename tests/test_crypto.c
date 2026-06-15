#include "sha256.h"
#include "hmac.h"
#include "aes.h"
#include "gcm.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int hexval(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static int hex2bin(const char*hex,uint8_t*out,size_t n){for(size_t i=0;i<n;i++){int a=hexval(hex[2*i]),b=hexval(hex[2*i+1]);if(a<0||b<0)return -1;out[i]=(uint8_t)((a<<4)|b);}return 0;}
static int expect_eq(const char*name,const uint8_t*a,const uint8_t*b,size_t n){if(memcmp(a,b,n)==0)return 0;fprintf(stderr,"%s mismatch\n",name);fprintf(stderr,"got: ");for(size_t i=0;i<n;i++)fprintf(stderr,"%02x",a[i]);fprintf(stderr,"\nexp: ");for(size_t i=0;i<n;i++)fprintf(stderr,"%02x",b[i]);fprintf(stderr,"\n");return 1;}

int main(void)
{
    uint8_t h[32],key[32]={1}; sha256((const uint8_t*)"abc",3,h); hmac_sha256(key,32,(const uint8_t*)"abc",3,h);

    uint8_t aes_key[32],pt[16],exp_ct[16],out[16];
    hex2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",aes_key,32);
    hex2bin("6bc1bee22e409f96e93d7e117393172a",pt,16);
    hex2bin("f3eed1bdb5d2a03c064b5a7e3db181f8",exp_ct,16);
    aes256_ctx c; aes256_init(&c,aes_key); aes256_encrypt_block(&c,pt,out); if(expect_eq("AES-256 vector",out,exp_ct,16))return 1;

    uint8_t gkey[32]={0},nonce[12]={0},gpt[16]={0},gct[16],gtag[16],exp_gct[16],exp_tag[16],dec[32];
    hex2bin("cea7403d4d606b6e074ec5d3baf39d18",exp_gct,16); hex2bin("d0d1c8a799996bf0265b98b5d48ab919",exp_tag,16);
    aes256_gcm_encrypt(gkey,nonce,NULL,0,gpt,16,gct,gtag); if(expect_eq("GCM ciphertext vector",gct,exp_gct,16))return 2; if(expect_eq("GCM tag vector",gtag,exp_tag,16))return 3;

    const char*m="hello crypto"; uint8_t rct[64],rtag[16]; aes256_gcm_encrypt(key,nonce,NULL,0,(const uint8_t*)m,strlen(m),rct,rtag); if(aes256_gcm_decrypt(key,nonce,NULL,0,rct,strlen(m),rtag,dec)){fprintf(stderr,"GCM roundtrip decrypt failed\n");return 4;} dec[strlen(m)]=0; if(strcmp((char*)dec,m)){fprintf(stderr,"GCM roundtrip plaintext mismatch\n");return 5;} rtag[0]^=1; if(aes256_gcm_decrypt(key,nonce,NULL,0,rct,strlen(m),rtag,dec)==0){fprintf(stderr,"GCM tampered tag accepted\n");return 6;}
    puts("crypto tests passed"); return 0;
}
