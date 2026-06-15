#include "gcm.h"
#include "aes.h"
#include <string.h>

/* Standards-based AES-GCM for 96-bit nonces: CTR encryption plus GHASH over
 * AAD/ciphertext and the length block.  Only encryption of AES blocks is used. */
static void xor_block(uint8_t a[16],const uint8_t b[16]){for(int i=0;i<16;i++)a[i]^=b[i];}
static void inc32(uint8_t c[16]){for(int i=15;i>=12;i--){if(++c[i])break;}}
static void put64be(uint8_t*p,uint64_t v){for(int i=0;i<8;i++)p[i]=(uint8_t)(v>>(56-8*i));}
static void gf_mul(const uint8_t X[16],const uint8_t Y[16],uint8_t out[16]){uint8_t Z[16]={0},V[16];memcpy(V,Y,16);for(int i=0;i<128;i++){if((X[i/8]>>(7-(i%8)))&1)xor_block(Z,V);int lsb=V[15]&1;for(int j=15;j>0;j--)V[j]=(uint8_t)((V[j]>>1)|((V[j-1]&1)<<7));V[0]>>=1;if(lsb)V[0]^=0xe1;}memcpy(out,Z,16);} 
static void ghash_update(uint8_t X[16],const uint8_t H[16],const uint8_t*buf,size_t len){while(len){uint8_t blk[16]={0};size_t n=len<16?len:16;memcpy(blk,buf,n);xor_block(X,blk);gf_mul(X,H,X);buf+=n;len-=n;}}
static void ghash(const uint8_t H[16],const uint8_t*aad,size_t al,const uint8_t*ct,size_t cl,uint8_t S[16]){memset(S,0,16);if(al)ghash_update(S,H,aad,al);if(cl)ghash_update(S,H,ct,cl);uint8_t lenblk[16];put64be(lenblk,(uint64_t)al*8u);put64be(lenblk+8,(uint64_t)cl*8u);xor_block(S,lenblk);gf_mul(S,H,S);} 
static void ctr_crypt(const aes256_ctx*ctx,const uint8_t J0[16],const uint8_t*in,size_t len,uint8_t*out){uint8_t ctr[16],ks[16];memcpy(ctr,J0,16);inc32(ctr);for(size_t off=0;off<len;){aes256_encrypt_block(ctx,ctr,ks);size_t n=len-off<16?len-off:16;for(size_t i=0;i<n;i++)out[off+i]=in[off+i]^ks[i];off+=n;inc32(ctr);}}
static void make_tag(const aes256_ctx*ctx,const uint8_t J0[16],const uint8_t H[16],const uint8_t*aad,size_t al,const uint8_t*ct,size_t cl,uint8_t tag[16]){uint8_t S[16],E[16];ghash(H,aad,al,ct,cl,S);aes256_encrypt_block(ctx,J0,E);for(int i=0;i<16;i++)tag[i]=E[i]^S[i];}
int aes256_gcm_encrypt(const uint8_t key[32],const uint8_t nonce[12],const uint8_t*aad,size_t al,const uint8_t*pt,size_t pl,uint8_t*ct,uint8_t tag[16]){aes256_ctx ctx;uint8_t H[16],J0[16]={0};aes256_init(&ctx,key);memset(H,0,16);aes256_encrypt_block(&ctx,H,H);memcpy(J0,nonce,12);J0[15]=1;ctr_crypt(&ctx,J0,pt,pl,ct);make_tag(&ctx,J0,H,aad,al,ct,pl,tag);return 0;}
int aes256_gcm_decrypt(const uint8_t key[32],const uint8_t nonce[12],const uint8_t*aad,size_t al,const uint8_t*ct,size_t cl,const uint8_t tag[16],uint8_t*pt){aes256_ctx ctx;uint8_t H[16],J0[16]={0},calc[16],diff=0;aes256_init(&ctx,key);memset(H,0,16);aes256_encrypt_block(&ctx,H,H);memcpy(J0,nonce,12);J0[15]=1;make_tag(&ctx,J0,H,aad,al,ct,cl,calc);for(int i=0;i<16;i++)diff|=calc[i]^tag[i];if(diff)return -1;ctr_crypt(&ctx,J0,ct,cl,pt);return 0;}
