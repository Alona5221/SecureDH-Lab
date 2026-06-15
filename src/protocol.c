#include "protocol.h"
#include "common.h"
#include "net.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
void put_u16(uint8_t*p,uint16_t v){p[0]=v>>8;p[1]=v;} void put_u64(uint8_t*p,uint64_t v){for(int i=0;i<8;i++)p[i]=(uint8_t)(v>>(56-8*i));} uint16_t get_u16(const uint8_t*p){return (uint16_t)(p[0]<<8|p[1]);} uint64_t get_u64(const uint8_t*p){uint64_t v=0;for(int i=0;i<8;i++)v=(v<<8)|p[i];return v;}
int send_msg(int fd,uint16_t type,uint32_t flags,uint32_t seq,const uint8_t*p,uint32_t len){msg_header_t h; h.magic=htonl(SDH_MAGIC);h.version=htons(SDH_VERSION);h.type=htons(type);h.flags=htonl(flags);h.seq=htonl(seq);h.length=htonl(len); return send_all(fd,&h,sizeof h)||send_all(fd,p,len)?-1:0;}
int recv_msg(int fd,uint16_t*type,uint32_t*flags,uint32_t*seq,uint8_t**payload,uint32_t*len){msg_header_t h;if(recv_all(fd,&h,sizeof h))return -1; if(ntohl(h.magic)!=SDH_MAGIC||ntohs(h.version)!=SDH_VERSION)return -1; *type=ntohs(h.type);*flags=ntohl(h.flags);*seq=ntohl(h.seq);*len=ntohl(h.length); if(*len>MAX_PAYLOAD)return -1; *payload=malloc(*len?*len:1); if(!*payload)return -1; if(recv_all(fd,*payload,*len)){free(*payload);return -1;} return 0;}
void encode_client_hello(uint8_t o[28],const client_hello_t*c){put_u16(o,c->version);put_u16(o+2,c->mode);put_u64(o+4,c->dh_public);memcpy(o+12,c->nonce,16);} int decode_client_hello(const uint8_t*b,size_t l,client_hello_t*c){if(l!=28)return -1;c->version=get_u16(b);c->mode=get_u16(b+2);c->dh_public=get_u64(b+4);memcpy(c->nonce,b+12,16);return 0;}
void encode_server_hello_without_auth(uint8_t o[26],const server_hello_t*s){put_u16(o,s->version);put_u64(o+2,s->dh_public);memcpy(o+10,s->nonce,16);} void encode_server_hello(uint8_t o[58],const server_hello_t*s){encode_server_hello_without_auth(o,s);memcpy(o+26,s->auth,32);} int decode_server_hello(const uint8_t*b,size_t l,server_hello_t*s){if(l!=58)return -1;s->version=get_u16(b);s->dh_public=get_u64(b+2);memcpy(s->nonce,b+10,16);memcpy(s->auth,b+26,32);return 0;}
