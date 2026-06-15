#include "common.h"
#include "net.h"
#include "dh.h"
#include "protocol.h"
#include "auth.h"
#include "kdf.h"
#include "gcm.h"
#include "log.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int read_text_file(const char*p,uint8_t**b,size_t*n){return read_file_all(p,b,n);} 
int main(int argc,char**argv){const char*host="127.0.0.1",*mode_s="weak",*pskfile=NULL,*msg="hello",*file=NULL;int port=9000,verbose=0;static struct option opts[]={{"host",1,0,'h'},{"port",1,0,'p'},{"mode",1,0,'m'},{"psk-file",1,0,'k'},{"message",1,0,'M'},{"file",1,0,'f'},{"verbose",0,0,'v'},{0,0,0,0}};int c;while((c=getopt_long(argc,argv,"",opts,NULL))!=-1){if(c=='h')host=optarg;else if(c=='p')port=atoi(optarg);else if(c=='m')mode_s=optarg;else if(c=='k')pskfile=optarg;else if(c=='M')msg=optarg;else if(c=='f')file=optarg;else if(c=='v')verbose=1;}log_set_verbose(verbose);int mode=strcmp(mode_s,"secure")==0?MODE_SECURE:MODE_WEAK;uint8_t*psk=NULL;size_t psk_len=0;if(mode==MODE_SECURE&&(!pskfile||read_file_all(pskfile,&psk,&psk_len))){log_error("psk read failed");return 1;}int fd=tcp_connect(host,(uint16_t)port);if(fd<0){perror("connect");return 1;}client_hello_t ch={SDH_VERSION,mode,0,{0}};uint64_t priv=dh_generate_private();ch.dh_public=dh_compute_public(priv);random_bytes(ch.nonce,16);uint8_t chb[28];encode_client_hello(chb,&ch);send_msg(fd,MSG_CLIENT_HELLO,0,1,chb,28);uint16_t type;uint32_t flags,seq,len;uint8_t*payload=NULL;if(recv_msg(fd,&type,&flags,&seq,&payload,&len)||type!=MSG_SERVER_HELLO){log_error("handshake failed");return 1;}server_hello_t sh; if(decode_server_hello(payload,len,&sh)){log_error("bad server hello");return 1;}free(payload);uint8_t shwo[26];encode_server_hello_without_auth(shwo,&sh);if(mode==MODE_SECURE){uint8_t exp[32];compute_server_auth(psk,psk_len,chb,shwo,exp);if(!consttime_eq(exp,sh.auth,32)){log_error("[client] server authentication failed");close(fd);return 2;}log_info("[client] server handshake authentication passed");uint8_t ca[32];compute_client_auth(psk,psk_len,chb,shwo,ca);send_msg(fd,MSG_CLIENT_AUTH,0,3,ca,32);}uint64_t shared=dh_compute_shared(sh.dh_public,priv);uint8_t key[32];derive_session_key(shared,ch.nonce,sh.nonce,"SecureDH-Lab session",key);uint8_t nonce[12];random_bytes(nonce,12);uint8_t*plain=(uint8_t*)msg;size_t plen=strlen(msg);uint8_t*fb=NULL;if(file){if(read_text_file(file,&fb,&plen)){log_error("file read failed");return 1;}plain=fb;}uint8_t*ct=malloc(plen);uint8_t tag[16];aes256_gcm_encrypt(key,nonce,chb,28,plain,plen,ct,tag);uint8_t *dp=malloc(12+16+plen);memcpy(dp,nonce,12);memcpy(dp+12,tag,16);memcpy(dp+28,ct,plen);send_msg(fd,MSG_DATA,0,4,dp,(uint32_t)(28+plen));log_info("[client] encrypted message sent");free(dp);free(ct);free(fb);free(psk);close(fd);return 0;}
