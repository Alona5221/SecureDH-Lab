#include "common.h"
#include "net.h"
#include "dh.h"
#include "protocol.h"
#include "auth.h"
#include "kdf.h"
#include "gcm.h"
#include "log.h"
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
typedef struct{int fd;int mode;uint8_t*psk;size_t psk_len;} job_t;
static void*handle(void*arg){job_t*j=arg;int fd=j->fd;uint16_t type;uint32_t fl,seq,len;uint8_t*p=NULL;if(recv_msg(fd,&type,&fl,&seq,&p,&len)||type!=MSG_CLIENT_HELLO)goto end;client_hello_t ch;if(decode_client_hello(p,len,&ch))goto end;uint8_t chb[28];memcpy(chb,p,28);free(p);uint64_t priv=dh_generate_private();server_hello_t sh={SDH_VERSION,dh_compute_public(priv),{0},{0}};random_bytes(sh.nonce,16);uint8_t shwo[26],shb[58];encode_server_hello_without_auth(shwo,&sh);if(j->mode==MODE_SECURE)compute_server_auth(j->psk,j->psk_len,chb,shwo,sh.auth);encode_server_hello(shb,&sh);send_msg(fd,MSG_SERVER_HELLO,0,2,shb,58);if(j->mode==MODE_SECURE){if(recv_msg(fd,&type,&fl,&seq,&p,&len)||type!=MSG_CLIENT_AUTH||len!=32){log_error("authentication failed");goto end;}uint8_t exp[32];compute_client_auth(j->psk,j->psk_len,chb,shwo,exp);if(!consttime_eq(exp,p,32)){log_error("authentication failed");free(p);goto end;}free(p);log_info("[server] client handshake authentication passed");}log_info("[server] DH shared key established");uint64_t shared=dh_compute_shared(ch.dh_public,priv);uint8_t key[32];derive_session_key(shared,ch.nonce,sh.nonce,"SecureDH-Lab session",key);if(recv_msg(fd,&type,&fl,&seq,&p,&len)||type!=MSG_DATA||len<28)goto end;uint8_t*pt=malloc(len-28+1);if(aes256_gcm_decrypt(key,p,chb,28,p+28,len-28,p+12,pt)==0){pt[len-28]=0;log_info("[server] decrypted message: %s",pt);}else log_error("decrypt/tag verification failed");free(pt);free(p);end:close(fd);free(j);return NULL;}
int main(int argc,char**argv){const char*host="0.0.0.0",*mode_s="weak",*pskfile=NULL,*logp=NULL;int port=9000,verbose=0,daemon=0;static struct option opts[]={{"host",1,0,'h'},{"port",1,0,'p'},{"mode",1,0,'m'},{"psk-file",1,0,'k'},{"verbose",0,0,'v'},{"daemon",0,0,'d'},{"log",1,0,'l'},{"rekey-sec",1,0,'s'},{"rekey-msg",1,0,'r'},{0,0,0,0}};int c;while((c=getopt_long(argc,argv,"",opts,NULL))!=-1){if(c=='h')host=optarg;else if(c=='p')port=atoi(optarg);else if(c=='m')mode_s=optarg;else if(c=='k')pskfile=optarg;else if(c=='v')verbose=1;else if(c=='d')daemon=1;else if(c=='l')logp=optarg;}if(daemon)daemonize_process(logp);log_set_verbose(verbose);if(logp&&!daemon)log_set_file(logp);int mode=strcmp(mode_s,"secure")==0?MODE_SECURE:MODE_WEAK;uint8_t*psk=NULL;size_t psk_len=0;if(mode==MODE_SECURE&&(!pskfile||read_file_all(pskfile,&psk,&psk_len))){log_error("psk read failed");return 1;}int lfd=tcp_listen(host,(uint16_t)port,16);if(lfd<0){perror("listen");return 1;}log_info("[server] listening on %s:%d",host,port);for(;;){int fd=accept(lfd,NULL,NULL);if(fd<0)continue;job_t*j=calloc(1,sizeof* j);j->fd=fd;j->mode=mode;j->psk=psk;j->psk_len=psk_len;pthread_t th;pthread_create(&th,NULL,handle,j);pthread_detach(th);} }
