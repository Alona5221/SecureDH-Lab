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
#include <time.h>

typedef struct{int fd;int mode;uint8_t*psk;size_t psk_len;} job_t;
typedef struct{int mode;uint8_t client_nonce[16];uint8_t server_nonce[16];uint8_t key[32];uint32_t seq;time_t last_rekey_time;int msg_since_rekey;} session_t;

static int server_handshake_from_payload(int fd,int msg_type,const uint8_t*payload,uint32_t len,job_t*j,session_t*s)
{
    int is_rekey=(msg_type==MSG_REKEY); if(is_rekey) log_info(j->mode==MODE_SECURE?"[rekey] starting authenticated key update":"[rekey] starting key update");
    client_hello_t ch; if(decode_client_hello(payload,len,&ch)) return -1; uint8_t chb[28]; memcpy(chb,payload,28); memcpy(s->client_nonce,ch.nonce,16);
    uint64_t priv=dh_generate_private(); server_hello_t sh={SDH_VERSION,dh_compute_public(priv),{0},{0}}; random_bytes(sh.nonce,16); memcpy(s->server_nonce,sh.nonce,16);
    uint8_t shwo[26],shb[58]; encode_server_hello_without_auth(shwo,&sh); if(j->mode==MODE_SECURE)compute_server_auth(j->psk,j->psk_len,chb,shwo,sh.auth); encode_server_hello(shb,&sh); if(send_msg(fd,MSG_SERVER_HELLO,0,++s->seq,shb,58))return -1;
    if(j->mode==MODE_SECURE){uint16_t type;uint32_t fl,seq,alen;uint8_t*auth=NULL; if(recv_msg(fd,&type,&fl,&seq,&auth,&alen)||type!=MSG_CLIENT_AUTH||alen!=32){free(auth);log_error("authentication failed");return -1;} uint8_t exp[32]; compute_client_auth(j->psk,j->psk_len,chb,shwo,exp); if(!consttime_eq(exp,auth,32)){free(auth);log_error("authentication failed");return -1;} free(auth); if(!is_rekey)log_info("[server] client handshake authentication passed");}
    derive_session_key(dh_compute_shared(ch.dh_public,priv),s->client_nonce,s->server_nonce,"SecureDH-Lab session",s->key); s->last_rekey_time=time(NULL); s->msg_since_rekey=0;
    log_info(is_rekey?(j->mode==MODE_SECURE?"[rekey] new authenticated session key established":"[rekey] new session key established"):"[server] DH shared key established"); return 0;
}

static int decrypt_data(session_t*s,const uint8_t*p,uint32_t len)
{ if(len<28)return -1; uint8_t*pt=malloc(len-28+1); if(!pt)return -1; int rc=aes256_gcm_decrypt(s->key,p,NULL,0,p+28,len-28,p+12,pt); if(rc==0){pt[len-28]=0;log_info("[server] decrypted message: %s",pt);s->msg_since_rekey++;} else log_error("decrypt/tag verification failed"); free(pt); return rc; }

static void*handle(void*arg)
{
    job_t*j=arg; int fd=j->fd; session_t sess={.mode=j->mode}; uint16_t type; uint32_t fl,seq,len; uint8_t*p=NULL;
    if(recv_msg(fd,&type,&fl,&seq,&p,&len)||type!=MSG_CLIENT_HELLO) goto end;
    if(server_handshake_from_payload(fd,type,p,len,j,&sess)){free(p);goto end;}
    free(p);
    while(recv_msg(fd,&type,&fl,&seq,&p,&len)==0){ if(type==MSG_DATA)decrypt_data(&sess,p,len); else if(type==MSG_REKEY){ if(server_handshake_from_payload(fd,type,p,len,j,&sess)){free(p);break;} } else {free(p);break;} free(p); p=NULL; }
end: close(fd); free(j); return NULL;
}

int main(int argc,char**argv)
{
    const char*host="0.0.0.0",*mode_s="weak",*pskfile=NULL,*logp=NULL; int port=9000,verbose=0,daemon=0,rekey_sec=0,rekey_msg=0;
    static struct option opts[]={{"host",1,0,'h'},{"port",1,0,'p'},{"mode",1,0,'m'},{"psk-file",1,0,'k'},{"verbose",0,0,'v'},{"daemon",0,0,'d'},{"log",1,0,'l'},{"rekey-sec",1,0,'s'},{"rekey-msg",1,0,'r'},{0,0,0,0}};
    int c; while((c=getopt_long(argc,argv,"",opts,NULL))!=-1){if(c=='h')host=optarg;else if(c=='p')port=atoi(optarg);else if(c=='m')mode_s=optarg;else if(c=='k')pskfile=optarg;else if(c=='v')verbose=1;else if(c=='d')daemon=1;else if(c=='l')logp=optarg;else if(c=='s')rekey_sec=atoi(optarg);else if(c=='r')rekey_msg=atoi(optarg);} (void)rekey_sec;(void)rekey_msg;
    if(daemon)daemonize_process(logp);
    log_set_verbose(verbose);
    if(logp&&!daemon)log_set_file(logp);
    int mode=strcmp(mode_s,"secure")==0?MODE_SECURE:MODE_WEAK;
    uint8_t*psk=NULL; size_t psk_len=0;
    if(mode==MODE_SECURE&&(!pskfile||read_file_all(pskfile,&psk,&psk_len))){log_error("psk read failed");return 1;}
    int lfd=tcp_listen(host,(uint16_t)port,16);
    if(lfd<0){perror("listen");return 1;}
    log_info("[server] listening on %s:%d",host,port);
    for(;;){int fd=accept(lfd,NULL,NULL); if(fd<0)continue; job_t*j=calloc(1,sizeof*j); if(!j){close(fd);continue;} j->fd=fd;j->mode=mode;j->psk=psk;j->psk_len=psk_len; pthread_t th; if(pthread_create(&th,NULL,handle,j)==0)pthread_detach(th); else {close(fd);free(j);} }
}
