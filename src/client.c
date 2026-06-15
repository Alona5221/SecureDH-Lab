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
#include <time.h>

typedef struct { int mode; uint8_t client_nonce[16]; uint8_t server_nonce[16]; uint8_t key[32]; uint32_t seq; time_t last_rekey_time; int msg_since_rekey; } session_t;

static int do_handshake(int fd,int mode,const uint8_t*psk,size_t psk_len,session_t*s,int rekey)
{
    if(rekey) log_info(mode==MODE_SECURE?"[rekey] starting authenticated key update":"[rekey] starting key update");
    client_hello_t ch={SDH_VERSION,mode,0,{0}}; uint64_t priv=dh_generate_private();
    ch.dh_public=dh_compute_public(priv); random_bytes(ch.nonce,16); memcpy(s->client_nonce,ch.nonce,16);
    uint8_t chb[28]; encode_client_hello(chb,&ch);
    if(send_msg(fd,rekey?MSG_REKEY:MSG_CLIENT_HELLO,0,++s->seq,chb,28)) return -1;
    uint16_t type; uint32_t flags,seq,len; uint8_t*payload=NULL;
    if(recv_msg(fd,&type,&flags,&seq,&payload,&len)||type!=MSG_SERVER_HELLO) return -1;
    server_hello_t sh; if(decode_server_hello(payload,len,&sh)){free(payload);return -1;} free(payload);
    uint8_t shwo[26]; encode_server_hello_without_auth(shwo,&sh); memcpy(s->server_nonce,sh.nonce,16);
    if(mode==MODE_SECURE){uint8_t exp[32]; compute_server_auth(psk,psk_len,chb,shwo,exp); if(!consttime_eq(exp,sh.auth,32)){log_error(rekey?"[client] rekey server authentication failed":"[client] server authentication failed"); return -1;} if(!rekey)log_info("[client] server handshake authentication passed"); uint8_t ca[32]; compute_client_auth(psk,psk_len,chb,shwo,ca); if(send_msg(fd,MSG_CLIENT_AUTH,0,++s->seq,ca,32))return -1;}
    derive_session_key(dh_compute_shared(sh.dh_public,priv),s->client_nonce,s->server_nonce,"SecureDH-Lab session",s->key);
    s->last_rekey_time=time(NULL); s->msg_since_rekey=0;
    if(rekey) log_info(mode==MODE_SECURE?"[rekey] new authenticated session key established":"[rekey] new session key established");
    return 0;
}

static int send_encrypted(int fd,session_t*s,const uint8_t*plain,size_t plen)
{ uint8_t nonce[12],tag[16]; random_bytes(nonce,12); uint8_t*ct=malloc(plen?plen:1); uint8_t*dp=malloc(28+plen); if(!ct||!dp){free(ct);free(dp);return -1;} aes256_gcm_encrypt(s->key,nonce,NULL,0,plain,plen,ct,tag); memcpy(dp,nonce,12); memcpy(dp+12,tag,16); memcpy(dp+28,ct,plen); int rc=send_msg(fd,MSG_DATA,0,++s->seq,dp,(uint32_t)(28+plen)); free(ct); free(dp); return rc; }

int main(int argc,char**argv)
{
    const char*host="127.0.0.1",*mode_s="weak",*pskfile=NULL,*msg="hello",*file=NULL; int port=9000,verbose=0,repeat=1,interval_ms=0,rekey_msg=0,rekey_sec=0;
    static struct option opts[]={{"host",1,0,'h'},{"port",1,0,'p'},{"mode",1,0,'m'},{"psk-file",1,0,'k'},{"message",1,0,'M'},{"file",1,0,'f'},{"verbose",0,0,'v'},{"repeat",1,0,'R'},{"interval",1,0,'i'},{"rekey-msg",1,0,'r'},{"rekey-sec",1,0,'s'},{0,0,0,0}};
    int c; while((c=getopt_long(argc,argv,"",opts,NULL))!=-1){if(c=='h')host=optarg;else if(c=='p')port=atoi(optarg);else if(c=='m')mode_s=optarg;else if(c=='k')pskfile=optarg;else if(c=='M')msg=optarg;else if(c=='f')file=optarg;else if(c=='v')verbose=1;else if(c=='R')repeat=atoi(optarg);else if(c=='i')interval_ms=atoi(optarg);else if(c=='r')rekey_msg=atoi(optarg);else if(c=='s')rekey_sec=atoi(optarg);} log_set_verbose(verbose);
    int mode=strcmp(mode_s,"secure")==0?MODE_SECURE:MODE_WEAK; uint8_t*psk=NULL; size_t psk_len=0; if(mode==MODE_SECURE&&(!pskfile||read_file_all(pskfile,&psk,&psk_len))){log_error("psk read failed");return 1;}
    int fd=tcp_connect(host,(uint16_t)port); if(fd<0){perror("connect");return 1;} session_t sess={.mode=mode}; if(do_handshake(fd,mode,psk,psk_len,&sess,0)){close(fd);return 2;}
    uint8_t*filebuf=NULL; size_t filelen=0; if(file&&read_file_all(file,&filebuf,&filelen)){log_error("file read failed");return 1;}
    for(int i=1;i<=repeat;i++){time_t now=time(NULL); int need=(rekey_msg>0&&sess.msg_since_rekey>=rekey_msg)||(rekey_sec>0&&now-sess.last_rekey_time>=rekey_sec); if(need&&do_handshake(fd,mode,psk,psk_len,&sess,1)){close(fd);return 3;} uint8_t stack[1024]; uint8_t*plain=stack; size_t plen; if(filebuf){plain=filebuf; plen=filelen;} else if(repeat>1){plen=(size_t)snprintf((char*)stack,sizeof stack,"%s #%d",msg,i);} else {plain=(uint8_t*)msg; plen=strlen(msg);} if(send_encrypted(fd,&sess,plain,plen)){log_error("send failed");break;} sess.msg_since_rekey++; log_info("[client] encrypted message sent"); if(interval_ms>0)usleep((useconds_t)interval_ms*1000);}
    free(filebuf); free(psk); close(fd); return 0;
}
