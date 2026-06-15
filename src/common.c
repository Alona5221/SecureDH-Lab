#include "common.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
int random_bytes(uint8_t *buf,size_t len){int fd=open("/dev/urandom",O_RDONLY); if(fd<0)return -1; size_t off=0; while(off<len){ssize_t r=read(fd,buf+off,len-off); if(r<=0){close(fd);return -1;} off+=(size_t)r;} close(fd); return 0;}
void secure_zero(void *p,size_t n){volatile uint8_t *v=p; while(n--)*v++=0;}
int read_file_all(const char *path,uint8_t **out,size_t *out_len){FILE*f=fopen(path,"rb"); if(!f)return -1; if(fseek(f,0,SEEK_END)!=0){fclose(f);return -1;} long n=ftell(f); if(n<0){fclose(f);return -1;} rewind(f); uint8_t*b=malloc((size_t)n? (size_t)n:1); if(!b){fclose(f);return -1;} if(fread(b,1,(size_t)n,f)!=(size_t)n){free(b);fclose(f);return -1;} fclose(f); *out=b; *out_len=(size_t)n; return 0;}
int write_file_bytes(const char *path,const uint8_t *buf,size_t len){FILE*f=fopen(path,"wb"); if(!f)return -1; int ok=fwrite(buf,1,len,f)==len; fclose(f); return ok?0:-1;}
int daemonize_process(const char *log_path){pid_t p=fork(); if(p<0)return -1; if(p>0)_exit(0); if(setsid()<0)return -1; p=fork(); if(p<0)return -1; if(p>0)_exit(0); if(chdir("/")!=0)return -1; int nullfd=open("/dev/null",O_RDONLY); int outfd=open(log_path?log_path:"/dev/null",O_WRONLY|O_CREAT|O_APPEND,0644); if(nullfd>=0)dup2(nullfd,STDIN_FILENO); if(outfd>=0){dup2(outfd,STDOUT_FILENO);dup2(outfd,STDERR_FILENO);} if(nullfd>2)close(nullfd); if(outfd>2)close(outfd); return 0;}
