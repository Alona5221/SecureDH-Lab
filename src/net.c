#include "net.h"
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
int send_all(int fd,const void*buf,size_t len){const char*p=buf;while(len){ssize_t n=send(fd,p,len,0);if(n<=0)return -1;p+=n;len-=n;}return 0;}
int recv_all(int fd,void*buf,size_t len){char*p=buf;while(len){ssize_t n=recv(fd,p,len,0);if(n<=0)return -1;p+=n;len-=n;}return 0;}
int tcp_listen(const char*host,uint16_t port,int backlog){int fd=socket(AF_INET,SOCK_STREAM,0); if(fd<0)return -1; int yes=1; setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes); struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_port=htons(port); if(inet_pton(AF_INET,host,&a.sin_addr)!=1){close(fd);return -1;} if(bind(fd,(struct sockaddr*)&a,sizeof a)<0||listen(fd,backlog)<0){close(fd);return -1;} return fd;}
int tcp_connect(const char*host,uint16_t port){int fd=socket(AF_INET,SOCK_STREAM,0); if(fd<0)return -1; struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_port=htons(port); if(inet_pton(AF_INET,host,&a.sin_addr)!=1){struct hostent*h=gethostbyname(host); if(!h){close(fd);return -1;} memcpy(&a.sin_addr,h->h_addr_list[0],4);} if(connect(fd,(struct sockaddr*)&a,sizeof a)<0){close(fd);return -1;} return fd;}
