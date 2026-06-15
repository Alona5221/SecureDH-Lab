#include "common.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc,char**argv){const char*out="psk.bin";int bytes=32;static struct option opts[]={{"psk-file",1,0,'p'},{"bytes",1,0,'b'},{0,0,0,0}};int c;while((c=getopt_long(argc,argv,"",opts,NULL))!=-1){if(c=='p')out=optarg;else if(c=='b')bytes=atoi(optarg);}uint8_t*b=malloc(bytes);if(!b||random_bytes(b,bytes)||write_file_bytes(out,b,bytes)){perror("keygen");return 1;}printf("wrote %d random bytes to %s\n",bytes,out);free(b);return 0;}
