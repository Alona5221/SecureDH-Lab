#include "protocol.h"
#include <stdio.h>
#include <string.h>
int main(void){client_hello_t ch={1,1,0x1122334455667788ULL,{0}};for(int i=0;i<16;i++)ch.nonce[i]=(uint8_t)i;uint8_t b[28];client_hello_t out;encode_client_hello(b,&ch);if(decode_client_hello(b,sizeof b,&out))return 1;if(out.version!=ch.version||out.mode!=ch.mode||out.dh_public!=ch.dh_public||memcmp(out.nonce,ch.nonce,16))return 2;puts("protocol encode/decode tests passed");return 0;}
