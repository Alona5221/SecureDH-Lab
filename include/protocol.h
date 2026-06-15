#ifndef PROTOCOL_H
#define PROTOCOL_H
#include <stdint.h>
#include <stddef.h>
#define MSG_CLIENT_HELLO 1
#define MSG_SERVER_HELLO 2
#define MSG_CLIENT_AUTH 3
#define MSG_DATA 4
#define MSG_REKEY 5
#define MSG_ERROR 6
typedef struct { uint32_t magic; uint16_t version; uint16_t type; uint32_t flags; uint32_t seq; uint32_t length; } msg_header_t;
typedef struct { uint16_t version; uint16_t mode; uint64_t dh_public; uint8_t nonce[16]; } client_hello_t;
typedef struct { uint16_t version; uint64_t dh_public; uint8_t nonce[16]; uint8_t auth[32]; } server_hello_t;
int send_msg(int fd,uint16_t type,uint32_t flags,uint32_t seq,const uint8_t *payload,uint32_t len);
int recv_msg(int fd,uint16_t *type,uint32_t *flags,uint32_t *seq,uint8_t **payload,uint32_t *len);
void put_u16(uint8_t *p,uint16_t v); void put_u64(uint8_t *p,uint64_t v); uint16_t get_u16(const uint8_t *p); uint64_t get_u64(const uint8_t *p);
void encode_client_hello(uint8_t out[28],const client_hello_t *ch); int decode_client_hello(const uint8_t *buf,size_t len,client_hello_t *ch);
void encode_server_hello_without_auth(uint8_t out[26],const server_hello_t *sh); void encode_server_hello(uint8_t out[58],const server_hello_t *sh); int decode_server_hello(const uint8_t *buf,size_t len,server_hello_t *sh);
#endif
