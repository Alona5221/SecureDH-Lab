#ifndef KDF_H
#define KDF_H
#include <stdint.h>
void derive_session_key(uint64_t shared,const uint8_t client_nonce[16],const uint8_t server_nonce[16],const char *label,uint8_t key[32]);
#endif
