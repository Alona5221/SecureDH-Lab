#ifndef DH_H
#define DH_H
#include <stdint.h>
#define DH_P 2305843009213693951ULL
#define DH_G 5ULL
uint64_t modexp_u64(uint64_t base, uint64_t exp, uint64_t mod);
uint64_t dh_generate_private(void);
uint64_t dh_compute_public(uint64_t priv);
uint64_t dh_compute_shared(uint64_t peer_pub, uint64_t priv);
#endif
