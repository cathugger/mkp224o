#ifndef INDEX_HEAP_H
#define INDEX_HEAP_H

#include "sc25519.h"

#define heap_init                CRYPTO_NAMESPACE(batch_heap_init)
#define heap_extend              CRYPTO_NAMESPACE(batch_heap_extend)
#define heap_pop                 CRYPTO_NAMESPACE(batch_heap_pop)
#define heap_push                CRYPTO_NAMESPACE(batch_heap_push)
#define heap_get2max             CRYPTO_NAMESPACE(batch_heap_get2max)
#define heap_rootreplaced        CRYPTO_NAMESPACE(batch_heap_rootreplaced)
#define heap_rootreplaced_3limbs CRYPTO_NAMESPACE(batch_heap_rootreplaced_3limbs)
#define heap_rootreplaced_2limbs CRYPTO_NAMESPACE(batch_heap_rootreplaced_2limbs)
#define heap_rootreplaced_1limb  CRYPTO_NAMESPACE(batch_heap_rootreplaced_1limb)

void heap_init(unsigned long long *h, unsigned long long hlen, sc25519 *scalars);

void heap_extend(unsigned long long *h, unsigned long long oldlen, unsigned long long newlen, sc25519 *scalars);

unsigned long long heap_pop(unsigned long long *h, unsigned long long *hlen, sc25519 *scalars);

void heap_push(unsigned long long *h, unsigned long long *hlen, unsigned long long elem, sc25519 *scalars);

void heap_get2max(unsigned long long *h, unsigned long long *max1, unsigned long long *max2, sc25519 *scalars);

void heap_rootreplaced(unsigned long long *h, unsigned long long hlen, sc25519 *scalars);
void heap_rootreplaced_3limbs(unsigned long long *h, unsigned long long hlen, sc25519 *scalars);
void heap_rootreplaced_2limbs(unsigned long long *h, unsigned long long hlen, sc25519 *scalars);
void heap_rootreplaced_1limb(unsigned long long *h, unsigned long long hlen, sc25519 *scalars);

#endif
