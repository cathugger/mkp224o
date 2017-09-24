#include <sodium/utils.h>

#define crypto_verify_32(a,b) \
  (!sodium_memcmp((a), (b), 32))
