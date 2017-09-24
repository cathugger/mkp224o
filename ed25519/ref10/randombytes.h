#include <sodium/randombytes.h>
#define randombytes(b,n) \
  (randombytes(b,n), 0)
