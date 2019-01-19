#include "fe25519.h"

// tmp MUST != out
// in MAY == out
void fe25519_batchinvert(fe25519 *out[],fe25519 tmp[],fe25519 * const in[], size_t num)
{
  fe25519 acc;
  fe25519 tmpacc;
  size_t i;

  fe25519_setint(&acc,1);

  for (i = 0;i < num;++i) {
    tmp[i] = acc;
    fe25519_mul(&acc,&acc,in[i]);
  }

  fe25519_invert(&acc,&acc);

  i = num;
  while (i--) {
    fe25519_mul(&tmpacc,&acc,in[i]);
    fe25519_mul(out[i],&acc,&tmp[i]);
    acc = tmpacc;
  }
}
