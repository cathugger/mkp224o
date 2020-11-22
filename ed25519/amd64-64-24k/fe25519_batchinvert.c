#include "fe25519.h"

// tmp MUST != out or in
// in MAY == out
void fe25519_batchinvert(fe25519 *out, const fe25519 *in, fe25519 *tmp, size_t num, size_t offset)
{
  fe25519 acc;
  fe25519 tmpacc;
  size_t i;
  const fe25519 *inp;
  fe25519 *outp;

  fe25519_setint(&acc,1);

  inp = in;
  for (i = 0;i < num;++i) {
    tmp[i] = acc;
    fe25519_mul(&acc,&acc,inp);
    inp = (const fe25519 *)((const char *)inp + offset);
  }

  fe25519_invert(&acc,&acc);

  i = num;
  inp = (const fe25519 *)((const char *)in + offset * num);
  outp = (fe25519 *)((char *)out + offset * num);
  while (i--) {
    inp = (const fe25519 *)((const char *)inp - offset);
    outp = (fe25519 *)((char *)outp - offset);
    fe25519_mul(&tmpacc,&acc,inp);
    fe25519_mul(outp,&acc,&tmp[i]);
    acc = tmpacc;
  }
}
