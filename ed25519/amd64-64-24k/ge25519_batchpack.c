#include "fe25519.h"
#include "ge25519.h"

// NOTE: leaves in unfinished state
void ge25519_batchpack_destructive_1(bytes32 *out, ge25519_p3 *in, fe25519 *tmp, size_t num)
{
  fe25519 ty;

  fe25519_batchinvert(&in->z, &in->z, tmp, num, sizeof(ge25519_p3));

  for (size_t i = 0; i < num; ++i) {
    fe25519_mul(&ty, &in[i].y, &in[i].z);
    fe25519_pack(out[i], &ty);
  }
}

void ge25519_batchpack_destructive_finish(bytes32 out, ge25519_p3 *unf)
{
  fe25519 tx;
  // z of unfinished is inverted
  fe25519_mul(&tx, &unf->x, &unf->z);
  out[31] ^= fe25519_getparity(&tx) << 7;
}
