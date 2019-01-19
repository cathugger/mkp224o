#include "ge.h"

// inz is ge_p3.Z pointer array. contents to .Zs will be overwritten
// NOTE: leaves in unfinished state
void ge_p3_batchtobytes_destructive_1(bytes32 out[],ge_p3 in[],fe *inz[],fe tmp[],size_t num)
{
  fe y;

  fe_batchinvert(inz,tmp,inz,num);

  for (size_t i = 0;i < num;++i) {
    fe_mul(y,in[i].Y,in[i].Z);
    fe_tobytes(out[i],y);
  }
}

void ge_p3_batchtobytes_destructive_finish(bytes32 out,ge_p3 *unf)
{
  fe x;
  // z of unfinished is inverted
  fe_mul(x,unf->X,unf->Z);
  out[31] ^= fe_isnegative(x) << 7;
}
