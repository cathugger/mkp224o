#include "ge.h"

// inz is ge_p3.Z pointer array. contents to .Zs will be overwritten
void ge_p3_batchtobytes_destructive(bytes32 out[],const ge_p3 in[],fe *inz[],fe tmp[],size_t num)
{
  fe x;
  fe y;

  fe_batchinvert(inz,tmp,inz,num);

  for (size_t i = 0;i < num;++i) {
    fe_mul(x,in[i].X,*inz[i]);
    fe_mul(y,in[i].Y,*inz[i]);
    fe_tobytes(out[i],y);
    out[i][31] ^= fe_isnegative(x) << 7;
  }
}
