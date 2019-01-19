#include "fe.h"

// tmp MUST != out
// in MAY == out
void fe_batchinvert(fe out[],fe tmp[],const fe in[], size_t num)
{
  fe acc;
  fe tmpacc;
  size_t i;

  fe_1(acc);

  for (i = 0;i < num;++i) {
    fe_copy(tmp[i],acc);
    fe_mul(acc,acc,in[i]);
  }

  fe_invert(acc,acc);

  i = num;
  while (i--) {
    fe_mul(tmpacc,acc,in[i]);
    fe_mul(out[i],acc,tmp[i]);
    fe_copy(acc,tmpacc);
  }
}
