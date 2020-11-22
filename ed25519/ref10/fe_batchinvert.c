#include "fe.h"

// tmp MUST != out or in
// in MAY == out
void fe_batchinvert(fe *out,fe *in,fe *tmp,size_t num,size_t shift)
{
  fe acc;
  fe tmpacc;
  size_t i;
  fe *inp;
  fe *outp;

  fe_1(acc);

  inp = in;
  for (i = 0;i < num;++i) {
    fe_copy(tmp[i],acc);
    fe_mul(acc,acc,*inp);
    inp = (fe *)((char *)inp + shift);
  }

  fe_invert(acc,acc);

  i = num;
  inp = (fe *)((char *)in + shift * num);
  outp = (fe *)((char *)out + shift * num);
  while (i--) {
    inp = (fe *)((char *)inp - shift);
    outp = (fe *)((char *)outp - shift);
    fe_mul(tmpacc,acc,*inp);
    fe_mul(*outp,acc,tmp[i]);
    fe_copy(acc,tmpacc);
  }
}
