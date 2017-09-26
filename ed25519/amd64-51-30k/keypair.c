#include <string.h>
#include "crypto_sign.h"
#include "crypto_hash_sha512.h"
#include "randombytes.h"
#include "ge25519.h"

int crypto_sign_seckey_expand(unsigned char *sk,const unsigned char *seed)
{
  crypto_hash_sha512(sk,seed,32);
  sk[0] &= 248;
  sk[31] &= 63;
  sk[31] |= 64;

  return 0;
}

int crypto_sign_seckey(unsigned char *sk)
{
  unsigned char seed[32];

  if (randombytes(seed,32) < 0)
    return -1;

  crypto_sign_seckey_expand(sk,seed);

  return 0;
}

int crypto_sign_pubkey(unsigned char *pk,const unsigned char *sk)
{
  sc25519 scsk;
  ge25519_p3 gepk;

  sc25519_from32bytes(&scsk,sk);
  ge25519_scalarmult_base(&gepk,&scsk);
  ge25519_pack(pk,&gepk);

  return 0;
}

int crypto_sign_keypair(unsigned char *pk,unsigned char *sk)
{
  crypto_sign_seckey(sk);
  crypto_sign_pubkey(pk,sk);
  return 0;
}
