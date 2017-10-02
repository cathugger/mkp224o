#define ED25519_SEEDBYTES      32
#define ED25519_SECRETKEYBYTES 64
#define ED25519_PUBLICKEYBYTES 32

#ifdef ED25519_ref10
#include "ref10/ed25519.h"
#define ed25519_seckey        ed25519_ref10_seckey
#define ed25519_seckey_expand ed25519_ref10_seckey_expand
#define ed25519_pubkey        ed25519_ref10_pubkey
#define ed25519_keygen        ed25519_ref10_keygen
#include "ref10/ge.h"

/* The basepoint multiplied by 8. */
static const ge_cached ge_eightpoint = {
  /* YplusX */
  {
    48496028, -16430416, 15164263, 11885335, 60784617, -4866353, 46481863,
    -2771805, 9708580, 2387263
  },
  /* YmunusX */
  {
    -10173472, -5540046, 21277639, 4080693, 1932823, -14916249, -9515873,
    -21787995, -36575460, 29827857
  },
  /* Z */
  {
    25143927, -10256223, -3515585, 5715072, 19432778, -14905909, 22462083,
    -8862871, 13226552, 743677
  },
  /* T2d */
  {
    -784818, -8208065, -28479270, 5551579, 15746872, 4911053, 19117091,
    11267669, -24569594, 14624995
  }
};
inline static void ge_initeightpoint() {}
#endif

#ifdef ED25519_amd64_51_30k
#include "amd64-51-30k/ed25519.h"
#define ed25519_seckey        ed25519_amd64_51_30k_seckey
#define ed25519_seckey_expand ed25519_amd64_51_30k_seckey_expand
#define ed25519_pubkey        ed25519_amd64_51_30k_pubkey
#define ed25519_keygen        ed25519_amd64_51_30k_keygen
#include "amd64-51-30k/ge25519.h"
#define ge_p1p1       ge25519_p1p1
#define ge_p3         ge25519_p3
#define ge_cached     ge25519_pniels
#define ge_p1p1_to_p3 ge25519_p1p1_to_p3
#define ge_p3_tobytes ge25519_pack
#define ge_add        ge25519_pnielsadd_p1p1

static inline void ge_scalarmult_base(ge_p3 *gepk,const unsigned char *sk)
{
	sc25519 scsk;

	sc25519_from32bytes(&scsk,sk);
	ge25519_scalarmult_base(gepk,&scsk);
}

/* The basepoint multiplied by 8. */
static const ge25519_pniels ge_eightpoint = {
	// ysubx
	{{ 1880013609944032, 273850692840390, 1250787290086935, 789632210881694, 2001713562248987 }},
	// xaddy
	{{ 1149173309373852, 797611345273702, 1925224452816873, 2065787175387590, 160206517707811 }},
	// z
	{{ 1563516364368503, 383531986082622, 1251481213240650, 1657022631558786, 49907331879479 }},
	// t2d
	{{ 1700965895112270, 372560131616985, 329575203620664, 756160485635107, 981466775886086 }},
};
inline static void ge_initeightpoint() {}
#endif

#ifdef ED25519_amd64_64_24k
#include "amd64-64-24k/ed25519.h"
#define ed25519_seckey        ed25519_amd64_64_seckey
#define ed25519_seckey_expand ed25519_amd64_64_seckey_expand
#define ed25519_pubkey        ed25519_amd64_64_pubkey
#define ed25519_keygen        ed25519_amd64_64_keygen
#include "amd64-64-24k/ge25519.h"
#define ge_p1p1       ge25519_p1p1
#define ge_p3         ge25519_p3
#define ge_cached     ge25519_pniels
#define ge_p1p1_to_p3 ge25519_p1p1_to_p3
#define ge_p3_tobytes ge25519_pack
#define ge_add        ge25519_pnielsadd_p1p1

static inline void ge_scalarmult_base(ge_p3 *gepk,const unsigned char *sk)
{
	sc25519 scsk;

	sc25519_from32bytes(&scsk,sk);
	ge25519_scalarmult_base(gepk,&scsk);
}

/* The basepoint multiplied by 8. */
static const ge25519_pniels ge_eightpoint = {
	// ysubx
	{{ 6788804652057281504U, 531290374162262565U, 6135835192563885415U, 8199018750971852188U }},
	// xaddy
	{{ 1960215011215539612U, 16708348392717346619U, 11897818088205565647U, 656205896531197613U }},
	// z
	{{ 15705615417005288055U, 5341641389565279826U, 1966574939768917451U, 204420431378348998U }},
	// t2d
	{{ 9713713562319586894U, 4328467261753610859U, 8262494979546083277U, 4020087914029409631U }},
};
inline static void ge_initeightpoint() {}
#endif

#ifdef ED25519_donna
#define ED25519_CUSTOMRANDOM
#define ED25519_CUSTOMHASH
#include <sodium/crypto_hash_sha512.h>
#include "ed25519-donna/ed25519-donna.h"

static int ed25519_seckey_expand(unsigned char *sk,const unsigned char *seed)
{
	crypto_hash_sha512(sk,seed,32);
	sk[0] &= 248;
	sk[31] &= 127;
	sk[31] |= 64;

	return 0;
}

static int ed25519_seckey(unsigned char *sk)
{
	unsigned char seed[32];

	randombytes(seed,32);
	return ed25519_seckey_expand(sk,seed);
}

static int ed25519_pubkey(unsigned char *pk,const unsigned char *sk)
{
	bignum256modm a;
	ge25519 ALIGN(16) A;

	expand256_modm(a,sk,32);
	ge25519_scalarmult_base_niels(&A,ge25519_niels_base_multiples,a);
	ge25519_pack(pk,&A);

	return 0;
}


static int ed25519_keypair(unsigned char *pk,unsigned char *sk)
{
	ed25519_seckey(sk);
	ed25519_pubkey(pk,sk);

	return 0;
}
// hacky, but works for current stuff in main.c
#define ge_p1p1       ge25519_p1p1 ALIGN(16)
#define ge_p3         ge25519 ALIGN(16)
#define ge_cached     ge25519_pniels ALIGN(16)

#define ge_p1p1_to_p3 ge25519_p1p1_to_full
#define ge_p3_tobytes ge25519_pack

DONNA_INLINE static void ge_add(ge25519_p1p1 *r,const ge25519 *p,const ge25519_pniels *q)
{
	ge25519_pnielsadd_p1p1(r,p,q,0);
}

DONNA_INLINE static void ge_scalarmult_base(ge25519 *A,const unsigned char *sk)
{
	bignum256modm ALIGN(16) a;
	expand256_modm(a,sk,32);
	ge25519_scalarmult_base_niels(A,ge25519_niels_base_multiples,a);
}

static ge25519_pniels ALIGN(16) ge_eightpoint;
// portable representation of (basepoint * 8)
static u8 fe_ysubx[32] = {
	0xE0,0xC3,0x64,0xC7,0xDC,0xAD,0x36,0x5E,
	0x25,0xAA,0x86,0xC8,0xC7,0x85,0x5F,0x07,
	0x67,0x65,0x1C,0x3D,0x99,0xDD,0x26,0x55,
	0x9C,0xB5,0x71,0x1E,0x1D,0xC4,0xC8,0x71,
};
static u8 fe_xaddy[32] = {
	0x9C,0xFD,0xE3,0xC2,0x2A,0x15,0x34,0x1B,
	0x3B,0xE7,0x62,0xAB,0x56,0xFA,0xDF,0xE7,
	0xCF,0xBE,0xB5,0x8D,0x83,0x8A,0x1D,0xA5,
	0xAD,0x3E,0x42,0x42,0xC9,0x4F,0x1B,0x09,
};
static u8 fe_z[32] = {
	0x77,0xAA,0x7F,0x85,0x02,0x8E,0xF5,0xD9,
	0x52,0xFE,0x8F,0xE6,0x8A,0x52,0x21,0x4A,
	0xCB,0x8D,0x1C,0x05,0x7D,0xAD,0x4A,0x1B,
	0xC6,0x7B,0x23,0x9D,0x4C,0x3F,0xD6,0x02,
};
static u8 fe_t2d[32] = {
	0x4E,0x06,0xF4,0xFB,0x04,0x0B,0xCE,0x86,
	0x6B,0x52,0xBB,0x96,0x0A,0xCE,0x11,0x3C,
	0xCD,0xEF,0x4A,0x46,0x68,0x47,0xAA,0x72,
	0x5F,0x65,0x90,0x91,0xA8,0x38,0xCA,0x37,
};

// initialize from packed representation
static void ge_initeightpoint()
{
	memset(&ge_eightpoint,0,sizeof(ge_eightpoint));
	curve25519_expand(ge_eightpoint.ysubx,fe_ysubx);
	curve25519_expand(ge_eightpoint.xaddy,fe_xaddy);
	curve25519_expand(ge_eightpoint.z,fe_z);
	curve25519_expand(ge_eightpoint.t2d,fe_t2d);
}

#endif
