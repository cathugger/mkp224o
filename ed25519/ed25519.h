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
#endif
