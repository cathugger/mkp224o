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
#endif
