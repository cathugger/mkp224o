
#undef ed25519_seckey
#undef ed25519_seckey_expand
#undef ed25519_pubkey
#undef ed25519_keygen

#undef ge_eightpoint
#undef ge_initeightpoint

#undef ge_add
#undef ge_p3_batchtobytes_destructive_1
#undef ge_p3_batchtobytes_destructive_finish
#undef ge_scalarmult_base


#ifdef ED25519_ref10

#undef ge_frombytes_negate_vartime
#undef ge_tobytes
#undef ge_p3_tobytes
#undef ge_p2_0
#undef ge_p3_0
#undef ge_precomp_0
#undef ge_p3_to_p2
#undef ge_p3_to_cached
#undef ge_p1p1_to_p2
#undef ge_p1p1_to_p3
#undef ge_p2_dbl
#undef ge_p3_dbl
#undef ge_madd
#undef ge_msub
#undef ge_sub
#undef ge_scalarmult_base
#undef ge_double_scalarmult_vartime

#endif


#if defined(ED25519_amd64_51_30k) || defined(ED25519_amd64_64_24k)

#undef ge25519
#undef ge25519_base
#undef ge25519_unpackneg_vartime
#undef ge25519_pack
#undef ge25519_isneutral_vartime
#undef ge25519_add
#undef ge25519_double
#undef ge25519_double_scalarmult_vartime
#undef ge25519_multi_scalarmult_vartime
#undef ge25519_scalarmult_base
#undef ge25519_p1p1_to_p2
#undef ge25519_p1p1_to_p3
#undef ge25519_p1p1_to_pniels
#undef ge25519_add_p1p1
#undef ge25519_dbl_p1p1
#undef choose_t
#undef ge25519_nielsadd2
#undef ge25519_nielsadd_p1p1
#undef ge25519_pnielsadd_p1p1
#undef ge25519_p3

#undef fe
#undef ge_p1p1
#undef ge_p3
#undef ge_p1p1_to_p3
#undef ge_p3_tobytes

#endif


#ifdef ED25519_donna

#undef fe_ysubx
#undef fe_xaddy
#undef fe_z
#undef fe_t2d

#undef fe
#undef ge_p1p1
#undef ge_p3
#undef ge_p1p1_to_p3
#undef ge_p3_tobytes

#endif
