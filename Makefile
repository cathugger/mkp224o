
CC= gcc
CFLAGS= -O3 -march=native -Wall
#CFLAGS= -O0 -g3 -fsanitize=address
MV= mv

ED25519OBJ= $(patsubst %.c,%.o,$(wildcard ed25519/ref10/*.c))

MAINOBJ= \
	main.o \
	base32_to.o \
	base32_from.o \
	$(ED25519OBJ) \
	keccak.o

TEST_BASE32OBJ= \
	test_base32.o \
	base32_to.o \
	base32_from.o

TEST_BASE16OBJ= \
	test_base16.o \
	base16_to.o \
	base16_from.o

TEST_ED25519OBJ= \
	test_ed25519.o \
	base16_to.o \
	base16_from.o \
	$(ED25519OBJ)

MAINLIB= -lsodium -lpthread
TEST_ED25519LIB= -lsodium

EXE= mkp224o test_base32 test_base16 test_ed25519

default: mkp224o

all: $(EXE)

mkp224o: $(MAINOBJ)
	$(CC) $(CFLAGS) -o $@.tmp $^ $(MAINLIB) && $(MV) $@.tmp $@

test_base32: $(TEST_BASE32OBJ)
	$(CC) $(CFLAGS) -o $@.tmp $^ && $(MV) $@.tmp $@

test_base16: $(TEST_BASE16OBJ)
	$(CC) $(CFLAGS) -o $@.tmp $^ && $(MV) $@.tmp $@

test_ed25519: $(TEST_ED25519OBJ)
	$(CC) $(CFLAGS) -o $@.tmp $^ $(TEST_ED25519LIB) && $(MV) $@.tmp $@

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@.tmp $< && $(MV) $@.tmp $@

clean:
	$(RM) $(MAINOBJ)
	$(RM) $(TEST_BASE16OBJ)
	$(RM) $(TEST_BASE32OBJ)
	$(RM) $(TEST_ED25519OBJ)
	$(RM) $(EXE)

depend:
	makedepend -Y -- $(CFLAGS) -- $(MAINOBJ:.o=.c) $(TEST_BASE16OBJ:.o=.c) $(TEST_BASE32OBJ:.o=.c) $(TEST_ED25519OBJ:.o=.c)

# DO NOT DELETE THIS LINE

main.o: ed25519/ref10/ed25519_ref10.h ed25519/ref10/ge.h ed25519/ref10/fe.h
main.o: ed25519/ref10/crypto_int32.h types.h vec.h base32.h keccak.h
base32_to.o: types.h base32.h
base32_from.o: types.h base32.h
ed25519/ref10/sc_reduce.o: ed25519/ref10/sc.h ed25519/ref10/crypto_int64.h
ed25519/ref10/sc_reduce.o: ed25519/ref10/crypto_uint32.h
ed25519/ref10/sc_reduce.o: ed25519/ref10/crypto_uint64.h
ed25519/ref10/ge_msub.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_msub.o: ed25519/ref10/crypto_int32.h ed25519/ref10/ge_msub.h
ed25519/ref10/fe_copy.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_isnegative.o: ed25519/ref10/fe.h
ed25519/ref10/fe_isnegative.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_tobytes.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p3_tobytes.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p3_tobytes.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_0.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p3_0.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p3_0.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_double_scalarmult.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_double_scalarmult.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_double_scalarmult.o: ed25519/ref10/base2.h
ed25519/ref10/ge_p1p1_to_p3.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p1p1_to_p3.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p3_to_p2.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p3_to_p2.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_sub.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_sub.o: ed25519/ref10/crypto_int32.h ed25519/ref10/ge_sub.h
ed25519/ref10/ge_madd.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_madd.o: ed25519/ref10/crypto_int32.h ed25519/ref10/ge_madd.h
ed25519/ref10/fe_frombytes.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_frombytes.o: ed25519/ref10/crypto_int64.h
ed25519/ref10/fe_frombytes.o: ed25519/ref10/crypto_uint64.h
ed25519/ref10/ge_scalarmult_base.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_scalarmult_base.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_scalarmult_base.o: ed25519/ref10/crypto_uint32.h
ed25519/ref10/ge_scalarmult_base.o: ed25519/ref10/base.h
ed25519/ref10/fe_neg.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p2_dbl.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p2_dbl.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p2_dbl.o: ed25519/ref10/ge_p2_dbl.h
ed25519/ref10/fe_1.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/sign.o: ed25519/ref10/crypto_sign.h
ed25519/ref10/sign.o: ed25519/ref10/ed25519_ref10.h
ed25519/ref10/sign.o: ed25519/ref10/crypto_hash_sha512.h ed25519/ref10/ge.h
ed25519/ref10/sign.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/sign.o: ed25519/ref10/sc.h
ed25519/ref10/fe_cmov.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/open.o: ed25519/ref10/crypto_sign.h
ed25519/ref10/open.o: ed25519/ref10/ed25519_ref10.h
ed25519/ref10/open.o: ed25519/ref10/crypto_hash_sha512.h
ed25519/ref10/open.o: ed25519/ref10/crypto_verify_32.h ed25519/ref10/ge.h
ed25519/ref10/open.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/open.o: ed25519/ref10/sc.h
ed25519/ref10/ge_add.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_add.o: ed25519/ref10/crypto_int32.h ed25519/ref10/ge_add.h
ed25519/ref10/fe_sub.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_pow22523.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_pow22523.o: ed25519/ref10/pow22523.h
ed25519/ref10/fe_sq2.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_sq2.o: ed25519/ref10/crypto_int64.h
ed25519/ref10/fe_mul.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_mul.o: ed25519/ref10/crypto_int64.h
ed25519/ref10/ge_p2_0.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p2_0.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/keypair.o: ed25519/ref10/randombytes.h
ed25519/ref10/keypair.o: ed25519/ref10/crypto_sign.h
ed25519/ref10/keypair.o: ed25519/ref10/ed25519_ref10.h
ed25519/ref10/keypair.o: ed25519/ref10/crypto_hash_sha512.h
ed25519/ref10/keypair.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/keypair.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_isnonzero.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_isnonzero.o: ed25519/ref10/crypto_verify_32.h
ed25519/ref10/ge_p1p1_to_p2.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p1p1_to_p2.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_sq.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_sq.o: ed25519/ref10/crypto_int64.h
ed25519/ref10/fe_add.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p3_to_cached.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p3_to_cached.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p3_to_cached.o: ed25519/ref10/d2.h
ed25519/ref10/ge_tobytes.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_tobytes.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/sc_muladd.o: ed25519/ref10/sc.h ed25519/ref10/crypto_int64.h
ed25519/ref10/sc_muladd.o: ed25519/ref10/crypto_uint32.h
ed25519/ref10/sc_muladd.o: ed25519/ref10/crypto_uint64.h
ed25519/ref10/ge_p3_dbl.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p3_dbl.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_frombytes.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_frombytes.o: ed25519/ref10/crypto_int32.h ed25519/ref10/d.h
ed25519/ref10/ge_frombytes.o: ed25519/ref10/sqrtm1.h
ed25519/ref10/fe_invert.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_invert.o: ed25519/ref10/pow225521.h
ed25519/ref10/ge_precomp_0.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_precomp_0.o: ed25519/ref10/crypto_int32.h
keccak.o: types.h keccak.h
test_base16.o: types.h base16.h
base16_to.o: types.h base16.h
base16_from.o: types.h base16.h
test_base32.o: types.h base32.h
base32_to.o: types.h base32.h
base32_from.o: types.h base32.h
test_ed25519.o: types.h base16.h ed25519/ref10/ed25519_ref10.h
base16_to.o: types.h base16.h
base16_from.o: types.h base16.h
ed25519/ref10/sc_reduce.o: ed25519/ref10/sc.h ed25519/ref10/crypto_int64.h
ed25519/ref10/sc_reduce.o: ed25519/ref10/crypto_uint32.h
ed25519/ref10/sc_reduce.o: ed25519/ref10/crypto_uint64.h
ed25519/ref10/ge_msub.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_msub.o: ed25519/ref10/crypto_int32.h ed25519/ref10/ge_msub.h
ed25519/ref10/fe_copy.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_isnegative.o: ed25519/ref10/fe.h
ed25519/ref10/fe_isnegative.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_tobytes.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p3_tobytes.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p3_tobytes.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_0.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p3_0.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p3_0.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_double_scalarmult.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_double_scalarmult.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_double_scalarmult.o: ed25519/ref10/base2.h
ed25519/ref10/ge_p1p1_to_p3.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p1p1_to_p3.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p3_to_p2.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p3_to_p2.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_sub.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_sub.o: ed25519/ref10/crypto_int32.h ed25519/ref10/ge_sub.h
ed25519/ref10/ge_madd.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_madd.o: ed25519/ref10/crypto_int32.h ed25519/ref10/ge_madd.h
ed25519/ref10/fe_frombytes.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_frombytes.o: ed25519/ref10/crypto_int64.h
ed25519/ref10/fe_frombytes.o: ed25519/ref10/crypto_uint64.h
ed25519/ref10/ge_scalarmult_base.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_scalarmult_base.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_scalarmult_base.o: ed25519/ref10/crypto_uint32.h
ed25519/ref10/ge_scalarmult_base.o: ed25519/ref10/base.h
ed25519/ref10/fe_neg.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p2_dbl.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p2_dbl.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p2_dbl.o: ed25519/ref10/ge_p2_dbl.h
ed25519/ref10/fe_1.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/sign.o: ed25519/ref10/crypto_sign.h
ed25519/ref10/sign.o: ed25519/ref10/ed25519_ref10.h
ed25519/ref10/sign.o: ed25519/ref10/crypto_hash_sha512.h ed25519/ref10/ge.h
ed25519/ref10/sign.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/sign.o: ed25519/ref10/sc.h
ed25519/ref10/fe_cmov.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/open.o: ed25519/ref10/crypto_sign.h
ed25519/ref10/open.o: ed25519/ref10/ed25519_ref10.h
ed25519/ref10/open.o: ed25519/ref10/crypto_hash_sha512.h
ed25519/ref10/open.o: ed25519/ref10/crypto_verify_32.h ed25519/ref10/ge.h
ed25519/ref10/open.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/open.o: ed25519/ref10/sc.h
ed25519/ref10/ge_add.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_add.o: ed25519/ref10/crypto_int32.h ed25519/ref10/ge_add.h
ed25519/ref10/fe_sub.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_pow22523.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_pow22523.o: ed25519/ref10/pow22523.h
ed25519/ref10/fe_sq2.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_sq2.o: ed25519/ref10/crypto_int64.h
ed25519/ref10/fe_mul.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_mul.o: ed25519/ref10/crypto_int64.h
ed25519/ref10/ge_p2_0.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p2_0.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/keypair.o: ed25519/ref10/randombytes.h
ed25519/ref10/keypair.o: ed25519/ref10/crypto_sign.h
ed25519/ref10/keypair.o: ed25519/ref10/ed25519_ref10.h
ed25519/ref10/keypair.o: ed25519/ref10/crypto_hash_sha512.h
ed25519/ref10/keypair.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/keypair.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_isnonzero.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_isnonzero.o: ed25519/ref10/crypto_verify_32.h
ed25519/ref10/ge_p1p1_to_p2.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p1p1_to_p2.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_sq.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_sq.o: ed25519/ref10/crypto_int64.h
ed25519/ref10/fe_add.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p3_to_cached.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p3_to_cached.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_p3_to_cached.o: ed25519/ref10/d2.h
ed25519/ref10/ge_tobytes.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_tobytes.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/sc_muladd.o: ed25519/ref10/sc.h ed25519/ref10/crypto_int64.h
ed25519/ref10/sc_muladd.o: ed25519/ref10/crypto_uint32.h
ed25519/ref10/sc_muladd.o: ed25519/ref10/crypto_uint64.h
ed25519/ref10/ge_p3_dbl.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_p3_dbl.o: ed25519/ref10/crypto_int32.h
ed25519/ref10/ge_frombytes.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_frombytes.o: ed25519/ref10/crypto_int32.h ed25519/ref10/d.h
ed25519/ref10/ge_frombytes.o: ed25519/ref10/sqrtm1.h
ed25519/ref10/fe_invert.o: ed25519/ref10/fe.h ed25519/ref10/crypto_int32.h
ed25519/ref10/fe_invert.o: ed25519/ref10/pow225521.h
ed25519/ref10/ge_precomp_0.o: ed25519/ref10/ge.h ed25519/ref10/fe.h
ed25519/ref10/ge_precomp_0.o: ed25519/ref10/crypto_int32.h
