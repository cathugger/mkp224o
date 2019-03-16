
#ifdef PASSPHRASE
void *worker_fast_pass(void *task)
{
	union pubonionunion pubonion;
	u8 * const pk = &pubonion.raw[PKPREFIX_SIZE];
	u8 secret[SKPREFIX_SIZE + SECRET_LEN];
	u8 * const sk = &secret[SKPREFIX_SIZE];
	u8 seed[SEED_LEN];
	u8 hashsrc[checksumstrlen + PUBLIC_LEN + 1];
	u8 wpk[PUBLIC_LEN + 1];
	ge_p3 ge_public;
	char *sname;

	size_t counter,oldcounter;
	size_t i;

#ifdef STATISTICS
	struct statstruct *st = (struct statstruct *)task;
#else
	(void) task;
#endif

	PREFILTER

	memcpy(secret,skprefix,SKPREFIX_SIZE);
	wpk[PUBLIC_LEN] = 0;
	memset(&pubonion,0,sizeof(pubonion));
	memcpy(pubonion.raw,pkprefix,PKPREFIX_SIZE);
	// write version later as it will be overwritten by hash
	memcpy(hashsrc,checksumstr,checksumstrlen);
	hashsrc[checksumstrlen + PUBLIC_LEN] = 0x03; // version

	sname = makesname();

initseed:
	pthread_mutex_lock(&determseed_mutex);
	for (int i = 0; i < SEED_LEN; i++)
		if (++determseed[i])
			break;
	memcpy(seed, determseed, SEED_LEN);
	pthread_mutex_unlock(&determseed_mutex);
	ed25519_seckey_expand(sk,seed);

#ifdef STATISTICS
	++st->numrestart.v;
#endif

	ge_scalarmult_base(&ge_public,sk);
	ge_p3_tobytes(pk,&ge_public);

	for (counter = oldcounter = 0;counter < DETERMINISTIC_LOOP_COUNT;counter += 8) {
		ge_p1p1 sum;

		if (unlikely(endwork))
			goto end;

		DOFILTER(i,pk,{
			if (numwords > 1) {
				shiftpk(wpk,pk,filter_len(i));
				size_t j;
				for (int w = 1;;) {
					DOFILTER(j,wpk,goto secondfind);
					goto next;
				secondfind:
					if (++w >= numwords)
						break;
					shiftpk(wpk,wpk,filter_len(j));
				}
			}
			// found!
			// update secret key with delta since last hit (if any)
			addsztoscalar32(sk,counter-oldcounter);
			oldcounter = counter;
			// sanity check
			if ((sk[0] & 248) != sk[0] || ((sk[31] & 63) | 64) != sk[31])
				goto initseed;

			// reseed right half of key to avoid reuse, it won't change public key anyway
			reseedright(sk);

			ADDNUMSUCCESS;

			// calc checksum
			memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
			FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
			// version byte
			pk[PUBLIC_LEN + 2] = 0x03;
			// full name
			strcpy(base32_to(&sname[direndpos],pk,PUBONION_LEN),".onion");
			onionready(sname,secret,pubonion.raw);
			pk[PUBLIC_LEN] = 0; // what is this for?
		});
	next:
		ge_add(&sum, &ge_public,&ge_eightpoint);
		ge_p1p1_to_p3(&ge_public,&sum);
		ge_p3_tobytes(pk,&ge_public);
#ifdef STATISTICS
		++st->numcalc.v;
#endif
	}
	goto initseed;

end:
	free(sname);
	POSTFILTER
	sodium_memzero(secret,sizeof(secret));
	sodium_memzero(seed,sizeof(seed));
	return 0;
}
#endif // PASSPHRASE
