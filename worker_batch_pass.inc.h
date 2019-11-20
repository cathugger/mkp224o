
#ifdef PASSPHRASE
void *worker_batch_pass(void *task)
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

	// state to keep batch data
	ge_p3 ge_batch[BATCHNUM];
	fe *(batchgez)[BATCHNUM];
	fe tmp_batch[BATCHNUM];
	bytes32 pk_batch[BATCHNUM];

	size_t counter,oldcounter;
	size_t i;

#ifdef STATISTICS
	struct statstruct *st = (struct statstruct *)task;
#endif

	// set up right pointers
	for (size_t b = 0;b < BATCHNUM;++b)
		batchgez[b] = &GEZ(ge_batch[b]);

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
#ifdef STATISTICS
	++st->numrestart.v;
#endif

	pthread_mutex_lock(&determseed_mutex);
	for (int i = 0; i < SEED_LEN; i++)
		if (++determseed[i])
			break;
	memcpy(seed, determseed, SEED_LEN);
	pthread_mutex_unlock(&determseed_mutex);

	ed25519_seckey_expand(sk,seed);

	ge_scalarmult_base(&ge_public,sk);

	for (counter = oldcounter = 0;counter < DETERMINISTIC_LOOP_COUNT - (BATCHNUM - 1) * 8;counter += BATCHNUM * 8) {
		ge_p1p1 sum;

		if (unlikely(endwork))
			goto end;


		for (size_t b = 0;b < BATCHNUM;++b) {
			ge_batch[b] = ge_public;
			ge_add(&sum,&ge_public,&ge_eightpoint);
			ge_p1p1_to_p3(&ge_public,&sum);
		}
		// NOTE: leaves unfinished one bit at the very end
		ge_p3_batchtobytes_destructive_1(pk_batch,ge_batch,batchgez,tmp_batch,BATCHNUM);

#ifdef STATISTICS
		st->numcalc.v += BATCHNUM;
#endif

		for (size_t b = 0;b < BATCHNUM;++b) {
			DOFILTER(i,pk_batch[b],{
				if (numwords > 1) {
					shiftpk(wpk,pk_batch[b],filter_len(i));
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
				// finish it up
				ge_p3_batchtobytes_destructive_finish(pk_batch[b],&ge_batch[b]);
				// copy public key
				memcpy(pk,pk_batch[b],PUBLIC_LEN);
				// update secret key with counter
				addsztoscalar32(sk,counter + (b * 8) - oldcounter);
				oldcounter = counter + (b * 8);
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
			;
		}
	}
	// continue if have leftovers, DETERMINISTIC_LOOP_COUNT - counter < BATCHNUM * 8
	// can't have leftovers in theory if BATCHNUM was power of 2 and smaller than DETERMINISTIC_LOOP_COUNT bound
#if (BATCHNUM & (BATCHNUM - 1)) || (BATCHNUM * 8) > DETERMINISTIC_LOOP_COUNT
	if (counter < DETERMINISTIC_LOOP_COUNT) {
		ge_p1p1 sum;

		if (unlikely(endwork))
			goto end;

		const size_t remaining = (DETERMINISTIC_LOOP_COUNT - counter) / 8;

		for (size_t b = 0;b < remaining;++b) {
			ge_batch[b] = ge_public;
			ge_add(&sum,&ge_public,&ge_eightpoint);
			ge_p1p1_to_p3(&ge_public,&sum);
		}
		// NOTE: leaves unfinished one bit at the very end
		ge_p3_batchtobytes_destructive_1(pk_batch,ge_batch,batchgez,tmp_batch,remaining);

#ifdef STATISTICS
		st->numcalc.v += remaining;
#endif

		for (size_t b = 0;b < remaining;++b) {
			DOFILTER(i,pk_batch[b],{
				if (numwords > 1) {
					shiftpk(wpk,pk_batch[b],filter_len(i));
					size_t j;
					for (int w = 1;;) {
						DOFILTER(j,wpk,goto secondfind2);
						goto next2;
					secondfind2:
						if (++w >= numwords)
							break;
						shiftpk(wpk,wpk,filter_len(j));
					}
				}
				// found!
				// finish it up
				ge_p3_batchtobytes_destructive_finish(pk_batch[b],&ge_batch[b]);
				// copy public key
				memcpy(pk,pk_batch[b],PUBLIC_LEN);
				// update secret key with counter
				addsztoscalar32(sk,counter + (b * 8) - oldcounter);
				oldcounter = counter + (b * 8);
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
		next2:
			;
		}
	}
#endif // (BATCHNUM & (BATCHNUM - 1)) || (BATCHNUM * 8) > DETERMINISTIC_LOOP_COUNT
	goto initseed;

end:
	free(sname);
	POSTFILTER
	sodium_memzero(secret,sizeof(secret));
	sodium_memzero(seed,sizeof(seed));
	return 0;
}
#endif // PASSPHRASE
