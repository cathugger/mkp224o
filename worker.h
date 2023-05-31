
extern pthread_mutex_t keysgenerated_mutex;
extern volatile size_t keysgenerated;
extern volatile int endwork;

extern int yamloutput;
extern int yamlraw;
extern int numwords;
extern size_t numneedgenerate;

extern char *workdir;
extern size_t workdirlen;

// statistics, if enabled
#ifdef STATISTICS
struct statstruct {
	union {
		u32 v;
		size_t align;
	} numcalc;
	union {
		u32 v;
		size_t align;
	} numsuccess;
	union {
		u32 v;
		size_t align;
	} numrestart;
} ;
VEC_STRUCT(statsvec,struct statstruct);
#endif

#ifdef PASSPHRASE
extern pthread_mutex_t determseed_mutex;
extern u8 determseed[SEED_LEN];
#endif

extern void worker_init(void);
extern void ed25519_pubkey_addbase(const u8 base_pk[32]);

extern char *makesname(void);
extern size_t worker_batch_memuse(void);

extern void *CRYPTO_NAMESPACE(worker_slow)(void *task);
extern void *CRYPTO_NAMESPACE(worker_fast)(void *task);
extern void *CRYPTO_NAMESPACE(worker_batch)(void *task);
#ifdef PASSPHRASE
extern void *CRYPTO_NAMESPACE(worker_fast_pass)(void *task);
extern void *CRYPTO_NAMESPACE(worker_batch_pass)(void *task);
#endif
