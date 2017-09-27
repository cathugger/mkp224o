int ed25519_amd64_64_seckey(unsigned char *sk);
int ed25519_amd64_64_seckey_expand(unsigned char *sk,const unsigned char *seed);
int ed25519_amd64_64_pubkey(unsigned char *pk,const unsigned char *sk);
int ed25519_amd64_64_keygen(unsigned char *pk,unsigned char *sk);
int ed25519_amd64_64_sign(
    unsigned char *sm,unsigned long long *smlen,
    const unsigned char *m,unsigned long long mlen,
    const unsigned char *sk
);
int ed25519_amd64_64_open(
    unsigned char *m,unsigned long long *mlen,
    const unsigned char *sm,unsigned long long smlen,
    const unsigned char *pk
);
int ed25519_amd64_64_open_batch(
    unsigned char* const m[],unsigned long long mlen[],
    unsigned char* const sm[],const unsigned long long smlen[],
    unsigned char* const pk[], 
    unsigned long long num
);
