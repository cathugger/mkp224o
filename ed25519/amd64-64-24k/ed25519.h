int ed25519_amd64_64_seckey(unsigned char *sk);
int ed25519_amd64_64_seckey_expand(unsigned char *sk,const unsigned char *seed);
int ed25519_amd64_64_pubkey(unsigned char *pk,const unsigned char *sk);
int ed25519_amd64_64_keygen(unsigned char *pk,unsigned char *sk);
