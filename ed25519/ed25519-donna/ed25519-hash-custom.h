/*
	a custom hash must have a 512bit digest and implement:

	struct ed25519_hash_context;

	void ed25519_hash_init(ed25519_hash_context *ctx);
	void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen);
	void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash);
	void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen);
*/
#include <sodium/crypto_hash_sha512.h>

typedef crypto_hash_sha512_state ed25519_hash_context;

static inline void ed25519_hash_init(ed25519_hash_context *ctx)
{
	crypto_hash_sha512_init(ctx);
}

static inline void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen)
{
	crypto_hash_sha512_update(ctx,in,inlen);
}

static inline void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash)
{
	crypto_hash_sha512_final(ctx,hash);
}

static inline void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen)
{
	crypto_hash_sha512(hash,in,inlen);
}
