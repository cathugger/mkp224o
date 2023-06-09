
#include "ed25519/ed25519_impl_pre.h"

static size_t CRYPTO_NAMESPACE(worker_batch_memuse)(void)
{
	return (sizeof(ge_p3) + sizeof(fe) + sizeof(bytes32)) * BATCHNUM;
}

#include "worker_batch.inc.h"
#include "worker_batch_pass.inc.h"

#include "ed25519/ed25519_impl_post.h"
