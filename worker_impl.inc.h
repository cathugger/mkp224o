
static size_t CRYPTO_NAMESPACE(worker_batch_memuse)(void)
{
	return (sizeof(ge_p3) + sizeof(fe) + sizeof(bytes32)) * BATCHNUM;
}

#include "worker_slow.inc.h"
#include "worker_fast.inc.h"
#include "worker_fast_pass.inc.h"
#include "worker_batch.inc.h"
#include "worker_batch_pass.inc.h"

