#define SECRET_LEN 64
#define PUBLIC_LEN 32
#define SEED_LEN   32
// with checksum + version num
#define PUBONION_LEN (PUBLIC_LEN + 3)

#define PKPREFIX_SIZE (29 + 3)
#define SKPREFIX_SIZE (29 + 3)

#define FORMATTED_PUBLIC_LEN (PKPREFIX_SIZE + PUBLIC_LEN)
#define FORMATTED_SECRET_LEN (SKPREFIX_SIZE + SECRET_LEN)

// full onion address, WITHOUT newline
#define ONION_LEN 62

// How many times we loop before a reseed
#define DETERMINISTIC_LOOP_COUNT 1<<24

// Argon2 hashed passphrase stretching settings
#define PWHASH_OPSLIMIT 256
#define PWHASH_MEMLIMIT 64 * 1024 * 1024
#define PWHASH_ALG      crypto_pwhash_ALG_ARGON2ID13

extern pthread_mutex_t fout_mutex;
extern FILE *fout;

extern size_t onionendpos;   // end of .onion within string
extern size_t direndpos;     // end of dir before .onion within string
extern size_t printstartpos; // where to start printing from
extern size_t printlen;      // precalculated, related to printstartpos
