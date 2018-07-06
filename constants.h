
#define LINEFEED_LEN (sizeof(char))
#define NULLTERM_LEN (sizeof(char))
#define PATH_SEPARATOR_LEN (sizeof(char))

static const int use_secret_mode = 1;
static const int use_public_mode = 0;

static const char hostname_filename[] = "hostname";
static const char secret_key_filename[] = "hs_ed25519_secret_key";
static const char public_key_filename[] = "hs_ed25519_public_key";

static const char keys_field_generated[] = "generated:";
static const char keys_field_hostname[] = "  - hostname: ";
static const char keys_field_secretkey[] = "  - hs_ed25519_secret_key: ";
static const char keys_field_publickey[] = "  - hs_ed25519_public_key: ";
static const char keys_field_time[] = "  - time: ";

#define KEYS_FIELD_GENERATED_LEN (sizeof(keys_field_generated) - NULLTERM_LEN)
#define KEYS_FIELD_HOSTNAME_LEN (sizeof(keys_field_hostname) - NULLTERM_LEN)
#define KEYS_FIELD_SECRETKEY_LEN (sizeof(keys_field_secretkey) - NULLTERM_LEN)
#define KEYS_FIELD_PUBLICKEY_LEN (sizeof(keys_field_publickey) - NULLTERM_LEN)
#define KEYS_FIELD_TIME_LEN (sizeof(keys_field_time) - NULLTERM_LEN)

static const char hostname_example[] = "xxxxxvsjzke274nisktdqcl3eqm5ve3m6iur6vwme7m5p6kxivrvjnyd.onion";
static const char seckey_example[] = "PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAACwCPMr6rvBRtkW7ZzZ8P7Ne4acRZrhPrN/EF6AETRraFGvdrkW5es4WXB2UxrbuUf8zPoIKkXK5cpdakYdUeM3";
static const char pubkey_example[] = "PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAAC973vWScqJr/GokqY4CXskGdqTbPIpH1bMJ9nX+VdFYw==";
static const char time_example[] = "2018-07-04 21:31:20";

#define HOSTNAME_LEN (sizeof(hostname_example) - NULLTERM_LEN)
#define SECKEY_LEN (sizeof(seckey_example) - NULLTERM_LEN)
#define PUBKEY_LEN (sizeof(pubkey_example) - NULLTERM_LEN)
#define TIME_LEN (sizeof(time_example) - NULLTERM_LEN)

#define KEYS_LEN ( KEYS_FIELD_GENERATED_LEN + LINEFEED_LEN \
	+ KEYS_FIELD_HOSTNAME_LEN + HOSTNAME_LEN + LINEFEED_LEN \
	+ KEYS_FIELD_SECRETKEY_LEN + SECKEY_LEN + LINEFEED_LEN \
	+ KEYS_FIELD_PUBLICKEY_LEN + PUBKEY_LEN + LINEFEED_LEN \
	+ KEYS_FIELD_TIME_LEN + TIME_LEN + LINEFEED_LEN \
	+ LINEFEED_LEN \
)
