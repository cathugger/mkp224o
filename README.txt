mkp224o - vanity address generator for ed25519 onion services

This tool generates vanity ed25519 (hidden service version 3, formely known as proposal 224) onion addresses.
For context, see <https://gitweb.torproject.org/torspec.git/plain/rend-spec-v3.txt>.

REQUIREMENTS:
C99 compatible compiler, libsodium, GNU make, GNU autoconf, UNIX-like platform (currently tested in Linux and OpenBSD).

BUILDING:
`./autogen.sh` to generate configure script, if it's not there already.
`./configure` to generate makefile; in *BSD platforms you probably want to use
`./configure CPPFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"`.
You probably also want to pass something like "--enable-amd64-51-30k"
or "--enable-donna" to configure script for faster key generation;
run `./configure --help` to see all available options.
Finally, `make` to start building (`gmake` in *BSD platforms).

USAGE:
Generator needs one or more filters to work.
It makes directory with secret/public keys and hostname
for each discovered service. By default root is current
directory, but that can be overridden with -d switch.
Use -s switch to enable printing of statistics, which may be useful
when benchmarking different ed25519 implementations on your machine.
Use -h switch to obtain all available options.
I highly recommend reading OPTIMISATION.txt for performance-related tips.

CONTACT:
For bug reports/questions/whatever else, email cathugger at cock dot li.
PGP key, if needed, can be found at <http://cathug2kyi4ilneggumrenayhuhsvrgn6qv2y47bgeet42iivkpynqad.onion/contact.html>.

ACKNOWLEDGEMENTS & LEGAL:
To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights to this software to the public domain worldwide. This software is distributed without any warranty.
You should have received a copy of the CC0 Public Domain Dedication along with this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

keccak.c is based on <https://github.com/gvanas/KeccakCodePackage/blob/master/Standalone/CompactFIPS202/Keccak-more-compact.c>.
ed25519/{ref10,amd64-51-30k,amd64-64-24k} are adopted from SUPERCOP <https://bench.cr.yp.to/supercop.html>.
ed25519/ed25519-donna adopted from <https://github.com/floodyberry/ed25519-donna>.
Idea used in worker_fast() is stolen from <https://github.com/Yawning/horse25519>.
base64 routines and initial YAML processing work contributed by Alexander Khristoforov <heios@protonmail.com>.
Passphrase-based generation code and idea used in worker_batch() contributed by <https://github.com/foobar2019>.
