mkp224o - vanity address generator for ed25519 onion services

This tool generates vanity ed25519 (hidden service version 3) onion addresses.
For context, see <https://gitweb.torproject.org/torspec.git/plain/rend-spec-v3.txt>.

REQUIREMENTS:
libsodium, GNU make, UNIX-like platform (currently tested in Linux).

BUILDING:
`make` (`gmake` in *BSD platforms).

USAGE:
Generator needs one of more filters to work.
It makes directory with secret/public keys and hostname
for each discovered service. By default root is current
directory, but that can be overridden with -d switch.
Use -h switch to obtain all avaiable options.

ACKNOWLEDGEMENTS & LEGAL:
To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights to this software to the public domain worldwide. This software is distributed without any warranty.
You should have received a copy of the CC0 Public Domain Dedication along with this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

keccak.c is based on <https://github.com/gvanas/KeccakCodePackage/blob/master/Standalone/CompactFIPS202/Keccak-more-compact.c>.
ed25519/ref10 is taken from SUPERCOP <https://bench.cr.yp.to/supercop.html>.
idea used in main.c' dofastwork() is stolen from <https://github.com/Yawning/horse25519>.
