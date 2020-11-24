## mkp224o - vanity address generator for ed25519 onion services

This tool generates vanity ed25519 ([hidden service version 3][v3],
formely known as proposal 224) onion addresses.

### Requirements

* C99 compatible compiler (gcc and clang should work)
* libsodium (including headers)
* GNU make
* GNU autoconf (to generate configure script, needed only if not using release tarball)
* UNIX-like platform (currently tested in Linux and OpenBSD, but should
  also build under cygwin and msys2).

For debian-like linux distros, this should be enough to prepare for building:

```bash
apt install gcc libsodium-dev make autoconf
```

### Building

`./autogen.sh` to generate configure script, if it's not there already.

`./configure` to generate makefile; in \*BSD platforms you probably want to use
`./configure CPPFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"`.

You probably also want to pass something like `--enable-amd64-51-30k`
or `--enable-donna` to configure script for faster key generation;
run `./configure --help` to see all available options.

Finally, `make` to start building (`gmake` in \*BSD platforms).

### Usage

Generator needs one or more filters to work.

It makes directory with secret/public keys and hostname
for each discovered service. By default root is current
directory, but that can be overridden with `-d` switch.

Use `-s` switch to enable printing of statistics, which may be useful
when benchmarking different ed25519 implementations on your machine.

Use `-h` switch to obtain all available options.

I highly recommend reading [OPTIMISATION.txt][OPTIMISATION] for
performance-related tips.

### FAQ and other useful info

* How do I generate address?

  Once compiled, run it like `./mkp224o neko`, and it will try creating
  keys for onions starting with "neko" in this example; use `./mkp224o
  -d nekokeys neko` to not litter current directory and put all
  discovered keys in directory named "nekokeys".

* How do I make tor use generated keys?

  Copy key folder (though technically only `hs_ed25519_secret_key` is required)
  to where you want your service keys to reside:

  ```bash
  sudo cp -r neko54as6d54....onion /var/lib/tor/nekosvc
  ```

  You may need to adjust ownership and permissions:

  ```bash
  sudo chown -R tor: /var/lib/tor/nekosvc
  sudo chmod -R u+rwX,og-rwx /var/lib/tor/nekosvc
  ```

  Then edit `torrc` and add new service with that folder.
  After reload/restart tor should pick it up.

* Generate addresses with 1-2 and 7-9 digits?

  Onion addresses use base32 encoding which does not include 1,2,7,8,9
  numbers.
  So no, that's not possible to generate these, and mkp224o tries to
  detect invalid filters containing them early on.

* How long is it going to take?

  Because of probablistic nature of brute force key generation, and
  varience of hardware it's going to run on, it's hard to make promisses
  about how long it's going to take, especially when the most of users
  want just a few keys.
  See [this issue][#27] for very valuable discussion about this.
  If your machine is powerful enough, 6 character prefix shouldn't take
  more than few tens of minutes, if using batch mode (read
  [OPTIMISATION.txt][OPTIMISATION]) 7 characters can take hours
  to days.
  No promisses though, it depends on pure luck.

* Will this work with onionbalance?

  It appears that onionbalance supports loading usual
  `hs_ed25519_secret_key` key so it should work.

### Contact

For bug reports/questions/whatever else, email cathugger at cock dot li.
PGP key, if needed, can be found at <http://cathug2kyi4ilneggumrenayhuhsvrgn6qv2y47bgeet42iivkpynqad.onion/contact.html>.

### Acknowledgements & Legal

To the extent possible under law, the author(s) have dedicated all
copyright and related and neighboring rights to this software to the
public domain worldwide. This software is distributed without any
warranty.
You should have received a copy of the CC0 Public Domain Dedication
along with this software. If not, see [CC0][].

* `keccak.c` is based on [Keccak-more-compact.c][keccak.c]
* `ed25519/{ref10,amd64-51-30k,amd64-64-24k}` are adopted from
  [SUPERCOP][]
* `ed25519/ed25519-donna` adopted from [ed25519-donna][]
* Idea used in `worker_fast()` is stolen from [horse25519][]
* base64 routines and initial YAML processing work contributed by
  Alexander Khristoforov (heios at protonmail dot com)
* Passphrase-based generation code and idea used in `worker_batch()`
  contributed by [foobar2019][]

[v3]: https://gitweb.torproject.org/torspec.git/plain/rend-spec-v3.txt
[OPTIMISATION]: ./OPTIMISATION.txt
[#27]: https://github.com/cathugger/mkp224o/issues/27
[keccak.c]: https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-more-compact.c
[CC0]: https://creativecommons.org/publicdomain/zero/1.0/
[SUPERCOP]: https://bench.cr.yp.to/supercop.html
[ed25519-donna]: https://github.com/floodyberry/ed25519-donna
[horse25519]: https://github.com/Yawning/horse25519
[foobar2019]: https://github.com/foobar2019
