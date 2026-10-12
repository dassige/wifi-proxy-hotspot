# redsocks performance patches

Two small patches against Debian's `redsocks` source package (`0.5-2`,
matching the `0.5-2+b5` binary shipped in Trixie), applied by `install.sh`
after the stock package is installed. They came out of an investigation into
slow proxied connections over a long-distance (intercontinental) link to the
upstream proxy, where every extra round trip costs a noticeable fraction of a
second. They should apply to other `0.5` source releases too; if a newer
redsocks no longer accepts them, the installer just keeps the stock binary.

**License:** these patches modify redsocks
(<https://github.com/darkk/redsocks>), which is licensed under the Apache
License 2.0; the patches are distributed under that same license.

## 0001-tcp-nodelay.patch

`redsocks` never sets `TCP_NODELAY` anywhere in its source (only
`SO_KEEPALIVE`/`SO_REUSEADDR`), leaving Nagle's algorithm enabled on both
relay legs. Adds `apply_tcp_nodelay()` in `base.c` (declared in `base.h`),
called from `redsocks.c` (the accepted client socket) and `utils.c` (the
socket connecting out to the upstream proxy).

## 0002-preemptive-basic-auth.patch

`http-connect.c`'s `httpc_mkconnect()` only attaches `Proxy-Authorization`
once it has already been rejected with a 407 and learned the auth scheme
from the challenge header — wasting a full extra TCP handshake + CONNECT
round trip on every connection where the per-instance-cached
`last_auth_query` isn't already warm (e.g. the first connection after every
redsocks restart). Sends Basic auth proactively on the first attempt
instead, when `login`/`password` are configured. If a proxy genuinely
requires Digest, the first attempt is rejected and the existing
challenge/retry path still handles it correctly — same behavior as
upstream for that case, just no longer paid for the common Basic case.

## Reapplying manually

If a `redsocks` package upgrade replaces `/usr/sbin/redsocks` with the
stock (unpatched) binary, rebuild and reinstall:

```bash
sudo apt-get install -y build-essential dpkg-dev libevent-dev
mkdir -p /tmp/redsocks-build && cd /tmp/redsocks-build
# apt needs a deb-src line to fetch source; add one temporarily if missing
apt-get source redsocks
cd redsocks-*/
patch -p1 < /path/to/this/repo/package/redsocks-patches/0001-tcp-nodelay.patch
patch -p1 < /path/to/this/repo/package/redsocks-patches/0002-preemptive-basic-auth.patch
make
backup="/usr/sbin/redsocks.orig-$(dpkg-query -W -f='${Version}' redsocks)"
[ -f "$backup" ] || sudo cp /usr/sbin/redsocks "$backup"  # don't clobber a real backup with an already-patched binary
sudo install -m 755 -o root -g root redsocks /usr/sbin/redsocks
sudo systemctl restart redsocks
```

`install.sh` does exactly this (Step 4b), non-fatally — if source fetch or
build fails (e.g. no internet access to Debian's mirrors at install time),
it warns and leaves the stock binary in place rather than failing the
whole install, since this is a performance optimization, not a functional
requirement.
