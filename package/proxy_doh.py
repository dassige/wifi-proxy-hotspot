"""
DNS-over-HTTPS (RFC 8484, wire format) through an upstream proxy, used by
dns_router.py for hostnames matched by a pattern rule that routes through
that proxy.

Why: a CDN picks the server it hands out by where the DNS question comes
from. Asked from the hotspot's own country, Akamai returns a local edge, so
proxied video went local edge -> proxy abroad -> local edge. Measured on a
live TV stream through a proxy on another continent, 8 rounds: a 10 s
segment took a median 7.3 s from the local edge (worst 10.2 s, longer than
it plays) vs 3.7 s from an edge near the proxy. EDNS Client Subnet doesn't
help, because Akamai ignores it (scope 0). But asking Google's DoH *through*
the proxy makes Google's side near the proxy do the lookup, and Akamai then
answers with a server near the proxy.

Latency is bounded by design. A background thread per proxy keeps POOL_SIZE
tunnels open and pings them so they stay warm. A lookup only ever uses an
already-open tunnel (one round trip, ~0.5 s across continents). If none is ready,
resolve() raises straight away and the caller falls back to ordinary DNS,
so a slow or dead proxy never adds its tunnel setup time to anyone's lookup.

Stdlib-only (plus proxy_check), so it's testable off the Pi.
"""
import random
import struct
import threading
import time

from proxy_check import open_tunnel

DOH_HOST = "dns.google"
DOH_PATH = "/dns-query"
POOL_SIZE = 2
QUERY_TIMEOUT = 2.5
CONNECT_TIMEOUT = 8
PING_EVERY = 45
RETRY_AFTER_FAILURE = 30
MAINTAIN_EVERY = 5


class DoHError(Exception):
    pass


def build_query(name, rtype=1):
    # Minimal DNS query in wire format (for the keep-alive pings).
    q = struct.pack("!HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return q + struct.pack("!HH", rtype, 1)


class _Conn:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""
        self.last_used = time.monotonic()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def _fill(self):
        chunk = self.sock.recv(16384)
        if not chunk:
            raise DoHError("connection closed by the DoH server")
        self.buf += chunk

    def read_until(self, marker):
        while marker not in self.buf:
            self._fill()
        head, _, self.buf = self.buf.partition(marker)
        return head

    def read_exact(self, n):
        while len(self.buf) < n:
            self._fill()
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def exchange(self, wire, timeout):
        """One DoH POST on this keep-alive connection; returns (body, reusable)."""
        self.sock.settimeout(timeout)
        self.sock.sendall(
            (f"POST {DOH_PATH} HTTP/1.1\r\nHost: {DOH_HOST}\r\nContent-Type: application/dns-message\r\n"
             f"Accept: application/dns-message\r\nContent-Length: {len(wire)}\r\n\r\n").encode() + wire)
        head = self.read_until(b"\r\n\r\n").decode("latin-1")
        status_line, *header_lines = head.split("\r\n")
        headers = {}
        for line in header_lines:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
        if headers.get("transfer-encoding", "").lower() == "chunked":
            body = b""
            while True:
                size = int(self.read_until(b"\r\n").split(b";")[0] or b"0", 16)
                if size == 0:
                    self.read_until(b"\r\n")
                    break
                body += self.read_exact(size)
                self.read_exact(2)
        elif "content-length" in headers:
            body = self.read_exact(int(headers["content-length"]))
        else:
            raise DoHError("DoH response without a length")
        if " 200 " not in f"{status_line} ":
            raise DoHError(f"DoH server answered {status_line[:60]}")
        self.last_used = time.monotonic()
        return body, headers.get("connection", "").lower() != "close"


class DoHPool:
    """Warm DoH tunnels through one proxy profile."""

    def __init__(self, name, profile):
        self.name = name
        self.profile = dict(profile)
        self._idle = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._next_attempt = 0.0
        self.stats = {"ok": 0, "fallback": 0, "last_error": ""}
        self._thread = threading.Thread(target=self._maintain, name=f"doh-{name}", daemon=True)
        self._thread.start()

    def warm(self):
        with self._lock:
            return len(self._idle)

    def resolve(self, wire):
        with self._lock:
            conn = self._idle.pop() if self._idle else None
        if conn is None:
            self.stats["fallback"] += 1
            raise DoHError("no warm connection through the proxy yet")
        try:
            body, reusable = conn.exchange(wire, QUERY_TIMEOUT)
        except Exception as e:
            conn.close()
            self.stats["fallback"] += 1
            self.stats["last_error"] = f"{type(e).__name__}: {e}"[:160]
            raise DoHError(str(e)) from None
        self.stats["ok"] += 1
        if reusable:
            with self._lock:
                self._idle.append(conn)
        else:
            conn.close()
        return body

    def close(self):
        self._stop.set()
        with self._lock:
            idle, self._idle = self._idle, []
        for conn in idle:
            conn.close()

    def _maintain(self):
        while not self._stop.is_set():
            try:
                self._ping_idle()
                if self.warm() < POOL_SIZE and time.monotonic() >= self._next_attempt:
                    conn = _Conn(open_tunnel(self.profile, DOH_HOST, 443, timeout=CONNECT_TIMEOUT))
                    if self._stop.is_set():
                        conn.close()
                        break
                    with self._lock:
                        self._idle.append(conn)
                    continue  # open the next one straight away
            except Exception as e:
                self.stats["last_error"] = f"{type(e).__name__}: {e}"[:160]
                self._next_attempt = time.monotonic() + RETRY_AFTER_FAILURE
            self._stop.wait(MAINTAIN_EVERY)

    def _ping_idle(self):
        now = time.monotonic()
        with self._lock:
            stale = [c for c in self._idle if now - c.last_used >= PING_EVERY]
            self._idle = [c for c in self._idle if c not in stale]
        for conn in stale:
            try:
                _, reusable = conn.exchange(build_query(DOH_HOST), QUERY_TIMEOUT)
            except Exception:
                conn.close()
                continue
            if reusable:
                with self._lock:
                    self._idle.append(conn)
            else:
                conn.close()


class DoHManager:
    """One pool per proxy profile that a DoH-eligible rule routes through."""

    def __init__(self, pool_factory=DoHPool):
        self._pools = {}
        self._lock = threading.Lock()
        self._factory = pool_factory

    def sync(self, needed):
        # needed: {profile name: profile dict}. Starts/stops/restarts pools so
        # exactly these exist, each with the profile's current settings.
        with self._lock:
            for name in list(self._pools):
                pool = self._pools[name]
                if name not in needed or pool.profile != needed[name]:
                    pool.close()
                    del self._pools[name]
            for name, profile in needed.items():
                if name not in self._pools:
                    self._pools[name] = self._factory(name, profile)

    def has(self, name):
        with self._lock:
            return name in self._pools

    def resolve(self, name, wire):
        with self._lock:
            pool = self._pools.get(name)
        if pool is None:
            raise DoHError(f"no DoH pool for {name}")
        return pool.resolve(wire)

    def stats(self):
        with self._lock:
            return {name: dict(pool.stats, warm=pool.warm()) for name, pool in self._pools.items()}
