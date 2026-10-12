"""DNS-over-HTTPS through the proxy (proxy_doh.py) and its use in dns_router,
against a fake DoH server on localhost (plain TCP standing in for the TLS
tunnel open_tunnel() would return)."""
import json
import socket
import threading
import time

import dns.message
import dns.rcode
import dns.rrset
import pytest

import dns_router
import proxy_doh
from conftest import load_script

EU_EDGE = "2.23.231.130"


class FakeDoH:
    """Minimal RFC 8484 server: answers every POST with an A record, in the
    style selected by `mode` ("length", "chunked", "close", "500")."""

    def __init__(self, mode="length"):
        self.mode = mode
        self.requests = []
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        threading.Thread(target=self._accept, daemon=True).start()

    def connect(self, *args, **kwargs):  # stands in for proxy_check.open_tunnel
        return socket.create_connection(self.srv.getsockname(), timeout=5)

    def _accept(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        buf = b""
        with conn:
            while True:
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                head, _, buf = buf.partition(b"\r\n\r\n")
                length = int(next(l.split(b":")[1] for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")))
                while len(buf) < length:
                    buf += conn.recv(4096)
                wire, buf = buf[:length], buf[length:]
                self.requests.append((head.decode(), wire))
                query = dns.message.from_wire(wire)
                answer = dns.message.make_response(query)
                answer.answer.append(dns.rrset.from_text(query.question[0].name, 20, "IN", "A", EU_EDGE))
                body = answer.to_wire()
                if self.mode == "500":
                    conn.sendall(b"HTTP/1.1 500 Internal\r\nContent-Length: 0\r\n\r\n")
                elif self.mode == "chunked":
                    half = len(body) // 2
                    conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
                                 b"%x\r\n%s\r\n%x\r\n%s\r\n0\r\n\r\n" % (half, body[:half], len(body) - half, body[half:]))
                else:
                    close = b"Connection: close\r\n" if self.mode == "close" else b""
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n" + close +
                                 b"Content-Length: %d\r\n\r\n" % len(body) + body)
                    if self.mode == "close":
                        return


def query_wire(name="hlslive-web-gcdn-skycdn-it.akamaized.net"):
    return dns.message.make_query(name, "A").to_wire()


def answer_ip(wire):
    return [a.address for rr in dns.message.from_wire(wire).answer for a in rr]


@pytest.mark.parametrize("mode,reusable", [("length", True), ("chunked", True), ("close", False)])
def test_exchange_parses_bodies_and_keep_alive(mode, reusable):
    server = FakeDoH(mode)
    conn = proxy_doh._Conn(server.connect())
    wire = query_wire()
    body, keep = conn.exchange(wire, timeout=5)
    assert answer_ip(body) == [EU_EDGE] and keep is reusable
    head, sent = server.requests[0]
    assert head.startswith("POST /dns-query HTTP/1.1") and "Host: dns.google" in head
    assert "Content-Type: application/dns-message" in head and sent == wire
    if reusable:  # the same connection serves a second query
        body, _ = conn.exchange(query_wire("www.raiplay.it"), timeout=5)
        assert answer_ip(body) == [EU_EDGE] and len(server.requests) == 2
    conn.close()


def test_exchange_rejects_error_status():
    conn = proxy_doh._Conn(FakeDoH("500").connect())
    with pytest.raises(proxy_doh.DoHError, match="500"):
        conn.exchange(query_wire(), timeout=5)


def wait_for(predicate, seconds=5):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_pool_warms_up_resolves_and_reuses(monkeypatch):
    server = FakeDoH()
    monkeypatch.setattr(proxy_doh, "open_tunnel", server.connect)
    pool = proxy_doh.DoHPool("Remote", {"ip": "x", "port": "1"})
    try:
        assert wait_for(lambda: pool.warm() == proxy_doh.POOL_SIZE)
        for _ in range(5):
            assert answer_ip(pool.resolve(query_wire())) == [EU_EDGE]
        assert pool.stats["ok"] == 5 and pool.warm() == proxy_doh.POOL_SIZE   # connections went back
    finally:
        pool.close()


def test_pool_never_waits_for_a_tunnel(monkeypatch):
    def slow_or_dead(*a, **k):
        time.sleep(0.5)
        raise RuntimeError("Could not connect to proxy: timed out")

    monkeypatch.setattr(proxy_doh, "open_tunnel", slow_or_dead)
    pool = proxy_doh.DoHPool("DEAD", {"ip": "x", "port": "1"})
    try:
        t0 = time.monotonic()
        with pytest.raises(proxy_doh.DoHError):
            pool.resolve(query_wire())
        assert time.monotonic() - t0 < 0.1                                    # immediate fallback
        assert pool.stats["fallback"] == 1
        assert wait_for(lambda: "timed out" in pool.stats["last_error"])
    finally:
        pool.close()


def test_failed_exchange_drops_the_connection(monkeypatch):
    server = FakeDoH("500")
    monkeypatch.setattr(proxy_doh, "open_tunnel", server.connect)
    pool = proxy_doh.DoHPool("Remote", {"ip": "x", "port": "1"})
    try:
        assert wait_for(lambda: pool.warm() == proxy_doh.POOL_SIZE)
        with pytest.raises(proxy_doh.DoHError):
            pool.resolve(query_wire())
        assert pool.warm() == proxy_doh.POOL_SIZE - 1 and "500" in pool.stats["last_error"]
    finally:
        pool.close()


class FakePool:
    instances = []

    def __init__(self, name, profile):
        self.name, self.profile, self.closed = name, dict(profile), False
        self.stats = {"ok": 0, "fallback": 0, "last_error": ""}
        FakePool.instances.append(self)

    def close(self):
        self.closed = True

    def warm(self):
        return 2

    def resolve(self, wire):
        return wire


def test_manager_sync_starts_stops_and_restarts_on_profile_change():
    FakePool.instances = []
    m = proxy_doh.DoHManager(pool_factory=FakePool)
    m.sync({"Remote": {"ip": "1.1.1.1"}, "AWS": {"ip": "2.2.2.2"}})
    assert m.has("Remote") and m.has("AWS") and len(FakePool.instances) == 2
    m.sync({"Remote": {"ip": "1.1.1.1"}})                                        # AWS no longer used
    assert FakePool.instances[1].closed and not m.has("AWS")
    m.sync({"Remote": {"ip": "9.9.9.9"}})                                        # profile edited
    assert FakePool.instances[0].closed and m.has("Remote") and len(FakePool.instances) == 3
    assert m.stats()["Remote"]["warm"] == 2
    with pytest.raises(proxy_doh.DoHError):
        m.resolve("nope", b"")


# --- dns_router: which lookups go through the proxy, and fallback ---------------

@pytest.fixture
def router(tmp_path, monkeypatch, fake_run):
    rules = tmp_path / "pattern_rules.json"
    profiles = tmp_path / "proxies.json"
    profiles.write_text(json.dumps({"profiles": {"Remote": {"ip": "1.2.3.4", "port": "8080"}}}))

    def write_rules(resolve_via_proxy=True, action="Remote"):
        rules.write_text(json.dumps({"bypass_cidr": "192.168.1.0/24", "default_action": "direct",
                                     "resolve_via_proxy": resolve_via_proxy, "rules": [
                                         {"id": "r1", "pattern": "*.akamaized.net", "mode": "wildcard",
                                          "action": action, "enabled": True}]}))
        dns_router._rules_cache["mtime"] = None

    manager = proxy_doh.DoHManager(pool_factory=FakePool)
    monkeypatch.setattr(dns_router, "RULES_FILE", str(rules))
    monkeypatch.setattr(dns_router, "PROXY_STORE", str(profiles))
    monkeypatch.setattr(dns_router, "_doh", manager)
    upstream_calls = []

    def fake_udp(request, server, timeout=None):
        upstream_calls.append(server)
        r = dns.message.make_response(request)
        r.answer.append(dns.rrset.from_text(request.question[0].name, 20, "IN", "A", "198.51.100.10"))
        return r

    monkeypatch.setattr(dns_router.dns.query, "udp", fake_udp)
    dns_router._tagged.clear()
    write_rules()
    return {"write_rules": write_rules, "manager": manager, "upstream": upstream_calls, "fake_run": fake_run}


def eu_answer(wire):
    q = dns.message.from_wire(wire)
    r = dns.message.make_response(q)
    r.id = 0  # the router must restore the client's query ID
    r.answer.append(dns.rrset.from_text(q.question[0].name, 20, "IN", "A", EU_EDGE))
    return r.to_wire()


def test_matched_proxied_name_is_answered_from_the_proxys_side_and_tagged(router, monkeypatch):
    monkeypatch.setattr(FakePool, "resolve", lambda self, wire: eu_answer(wire))
    q = dns.message.make_query("hlslive-web-gcdn-skycdn-it.akamaized.net", "A")
    reply = dns.message.from_wire(dns_router.handle_query(q.to_wire(), ["192.168.1.1"]))
    assert [a.address for rr in reply.answer for a in rr] == [EU_EDGE] and reply.id == q.id
    assert router["upstream"] == []                                            # ordinary DNS not used
    assert router["fake_run"].calls[-1]["input"] == f"add wpx_r1 {EU_EDGE}\n"  # the EU IP gets routed


def test_falls_back_to_ordinary_dns(router, monkeypatch):
    def fail(self, wire):
        raise proxy_doh.DoHError("no warm connection")

    monkeypatch.setattr(FakePool, "resolve", fail)
    q = dns.message.make_query("x.akamaized.net", "A")
    reply = dns.message.from_wire(dns_router.handle_query(q.to_wire(), ["192.168.1.1"]))
    assert [a.address for rr in reply.answer for a in rr] == ["198.51.100.10"] and router["upstream"] == ["192.168.1.1"]


def test_unmatched_names_never_use_the_proxy(router, monkeypatch):
    monkeypatch.setattr(FakePool, "resolve", lambda self, wire: pytest.fail("used the proxy"))
    dns_router.handle_query(dns.message.make_query("www.bbc.co.uk", "A").to_wire(), ["192.168.1.1"])
    assert router["upstream"] == ["192.168.1.1"]


def test_pools_follow_the_setting_and_rule_actions(router):
    dns_router.load_rules()
    assert router["manager"].has("Remote")
    router["write_rules"](resolve_via_proxy=False)
    dns_router.load_rules()
    assert not router["manager"].has("Remote")
    router["write_rules"](action="direct")                                     # direct rules need no pool
    dns_router.load_rules()
    assert not router["manager"].has("Remote")


# --- panel and health --------------------------------------------------------------

def test_setting_round_trips_and_defaults_on(app_module, monkeypatch, tmp_path):
    path = tmp_path / "pattern_rules.json"
    monkeypatch.setattr(app_module, "PATTERN_RULES_FILE", str(path))
    monkeypatch.setattr(app_module, "rebuild_firewall", lambda: None)
    path.write_text(json.dumps({"bypass_cidr": "192.168.1.0/24", "default_action": "direct", "rules": []}))
    assert app_module.load_pattern_config()["resolve_via_proxy"] is True
    config = app_module.load_pattern_config()
    config["resolve_via_proxy"] = False
    app_module.save_pattern_config(config)
    app_module.set_default_action("direct")                                    # an unrelated save
    assert json.loads(path.read_text())["resolve_via_proxy"] is False


def test_health_tile_for_proxied_lookups(tmp_path, monkeypatch):
    health = load_script("rasp-proxy-health.py", "rasp_proxy_health_doh")
    snap = tmp_path / "lookups.json"
    monkeypatch.setattr(health, "LOOKUPS_FILE", str(snap))
    monkeypatch.setattr(health, "dns_probe", lambda *a, **k: (True, "ok"))
    snap.write_text(json.dumps({"generated": time.time(), "capture": "ok", "clients": {},
                                "doh": {"Remote": {"warm": 2, "ok": 40, "fallback": 1, "last_error": ""}}}))
    tile = {c["id"]: c for c in health.check_dns_router()}["dns:via-proxy"]
    assert tile["status"] == "ok" and "Remote: 2 ready, 40 via proxy, 1 fallback" in tile["detail"] and not tile["alert"]
    snap.write_text(json.dumps({"generated": time.time(), "capture": "ok", "clients": {},
                                "doh": {"Remote": {"warm": 0, "ok": 0, "fallback": 3, "last_error": "timed out"}}}))
    tile = {c["id"]: c for c in health.check_dns_router()}["dns:via-proxy"]
    assert tile["status"] == "warn" and "No tunnel through Remote (timed out)" in tile["detail"]
    snap.write_text(json.dumps({"generated": time.time(), "capture": "ok", "clients": {}}))
    assert "dns:via-proxy" not in {c["id"] for c in health.check_dns_router()}
