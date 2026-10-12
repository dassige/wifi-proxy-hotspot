#!/usr/bin/env python3
"""
DNS-based pattern router for the Wi-Fi Proxy Hotspot.

Sits between the hotspot's own dnsmasq (NetworkManager's shared-connection
resolver) and the real upstream DNS servers. Every query is forwarded
unmodified and the real answer is always returned — this process never
blocks or rewrites DNS traffic, it only *observes* it. For queries whose
hostname matches a configured pattern rule, the resolved IP addresses are
tagged into that rule's ipset, which the firewall (see
rasp-proxy-rebuild-firewall) uses to decide whether that traffic goes
through the upstream proxy or direct.

One exception to "forwarded to the real upstream": a hostname matched by a
rule that routes through a proxy is looked up *through that proxy*, over
DNS-over-HTTPS (proxy_doh.py), so CDNs answer with servers near the proxy
rather than near the hotspot. It's still the genuine answer, just asked from
the proxy's side. It falls back to the ordinary upstream whenever that isn't
instantly available. Can be turned off on the Routing Rules page
("resolve_via_proxy" in pattern_rules.json).

Runs as an unprivileged, dedicated service account with only
CAP_NET_ADMIN (granted via systemd AmbientCapabilities) so it can call
`ipset` directly, without sudo, on the hot path of every DNS query.

Failure mode is deliberately fail-open: any error in rule matching or
ipset tagging is swallowed so a bug here can never break DNS resolution
for hotspot devices, at worst it just fails to tag that one lookup.

Also keeps a per-device record of recent lookups for the admin panel's DNS
Lookups page. That can't come from the queries above: they all arrive from
dnsmasq on 127.0.0.1, and names dnsmasq answers from its own cache never
arrive at all. So a separate thread passively captures DNS queries as
devices send them on the AP interface (a kernel socket filter passes only
UDP to port 53, so ordinary traffic never reaches Python). That also sees
queries sent straight to an outside resolver, which bypass pattern rules
entirely. Needs CAP_NET_RAW; without it only this record is lost, never DNS
routing itself. The record is in memory only, snapshotted to a small JSON
file under /run (tmpfs), readable only by the service group.
"""
import collections
import ctypes
import socket
import socketserver
import subprocess
import sys
import threading
import json
import os
import re
import struct
import time

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from pattern_match import match_rule, prepare_rule
from proxy_doh import DoHManager

LISTEN_ADDR = "127.0.0.1"
LISTEN_PORT = 15353
RULES_FILE = "/var/lib/rasp-proxy-admin/pattern_rules.json"
# Group-readable (redsocks); holds proxy credentials, used only to open the
# DoH tunnels below and never logged.
PROXY_STORE = "/var/lib/rasp-proxy-admin/proxies.json"
IPSET_TIMEOUT = "86400"
UPSTREAM_TIMEOUT = 4.0
FALLBACK_UPSTREAMS = ["1.1.1.1", "8.8.8.8"]

# An IP tagged within this window is trusted to still be in its ipset
# (whose own timeout is 24h), so the reply isn't held for it again.
TAG_REFRESH_SECONDS = 3600
TAG_TIMEOUT = 1.0
TAGGED_MAX = 20000

_rules_lock = threading.Lock()
_rules_cache = {"mtime": None, "rules": [], "guards": {}}
# Leak guards answered here rather than in the firewall (see the URL Pattern
# Rules page): Apple's documented way for a network to turn off iCloud
# Private Relay, which would otherwise carry an iPhone's traffic past every
# rule; and Firefox's canary domain, which tells it not to switch on its
# own DNS-over-HTTPS. Both just want a negative answer (NXDOMAIN).
PRIVATE_RELAY_NAMES = {"mask.icloud.com", "mask-h2.icloud.com"}
FIREFOX_DOH_CANARY = "use-application-dns.net"
_guard_hits = {"private_relay": 0, "dns": 0}  # since start, for the panel
_ensured_ipsets = set()
# Warm DNS-over-HTTPS tunnels through each proxy that a pattern rule routes
# through (see proxy_doh.py for why), used for those rules' hostnames.
_doh = DoHManager()
_tagged_lock = threading.Lock()
_tagged = {}  # (ipset, ip) -> time.monotonic() of the last successful tag

AP_IFACE = os.environ.get("RASP_PROXY_AP_IFACE", "wlan0")
LOOKUPS_FILE = "/run/rasp-proxy-dns/lookups.json"
LOOKUPS_PER_CLIENT = 300
LOOKUPS_MAX_CLIENTS = 100
SNAPSHOT_EVERY = 5      # seconds between snapshots while lookups are arriving
SNAPSHOT_HEARTBEAT = 60  # ...and at least this often regardless
HOSTNAME_RE = re.compile(r"[a-z0-9_-]+(\.[a-z0-9_-]+)+")

# Classic BPF over the IP header (SOCK_DGRAM packet socket, so no link-layer
# header): accept unfragmented UDP to port 53, drop everything else.
_BPF_UDP_DPORT_53 = [
    (0x30, 0, 0, 9),       # ldb [9]            IP protocol
    (0x15, 0, 6, 17),      # jeq #17 (UDP)      else drop
    (0x28, 0, 0, 6),       # ldh [6]            flags + fragment offset
    (0x45, 4, 0, 0x1FFF),  # jset #0x1fff       fragment -> drop
    (0xB1, 0, 0, 0),       # ldxb 4*([0]&0xf)   X = IP header length
    (0x48, 0, 0, 2),       # ldh [x+2]          UDP destination port
    (0x15, 0, 1, 53),      # jeq #53            else drop
    (0x06, 0, 0, 0x40000),  # ret #262144       accept
    (0x06, 0, 0, 0),       # ret #0             drop
]
SO_ATTACH_FILTER = 26
ETH_P_IP = 0x0800
PACKET_OUTGOING = 4
SIOCGIFADDR = 0x8915

_lookups_lock = threading.Lock()
# client IP -> OrderedDict(name -> {"first", "last", "count", "resolvers"}),
# both in least-recently-seen-first order.
_lookups = collections.OrderedDict()
_lookups_dirty = False
_capture_status = "starting"


def get_upstreams():
    servers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver "):
                    servers.append(line.split()[1])
    except OSError:
        pass
    servers = [s for s in servers if s != LISTEN_ADDR]
    return servers or FALLBACK_UPSTREAMS


def ensure_ipset(name):
    if name in _ensured_ipsets:
        return
    subprocess.run(
        ["ipset", "create", name, "hash:ip", "family", "inet", "timeout", IPSET_TIMEOUT, "-exist"],
        capture_output=True,
    )
    _ensured_ipsets.add(name)


def load_profiles():
    try:
        with open(PROXY_STORE) as f:
            return json.load(f).get("profiles", {})
    except (OSError, ValueError):
        return {}


def load_rules():
    try:
        mtime = os.stat(RULES_FILE).st_mtime
    except OSError:
        return []
    try:
        mtime = (mtime, os.stat(PROXY_STORE).st_mtime)  # a profile edit changes its DoH tunnel
    except OSError:
        pass

    with _rules_lock:
        if _rules_cache["mtime"] == mtime:
            return _rules_cache["rules"]

        try:
            with open(RULES_FILE) as f:
                data = json.load(f)
        except (OSError, ValueError):
            return _rules_cache["rules"]

        # Any rule change may have destroyed and recreated ipsets (the
        # rebuild helper prunes disabled/edited rules' sets), so forget what
        # we believe is already created/tagged rather than trust it.
        _ensured_ipsets.clear()
        with _tagged_lock:
            _tagged.clear()

        rules = []
        for r in data.get("rules", []):
            if not r.get("enabled", True):
                # Skip disabled rules entirely: don't tag their ipset, so a
                # disabled rule's ipset ages out / gets pruned by the
                # firewall-rebuild helper rather than being kept alive here.
                continue
            rule = prepare_rule(r)
            if rule is None:
                continue
            rule["ipset"] = f"wpx_{r['id']}"
            rules.append(rule)
            ensure_ipset(rule["ipset"])

        # "resolve_via_proxy" (on unless set false; Routing Rules page).
        profiles = load_profiles()
        needed = {}
        if data.get("resolve_via_proxy", True):
            needed = {r["action"]: profiles[r["action"]] for r in rules if r["action"] in profiles}
        try:
            _doh.sync(needed)
        except Exception:
            pass

        stored = data.get("leak_guards") or {}
        _rules_cache["guards"] = {k: bool(stored.get(k, True)) for k in ("dns", "private_relay", "ipv6")}
        _rules_cache["mtime"] = mtime
        _rules_cache["rules"] = rules
        return rules


def guard_answer(qname, request):
    # NXDOMAIN for a name a leak guard blocks, else None.
    guards = _rules_cache.get("guards") or {}
    hit = ("private_relay" if guards.get("private_relay") and qname in PRIVATE_RELAY_NAMES
           else "dns" if guards.get("dns") and qname == FIREFOX_DOH_CANARY else None)
    if hit:
        _guard_hits[hit] += 1
        reply = dns.message.make_response(request)
        reply.set_rcode(dns.rcode.NXDOMAIN)
        return reply.to_wire()
    return None


def resolve_through_proxy(action, request, data):
    # The answer as seen from the proxy's side (CDN servers near the proxy rather
    # than near the hotspot), or None -- then the caller uses ordinary DNS.
    if not _doh.has(action):
        return None
    try:
        response = dns.message.from_wire(_doh.resolve(action, data))
    except Exception:
        return None
    if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        return None
    response.id = request.id
    return response


def tag_response(response, ipset_name):
    # Runs *before* the reply is sent, but only for IPs not tagged recently.
    # Tagging after replying (as this once did) raced the client: its first
    # connection to a brand-new IP could beat the tag, go direct, and stay
    # direct for that connection's whole life -- for a video player's
    # keep-alive connection, the whole session. All of a reply's new IPs go
    # in one `ipset restore` (~4ms on the Pi 3B+, measured 2026-10-01), and
    # repeat lookups of already-tagged IPs pay nothing.
    try:
        now = time.monotonic()
        ips = [r.address for rrset in response.answer
               if rrset.rdtype == dns.rdatatype.A for r in rrset]
        with _tagged_lock:
            new = [ip for ip in ips
                   if (ipset_name, ip) not in _tagged
                   or now - _tagged[(ipset_name, ip)] >= TAG_REFRESH_SECONDS]
        if not new:
            return
        result = subprocess.run(
            ["ipset", "-exist", "restore"],
            input="".join(f"add {ipset_name} {ip}\n" for ip in new),
            capture_output=True, text=True, timeout=TAG_TIMEOUT,
        )
        if result.returncode == 0:
            with _tagged_lock:
                if len(_tagged) > TAGGED_MAX:
                    _tagged.clear()
                for ip in new:
                    _tagged[(ipset_name, ip)] = now
    except Exception:
        pass


def handle_query(data, upstreams):
    try:
        request = dns.message.from_wire(data)
        qname = str(request.question[0].name).rstrip(".").lower()
    except Exception:
        return None

    rules = load_rules()
    blocked = guard_answer(qname, request)
    if blocked is not None:
        return blocked
    matched = None
    try:
        matched = match_rule(qname, rules)
    except Exception:
        matched = None

    response = resolve_through_proxy(matched["action"], request, data) if matched else None
    for upstream in ([] if response is not None else upstreams):
        try:
            response = dns.query.udp(request, upstream, timeout=UPSTREAM_TIMEOUT)
            break
        except Exception:
            continue

    if response is None:
        reply = dns.message.make_response(request)
        reply.set_rcode(dns.rcode.SERVFAIL)
        return reply.to_wire()

    if matched:
        tag_response(response, matched["ipset"])

    return response.to_wire()


def parse_dns_query(packet):
    # IPv4 packet -> (client_ip, hostname, resolver_ip) for a DNS query to
    # port 53, else None. Re-checks what the socket filter already should
    # have, since packets can queue before the filter is attached. Names
    # that don't look like real hostnames are dropped: they're never real
    # sites, and anything stored here ends up on the admin page.
    try:
        if len(packet) < 28 or packet[0] >> 4 != 4 or packet[9] != 17:
            return None
        ihl = (packet[0] & 0x0F) * 4
        if struct.unpack("!H", packet[ihl + 2:ihl + 4])[0] != 53:
            return None
        msg = dns.message.from_wire(packet[ihl + 8:])
        if msg.flags & dns.flags.QR or not msg.question:
            return None
        name = msg.question[0].name.to_text(omit_final_dot=True).lower()
    except Exception:
        return None
    if len(name) > 253 or name.endswith(".arpa") or not HOSTNAME_RE.fullmatch(name):
        return None
    return socket.inet_ntoa(packet[12:16]), name, socket.inet_ntoa(packet[16:20])


def record_lookup(client, name, resolver, ap_ip):
    global _lookups_dirty
    now = time.time()
    with _lookups_lock:
        names = _lookups.get(client)
        if names is None:
            if len(_lookups) >= LOOKUPS_MAX_CLIENTS:
                _lookups.popitem(last=False)
            names = _lookups[client] = collections.OrderedDict()
        else:
            _lookups.move_to_end(client)
        entry = names.get(name)
        if entry is None:
            if len(names) >= LOOKUPS_PER_CLIENT:
                names.popitem(last=False)
            entry = names[name] = {"first": now, "last": now, "count": 0, "bypass": []}
        else:
            names.move_to_end(name)
        entry["last"] = now
        entry["count"] += 1
        # Asked some resolver other than the hotspot itself: dns_router
        # never sees that lookup, so no pattern rule can apply to it.
        if ap_ip and resolver != ap_ip and resolver not in entry["bypass"]:
            entry["bypass"].append(resolver)
        _lookups_dirty = True


def iface_ipv4(iface):
    try:
        import fcntl  # Linux-only; imported here so this module still imports elsewhere for tests

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            packed = fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack("256s", iface.encode()[:15]))
            return socket.inet_ntoa(packed[20:24])
        finally:
            s.close()
    except OSError:
        return None


def open_capture_socket(iface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))
    code = b"".join(struct.pack("HBBI", *ins) for ins in _BPF_UDP_DPORT_53)
    buf = ctypes.create_string_buffer(code, len(code))
    prog = struct.pack("HL", len(_BPF_UDP_DPORT_53), ctypes.addressof(buf))
    # Filter first, then bind: an unbound packet socket sees every interface.
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, prog)
    sock.bind((iface, ETH_P_IP))
    return sock, buf


def set_capture_status(status):
    # Marks the snapshot dirty so a status change (e.g. "starting" -> "ok")
    # reaches the admin page within one snapshot interval, not a heartbeat.
    global _capture_status, _lookups_dirty
    with _lookups_lock:
        if status != _capture_status:
            _capture_status = status
            _lookups_dirty = True


def capture_loop():
    while True:
        try:
            sock, _filter_buf = open_capture_socket(AP_IFACE)
        except PermissionError:
            set_capture_status("no permission to capture DNS lookups (CAP_NET_RAW missing)")
            print(f"dns_router: {_capture_status}", file=sys.stderr, flush=True)
            return
        except OSError as e:
            set_capture_status(f"lookup capture unavailable on {AP_IFACE}: {e.strerror or e}")
            time.sleep(10)
            continue
        set_capture_status("ok")
        ap_ip, ap_ip_checked = iface_ipv4(AP_IFACE), time.monotonic()
        try:
            while True:
                packet, addr = sock.recvfrom(65535)
                if addr[2] == PACKET_OUTGOING:
                    continue
                if time.monotonic() - ap_ip_checked > 60:
                    ap_ip, ap_ip_checked = iface_ipv4(AP_IFACE) or ap_ip, time.monotonic()
                parsed = parse_dns_query(packet)
                if parsed:
                    record_lookup(*parsed, ap_ip)
        except OSError as e:
            set_capture_status(f"lookup capture interrupted: {e.strerror or e}")
            time.sleep(5)
        finally:
            sock.close()


def write_snapshot(snapshot):
    tmp = LOOKUPS_FILE + ".tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "w") as f:
            json.dump(snapshot, f)
        os.replace(tmp, LOOKUPS_FILE)
    except OSError:
        pass


def snapshot_loop():
    global _lookups_dirty
    last_write = None
    while True:
        now = time.monotonic()
        with _lookups_lock:
            due = _lookups_dirty or last_write is None or now - last_write >= SNAPSHOT_HEARTBEAT
            if due:
                clients = {
                    ip: [dict(e, name=n, bypass=list(e["bypass"])) for n, e in reversed(names.items())]
                    for ip, names in _lookups.items()
                }
                status = _capture_status
                _lookups_dirty = False
        if due:
            write_snapshot({"generated": time.time(), "capture": status, "clients": clients,
                            "doh": _doh.stats(), "guard_hits": dict(_guard_hits)})
            last_write = now
        time.sleep(SNAPSHOT_EVERY)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        upstreams = get_upstreams()
        wire = handle_query(data, upstreams)
        if wire is not None:
            sock.sendto(wire, self.client_address)


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            length_bytes = self._recv_exact(2)
            if not length_bytes:
                return
            (length,) = struct.unpack("!H", length_bytes)
            data = self._recv_exact(length)
            if not data:
                return
            upstreams = get_upstreams()
            wire = handle_query(data, upstreams)
            if wire is not None:
                self.request.sendall(struct.pack("!H", len(wire)) + wire)
        except Exception:
            pass

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    udp_server = ThreadingUDPServer((LISTEN_ADDR, LISTEN_PORT), UDPHandler)
    tcp_server = ThreadingTCPServer((LISTEN_ADDR, LISTEN_PORT), TCPHandler)

    load_rules()  # starts the DoH tunnels now, so they're warm before the first lookup
    udp_thread = threading.Thread(target=udp_server.serve_forever, daemon=True)
    udp_thread.start()
    threading.Thread(target=capture_loop, daemon=True).start()
    threading.Thread(target=snapshot_loop, daemon=True).start()
    tcp_server.serve_forever()


if __name__ == "__main__":
    main()
