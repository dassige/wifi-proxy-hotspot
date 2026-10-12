"""
Direct checks of an upstream proxy profile, shared by app.py (the Proxy
Profiles "Check" button) and rasp-proxy-health (the periodic health check),
so both measure exactly the same thing.

Each check opens its own TCP connection straight to the upstream proxy --
not through redsocks/iptables at all -- so it tests the proxy itself, not
this box's transparent-proxy path. Results never include the profile's
credentials. Stdlib-only.
"""
import base64
import json
import socket
import ssl
import time

# Fixed, neutral target for the connectivity check -- any reachable HTTPS
# host works equally well here, since this only proves the tunnel carries
# real TLS traffic end to end, not that any particular site is reachable.
PROXY_CHECK_HOST = "www.google.com"
PROXY_CHECK_PORT = 443
PROXY_CHECK_TIMEOUT = 8
# Reports the address the request arrived from, i.e. the proxy's exit IP,
# and its geolocated country. (ipinfo.io answered 406 for a commercial
# proxy's exit IP, and ipapi.co rate-limited it; api.country.is worked,
# checked live 2026-10-01.) Geolocation databases disagree about proxy IPs --
# one exit IP was put in one country here while a streaming service's own
# geo-check placed it in another -- so the country is only a hint, and a
# *change* is what's worth noticing.
EXIT_INFO_HOST = "api.country.is"
EXIT_INFO_PATH = "/"


def _socks5_connect(sock, dest_host, dest_port, login, password):
    # RFC 1928 (CONNECT) + RFC 1929 (username/password auth)
    methods = b"\x02\x00" if login else b"\x00"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    resp = sock.recv(2)
    if len(resp) != 2 or resp[0] != 0x05:
        raise RuntimeError("SOCKS5 greeting failed")
    method = resp[1]
    if method == 0xFF:
        raise RuntimeError("SOCKS5 server rejected all offered auth methods")
    if method == 0x02:
        user_b = login.encode()
        pass_b = (password or "").encode()
        sock.sendall(b"\x01" + bytes([len(user_b)]) + user_b + bytes([len(pass_b)]) + pass_b)
        auth_resp = sock.recv(2)
        if len(auth_resp) != 2 or auth_resp[1] != 0x00:
            raise RuntimeError("SOCKS5 authentication failed")

    host_b = dest_host.encode()
    req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + dest_port.to_bytes(2, "big")
    sock.sendall(req)
    resp = sock.recv(4)
    if len(resp) < 4 or resp[0] != 0x05:
        raise RuntimeError("SOCKS5 CONNECT failed: malformed reply")
    if resp[1] != 0x00:
        raise RuntimeError(f"SOCKS5 CONNECT rejected (reply code {resp[1]})")
    # Drain the bound-address field (its length depends on address type)
    # before treating the socket as a raw tunnel.
    atyp = resp[3]
    if atyp == 0x01:
        sock.recv(4 + 2)
    elif atyp == 0x03:
        n = sock.recv(1)[0]
        sock.recv(n + 2)
    elif atyp == 0x04:
        sock.recv(16 + 2)
    else:
        raise RuntimeError(f"SOCKS5 CONNECT reply: unknown address type {atyp}")


def open_tunnel(profile, host, port, timings=None, timeout=PROXY_CHECK_TIMEOUT):
    """TLS connection to host:port *through* the profile's proxy (HTTP CONNECT
    or SOCKS5, Basic auth sent up front). The proxy resolves `host` itself,
    so it's reached from the proxy's side of the world. Fills `timings` (ms)
    per phase as it goes, so a failure still reports how far it got."""
    timings = {} if timings is None else timings
    ip = profile["ip"]
    proxy_port = int(profile["port"])
    proxy_type = profile.get("type", "http-connect")
    login = profile.get("login") or None
    password = profile.get("password") or None

    t0 = time.monotonic()
    try:
        sock = socket.create_connection((ip, proxy_port), timeout=timeout)
    except OSError as e:
        raise RuntimeError(f"Could not connect to proxy: {e}") from None
    sock.settimeout(timeout)
    t_connect = time.monotonic()
    timings["tcp_connect_ms"] = round((t_connect - t0) * 1000, 1)
    try:
        if proxy_type == "socks5":
            _socks5_connect(sock, host, port, login, password)
        else:
            req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n"
            if login:
                auth = base64.b64encode(f"{login}:{password or ''}".encode()).decode()
                req += f"Proxy-Authorization: Basic {auth}\r\n"
            req += "\r\n"
            sock.sendall(req.encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = sock.recv(4096)
                if not chunk:
                    raise RuntimeError("Proxy closed the connection during CONNECT")
                resp += chunk
            status_line = resp.split(b"\r\n", 1)[0].decode(errors="replace")
            if " 200 " not in status_line:
                raise RuntimeError(f"Proxy rejected CONNECT: {status_line}")
        t_proxy_connect = time.monotonic()
        timings["proxy_connect_ms"] = round((t_proxy_connect - t_connect) * 1000, 1)

        tls_sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        timings["tls_handshake_ms"] = round((time.monotonic() - t_proxy_connect) * 1000, 1)
        return tls_sock
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise


def _tunnel_request(profile, host, port, request, timings=None):
    """One TLS request to host:port through the profile's proxy; returns
    (first_byte_monotonic_time, response_bytes)."""
    timings = {} if timings is None else timings
    t0 = time.monotonic()
    tls_sock = open_tunnel(profile, host, port, timings)
    t_tls = time.monotonic()
    try:
        tls_sock.sendall(request.encode())
        first_byte_time, data = None, b""
        while True:
            chunk = tls_sock.recv(4096)
            if not chunk:
                break
            if first_byte_time is None:
                first_byte_time = time.monotonic()
            data += chunk
        if first_byte_time:
            timings["ttfb_ms"] = round((first_byte_time - t_tls) * 1000, 1)
        timings["total_ms"] = round((time.monotonic() - t0) * 1000, 1)
        return first_byte_time, data
    finally:
        try:
            tls_sock.close()
        except OSError:
            pass


def check_proxy_profile(profile):
    """Real connectivity + latency check for one saved proxy profile.

    Measures each phase separately -- TCP connect, proxy auth/CONNECT round
    trip, TLS handshake with a fixed external host, and time to first byte --
    since those are exactly the phases that turned out to matter when
    investigating real-world proxy latency (see
    troubleshooting/2026-09-30_proxy-connection-latency.pdf).
    """
    result = {"ok": False, "error": None, "timings": {}}
    try:
        int(profile["port"])
        profile["ip"]
    except (KeyError, ValueError, TypeError):
        result["error"] = "Invalid profile address/port"
        return result
    try:
        _tunnel_request(
            profile, PROXY_CHECK_HOST, PROXY_CHECK_PORT,
            f"HEAD / HTTP/1.1\r\nHost: {PROXY_CHECK_HOST}\r\nConnection: close\r\n\r\n",
            result["timings"],
        )
        result["ok"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


def get_exit_info(profile):
    """The public IP traffic through this proxy appears to come from, and
    that IP's geolocated country: {"ip", "country", "city", "org"} (city/org
    may be empty), or {"error": ...}."""
    try:
        _, data = _tunnel_request(
            profile, EXIT_INFO_HOST, 443,
            f"GET {EXIT_INFO_PATH} HTTP/1.1\r\nHost: {EXIT_INFO_HOST}\r\nAccept: */*\r\n"
            "User-Agent: rasp-proxy-health/1.0\r\nConnection: close\r\n\r\n",
        )
        head, _, body = data.partition(b"\r\n\r\n")
        if b" 200 " not in head.split(b"\r\n", 1)[0]:
            return {"error": "exit-IP lookup failed: " + head.split(b"\r\n", 1)[0].decode(errors="replace")[:80]}
        if b"transfer-encoding: chunked" in head.lower():
            body = _dechunk(body)
        info = json.loads(body.decode())
        return {k: str(info.get(k, ""))[:80] for k in ("ip", "country", "city", "org")}
    except Exception as e:
        return {"error": f"exit-IP lookup failed: {e}"[:160]}


def _dechunk(body):
    out = b""
    while body:
        size_line, _, rest = body.partition(b"\r\n")
        size = int(size_line.split(b";")[0] or b"0", 16)
        if size == 0:
            break
        out += rest[:size]
        body = rest[size + 2:]
    return out
