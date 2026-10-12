import base64
import socket
import threading

import pytest

import proxy_check


def serve_once(handler):
    """A one-connection TCP server on localhost; returns its port and what it received."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    seen = {}

    def run():
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(5)
            handler(conn, seen)
        srv.close()

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1], seen


def read_headers(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def profile(port, **kw):
    return dict({"type": "http-connect", "ip": "127.0.0.1", "port": str(port), "login": "", "password": ""}, **kw)


def test_http_connect_sends_basic_auth_up_front_and_reports_rejection_without_secrets():
    def handler(conn, seen):
        seen["request"] = read_headers(conn)
        conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")

    port, seen = serve_once(handler)
    result = proxy_check.check_proxy_profile(profile(port, login="user1", password="pa55"))
    assert not result["ok"] and "407" in result["error"]
    assert "tcp_connect_ms" in result["timings"]
    expected = base64.b64encode(b"user1:pa55").decode()
    assert f"Proxy-Authorization: Basic {expected}".encode() in seen["request"]   # proactive, first request
    assert seen["request"].startswith(b"CONNECT www.google.com:443 HTTP/1.1\r\n")
    assert "pa55" not in str(result) and expected not in str(result)


def test_closed_proxy_port_is_reported():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    result = proxy_check.check_proxy_profile(profile(port))
    assert not result["ok"] and result["error"].startswith("Could not connect to proxy")


@pytest.mark.parametrize("bad", [{"ip": "x"}, {"ip": "x", "port": "abc"}])
def test_invalid_profile(bad):
    assert proxy_check.check_proxy_profile(bad)["error"] == "Invalid profile address/port"


def test_socks5_handshake_with_auth():
    def handler(conn, seen):
        seen["greeting"] = conn.recv(4)                             # ver 5, 2 methods: user/pass, none
        conn.sendall(b"\x05\x02")                                   # choose username/password
        seen["auth"] = conn.recv(1 + 1 + 2 + 1 + 3)
        conn.sendall(b"\x01\x00")
        seen["connect"] = conn.recv(4 + 1 + 9 + 2)
        conn.sendall(b"\x05\x00\x00\x01" + bytes(4) + b"\x00\x00")  # success, IPv4 bound address

    port, seen = serve_once(handler)
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    proxy_check._socks5_connect(sock, "ipinfo.io", 443, "ab", "xyz")
    sock.close()
    assert seen["greeting"] == b"\x05\x02\x02\x00"
    assert seen["auth"] == b"\x01\x02ab\x03xyz"
    assert seen["connect"] == b"\x05\x01\x00\x03\x09ipinfo.io\x01\xbb"


def test_socks5_rejected_connect():
    def handler(conn, seen):
        conn.recv(3)                                                # ver 5, 1 method: none
        conn.sendall(b"\x05\x00")
        conn.recv(64)
        conn.sendall(b"\x05\x05\x00\x01" + bytes(6))                # connection refused

    port, _ = serve_once(handler)
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    with pytest.raises(RuntimeError, match="reply code 5"):
        proxy_check._socks5_connect(sock, "x.it", 443, None, None)
    sock.close()


@pytest.mark.parametrize("raw,expected", [
    (b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ip":"203.0.113.10","country":"DE"}',
     {"ip": "203.0.113.10", "country": "DE", "city": "", "org": ""}),
    (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n{"ip":"1.2.3.4",\r\n'
     b'10\r\n"country":"IT"} \r\n0\r\n\r\n', {"ip": "1.2.3.4", "country": "IT", "city": "", "org": ""}),
])
def test_exit_info_parsing(monkeypatch, raw, expected):
    monkeypatch.setattr(proxy_check, "_tunnel_request", lambda *a, **k: (0.0, raw))
    assert proxy_check.get_exit_info({"ip": "x", "port": "1"}) == expected


def test_exit_info_406_like_ipinfo_gave_live(monkeypatch):
    monkeypatch.setattr(proxy_check, "_tunnel_request",
                        lambda *a, **k: (0.0, b"HTTP/1.1 406 Not Acceptable\r\n\r\n"))
    assert proxy_check.get_exit_info({})["error"] == "exit-IP lookup failed: HTTP/1.1 406 Not Acceptable"
