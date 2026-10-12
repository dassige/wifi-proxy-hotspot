import json
import socket
import struct
import subprocess

import dns.message
import dns.rrset
import pytest

import dns_router


@pytest.fixture(autouse=True)
def clean_state():
    dns_router._tagged.clear()
    dns_router._lookups.clear()
    yield
    dns_router._tagged.clear()
    dns_router._lookups.clear()


def reply(name, ips):
    r = dns.message.make_response(dns.message.make_query(name, "A"))
    r.answer.append(dns.rrset.from_text_list(name + ".", 30, "IN", "A", ips))
    return r


def ip_udp(src, dst, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + udp


def query(name, rtype="A"):
    return dns.message.make_query(name, rtype).to_wire()


# --- tagging (synchronous, only for IPs not tagged recently) -------------------

def test_new_ips_tagged_in_one_ipset_restore(fake_run):
    dns_router.tag_response(reply("a.netrw.it", ["45.139.96.1", "45.139.96.2"]), "wpx_x")
    assert [c["cmd"] for c in fake_run.calls] == [["ipset", "-exist", "restore"]]
    assert fake_run.calls[0]["input"] == "add wpx_x 45.139.96.1\nadd wpx_x 45.139.96.2\n"


def test_repeat_lookup_is_not_retagged_but_new_ip_is(fake_run):
    dns_router.tag_response(reply("a.netrw.it", ["45.139.96.1"]), "wpx_x")
    dns_router.tag_response(reply("a.netrw.it", ["45.139.96.1"]), "wpx_x")
    dns_router.tag_response(reply("a.netrw.it", ["45.139.96.1", "45.139.96.3"]), "wpx_x")
    assert [c["input"] for c in fake_run.calls] == ["add wpx_x 45.139.96.1\n", "add wpx_x 45.139.96.3\n"]


def test_same_ip_other_set_and_stale_tag_are_tagged(fake_run):
    dns_router.tag_response(reply("a.it", ["1.2.3.4"]), "wpx_x")
    dns_router.tag_response(reply("a.it", ["1.2.3.4"]), "wpx_y")
    dns_router._tagged[("wpx_x", "1.2.3.4")] -= dns_router.TAG_REFRESH_SECONDS + 1
    dns_router.tag_response(reply("a.it", ["1.2.3.4"]), "wpx_x")
    assert len(fake_run.calls) == 3


def test_failed_or_crashing_ipset_is_not_remembered_and_never_raises(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", ""))
    dns_router.tag_response(reply("b.it", ["1.2.3.4"]), "wpx_y")
    assert ("wpx_y", "1.2.3.4") not in dns_router._tagged

    def boom(*a, **k):
        raise subprocess.TimeoutExpired("ipset", 1)

    monkeypatch.setattr(subprocess, "run", boom)
    dns_router.tag_response(reply("b.it", ["1.2.3.4"]), "wpx_y")  # must not raise


# --- passive capture of devices' DNS queries -----------------------------------

def test_bpf_program_encodes_and_jumps_land_on_returns():
    prog = dns_router._BPF_UDP_DPORT_53
    assert len(b"".join(struct.pack("HBBI", *i) for i in prog)) == 8 * len(prog)
    for idx, (op, jt, jf, _) in enumerate(prog):
        if op in (0x15, 0x45):  # conditional jumps
            for off in (jt, jf):
                assert idx + 1 + off < len(prog)
    drop = len(prog) - 1
    assert prog[drop] == (0x06, 0, 0, 0) and prog[drop - 1][0] == 0x06
    assert 1 + 1 + prog[1][2] == drop and 3 + 1 + prog[3][1] == drop and 6 + 1 + prog[6][2] == drop


@pytest.mark.parametrize("packet,expected", [
    (ip_udp("192.168.4.71", "192.168.4.1", 5555, 53, query("RaiCinque1-Push.cdn.netrw.it.")),
     ("192.168.4.71", "raicinque1-push.cdn.netrw.it", "192.168.4.1")),
    (ip_udp("192.168.4.71", "8.8.8.8", 5555, 53, query("www.tv8.it")), ("192.168.4.71", "www.tv8.it", "8.8.8.8")),
])
def test_parse_dns_query(packet, expected):
    assert dns_router.parse_dns_query(packet) == expected


@pytest.mark.parametrize("packet", [
    ip_udp("192.168.4.71", "192.168.4.1", 53, 5555, query("x.it")),                       # not to port 53
    ip_udp("192.168.4.71", "192.168.4.1", 5555, 53,
           dns.message.make_response(dns.message.make_query("x.it", "A")).to_wire()),     # a response
    ip_udp("192.168.4.71", "192.168.4.1", 5555, 53, query("71.4.168.192.in-addr.arpa", "PTR")),
    ip_udp("192.168.4.71", "192.168.4.1", 5555, 53, query("wpad")),                       # single label
    ip_udp("192.168.4.71", "192.168.4.1", 5555, 53, query("<script>alert(1)</script>.evil.com")),
    ip_udp("192.168.4.71", "192.168.4.1", 5555, 53, b"\x00\x01garbage"),
    b"\x45short",
])
def test_parse_dns_query_rejects(packet):
    assert dns_router.parse_dns_query(packet) is None


def test_record_lookup_limits_and_bypass(monkeypatch):
    monkeypatch.setattr(dns_router, "LOOKUPS_PER_CLIENT", 3)
    monkeypatch.setattr(dns_router, "LOOKUPS_MAX_CLIENTS", 2)
    for n in ["a.it", "b.it", "c.it", "a.it", "d.it"]:
        dns_router.record_lookup("192.168.4.71", n, "192.168.4.1", "192.168.4.1")
    names = dns_router._lookups["192.168.4.71"]
    assert list(names) == ["c.it", "a.it", "d.it"] and names["a.it"]["count"] == 2
    dns_router.record_lookup("192.168.4.71", "a.it", "8.8.8.8", "192.168.4.1")
    assert names["a.it"]["bypass"] == ["8.8.8.8"]
    dns_router.record_lookup("192.168.4.80", "x.it", "1.1.1.1", None)   # AP IP unknown: no bypass flag
    assert dns_router._lookups["192.168.4.80"]["x.it"]["bypass"] == []
    dns_router.record_lookup("192.168.4.90", "y.it", "192.168.4.1", "192.168.4.1")
    assert list(dns_router._lookups) == ["192.168.4.80", "192.168.4.90"]      # oldest client evicted


def test_write_snapshot_is_atomic_json(tmp_path, monkeypatch):
    path = tmp_path / "lookups.json"
    monkeypatch.setattr(dns_router, "LOOKUPS_FILE", str(path))
    dns_router.write_snapshot({"generated": 1, "capture": "ok", "clients": {}})
    assert json.loads(path.read_text())["capture"] == "ok"
    assert not (tmp_path / "lookups.json.tmp").exists()


def test_capture_status_change_marks_snapshot_dirty():
    dns_router._lookups_dirty = False
    dns_router.set_capture_status("ok-test")
    assert dns_router._lookups_dirty and dns_router._capture_status == "ok-test"
