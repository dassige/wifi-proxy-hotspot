"""Batch E: leak guards (forced DNS + DoT block, iCloud Private Relay and
Firefox DoH canary, IPv6 block)."""
import json
import subprocess
import sys

import dns.message
import dns.rcode
import pytest

import dns_router
from conftest import FakeRun, load_script
from test_app_render import check_page, render_page

fw = load_script("rasp-proxy-rebuild-firewall.py", "rebuild_firewall_guards")
health = load_script("rasp-proxy-health.py", "rasp_proxy_health_guards")


@pytest.fixture
def fw_config(tmp_path, monkeypatch):
    rules = tmp_path / "pattern_rules.json"
    (tmp_path / "proxies.json").write_text(json.dumps({"profiles": {"Remote": {"local_port": 20000}}}))
    monkeypatch.setattr(fw, "PROXY_STORE", str(tmp_path / "proxies.json"))
    monkeypatch.setattr(fw, "RULES_FILE", str(rules))
    monkeypatch.setattr(sys, "argv", ["rasp-proxy-rebuild-firewall", "wlan0"])

    def write(**guards):
        data = {"bypass_cidr": "192.168.1.0/24", "default_action": "direct", "rules": []}
        if guards:
            data["leak_guards"] = guards
        rules.write_text(json.dumps(data))

    write()
    return write


def appended(fake, cmd, table, chain):
    return [c[c.index(chain) + 1:] for c in fake.commands(cmd)
            if "-t" in c and c[c.index("-t") + 1] == table and "-A" in c and c[c.index("-A") + 1] == chain]


def test_all_guards_on_by_default(fake_run, fw_config):
    fw.main()
    assert appended(fake_run, "iptables", "nat", "WPXDNS") == [
        ["-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN"],
        ["-d", "192.168.1.0/24", "-j", "RETURN"],
        ["-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"],
        ["-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"],
    ]
    assert appended(fake_run, "iptables", "filter", "WPXGUARD") == [
        ["-d", "192.168.1.0/24", "-j", "RETURN"],
        ["-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset"],
        ["-p", "udp", "--dport", "853", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"],
    ]
    assert appended(fake_run, "ip6tables", "filter", "WPXGUARD6") == [
        ["-j", "REJECT", "--reject-with", "icmp6-adm-prohibited"]]


def test_hooks_go_to_the_top_so_dns_redirect_beats_redsocks(fake_run, fw_config):
    fake_run.responses = [(["iptables", "-t", "nat", "-C"], "", 1), (["iptables", "-t", "filter", "-C"], "", 1),
                          (["ip6tables", "-t", "filter", "-C"], "", 1)]
    fw.main()
    cmds = fake_run.calls
    assert ["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-i", "wlan0", "-j", "WPXDNS"] in [c["cmd"] for c in cmds]
    assert ["iptables", "-t", "filter", "-I", "FORWARD", "1", "-i", "wlan0", "-j", "WPXGUARD"] in [c["cmd"] for c in cmds]
    assert ["ip6tables", "-t", "filter", "-I", "FORWARD", "1", "-i", "wlan0", "-j", "WPXGUARD6"] in [c["cmd"] for c in cmds]
    # inserted at position 1 *after* REDSOCKS was appended, so it ends up first in PREROUTING
    redsocks_hook = next(i for i, c in enumerate(cmds) if c["cmd"][3:5] == ["-A", "PREROUTING"])
    dns_hook = next(i for i, c in enumerate(cmds) if c["cmd"][3:6] == ["-I", "PREROUTING", "1"])
    save = next(i for i, c in enumerate(cmds) if c["cmd"][0] == "netfilter-persistent")
    assert redsocks_hook < dns_hook < save


def test_guards_off_leave_empty_but_hooked_chains(fake_run, fw_config):
    fw_config(dns=False, private_relay=False, ipv6=False)
    fw.main()
    assert appended(fake_run, "iptables", "nat", "WPXDNS") == []
    assert appended(fake_run, "iptables", "filter", "WPXGUARD") == []
    assert appended(fake_run, "ip6tables", "filter", "WPXGUARD6") == []
    flushed = [c for c in fake_run.commands() if "-F" in c]
    assert {c[c.index("-F") + 1] for c in flushed} >= {"WPXDNS", "WPXGUARD", "WPXGUARD6"}


def test_missing_ip6tables_does_not_break_the_rebuild(fw_config, monkeypatch):
    fake = FakeRun()

    def run(cmd, *a, **k):
        if cmd[0] == "ip6tables":
            raise FileNotFoundError("ip6tables")
        return fake(cmd, *a, **k)

    monkeypatch.setattr(subprocess, "run", run)
    fw.main()                                                   # must not raise
    assert any(c[0] == "netfilter-persistent" for c in fake.commands())


# --- dns_router answers ----------------------------------------------------------

@pytest.fixture
def router(tmp_path, monkeypatch, fake_run):
    rules = tmp_path / "rules.json"
    monkeypatch.setattr(dns_router, "RULES_FILE", str(rules))
    monkeypatch.setattr(dns_router, "PROXY_STORE", str(tmp_path / "none.json"))
    upstream = []

    def fake_udp(request, server, timeout=None):
        upstream.append(str(request.question[0].name))
        return dns.message.make_response(request)

    monkeypatch.setattr(dns_router.dns.query, "udp", fake_udp)

    def configure(**guards):
        rules.write_text(json.dumps({"rules": [], "leak_guards": guards}))
        dns_router._rules_cache["mtime"] = None

    configure()
    return configure, upstream


@pytest.mark.parametrize("name,guard", [("mask.icloud.com", "private_relay"), ("mask-h2.icloud.com", "private_relay"),
                                        ("use-application-dns.net", "dns")])
def test_guarded_names_get_nxdomain_and_are_counted(router, name, guard):
    configure, upstream = router
    before = dns_router._guard_hits[guard]
    reply = dns.message.from_wire(dns_router.handle_query(dns.message.make_query(name, "A").to_wire(), ["192.168.1.1"]))
    assert reply.rcode() == dns.rcode.NXDOMAIN and upstream == []
    assert dns_router._guard_hits[guard] == before + 1
    configure(**{guard: False})
    reply = dns.message.from_wire(dns_router.handle_query(dns.message.make_query(name, "A").to_wire(), ["192.168.1.1"]))
    assert reply.rcode() == dns.rcode.NOERROR and upstream == [name + "."]


def test_other_icloud_names_are_untouched(router):
    _, upstream = router
    dns_router.handle_query(dns.message.make_query("www.icloud.com", "A").to_wire(), ["192.168.1.1"])
    assert upstream == ["www.icloud.com."]


# --- panel ------------------------------------------------------------------------

def test_settings_default_on_and_survive_saves(app_module, monkeypatch, tmp_path):
    path = tmp_path / "pattern_rules.json"
    monkeypatch.setattr(app_module, "PATTERN_RULES_FILE", str(path))
    monkeypatch.setattr(app_module, "rebuild_firewall", lambda: None)
    path.write_text(json.dumps({"bypass_cidr": "192.168.1.0/24", "default_action": "direct", "rules": []}))
    assert app_module.load_pattern_config()["leak_guards"] == {"dns": True, "private_relay": True, "ipv6": True}
    monkeypatch.setattr(app_module, "render", lambda message="", **k: message)
    with app_module.app.test_request_context("/leak-guard", method="POST", data={"name": "private_relay", "enabled": "0"}):
        assert "turned off" in app_module.leak_guard_route.__wrapped__()
    app_module.set_default_action("direct")                    # an unrelated save keeps it
    assert json.loads(path.read_text())["leak_guards"]["private_relay"] is False
    with app_module.app.test_request_context("/leak-guard", method="POST", data={"name": "evil", "enabled": "0"}):
        assert app_module.leak_guard_route.__wrapped__()[1] == 400


def test_page_section_and_counts(app_module, monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "read_health_status", lambda: {"guard_counters": {"dns": 14, "ipv6": 0}})
    monkeypatch.setattr(app_module, "read_lookups_snapshot", lambda: {"guard_hits": {"private_relay": 3}})
    html = render_page(app_module, monkeypatch)
    check_page(html, tmp_path)
    assert html.count('action="/leak-guard"') == 3
    assert "14 attempts caught since the rules last changed" in html
    assert "3 attempts caught" in html and "0 attempts" not in html


# --- health -------------------------------------------------------------------------

def guard_box(monkeypatch, counts, hooks_ok=True):
    def run(cmd, timeout=15):
        if "-S" in cmd:
            chain = cmd[-1]
            out = f"-N {chain}\n" + f"-A {chain} x\n" * counts.get(chain, 0)
            return subprocess.CompletedProcess(cmd, 0, out, "")
        if "-C" in cmd:
            return subprocess.CompletedProcess(cmd, 0 if hooks_ok else 1, "", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(health, "run", run)


def test_health_guards_ok_missing_and_off(monkeypatch):
    full = {"WPXDNS": 4, "WPXGUARD": 3, "WPXGUARD6": 1}
    guard_box(monkeypatch, full)
    tile = health.check_leak_guards({})[0]
    assert tile["status"] == "ok" and tile["detail"] == "DNS forced through the hotspot, Private Relay blocked, IPv6 blocked"
    guard_box(monkeypatch, dict(full, WPXDNS=0))
    tile = health.check_leak_guards({})[0]
    assert tile["status"] == "fail" and "DNS redirect incomplete" in tile["detail"] and tile["alert"]
    guard_box(monkeypatch, {}, hooks_ok=False)
    tile = health.check_leak_guards({"leak_guards": {"dns": False, "private_relay": False, "ipv6": False}})[0]
    assert tile["status"] == "warn" and not tile["alert"]
    guard_box(monkeypatch, full)
    assert "(1 switched off)" in health.check_leak_guards({"leak_guards": {"ipv6": False}})[0]["detail"]


def test_health_guard_counters(monkeypatch):
    listings = {
        "WPXDNS": "Chain WPXDNS (1 references)\n pkts bytes target prot opt in out source destination\n"
                  "  900 54000 RETURN all -- * * 0.0.0.0/0 0.0.0.0/0 ADDRTYPE match dst-type LOCAL\n"
                  "    9   540 REDIRECT udp -- * * 0.0.0.0/0 0.0.0.0/0 udp dpt:53 redir ports 53\n"
                  "    1    60 REDIRECT tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:53 redir ports 53\n",
        "WPXGUARD": "Chain WPXGUARD (1 references)\n pkts bytes target prot opt in out source destination\n"
                    "    4   240 REJECT tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:853 reject-with tcp-reset\n",
        "WPXGUARD6": "Chain WPXGUARD6 (1 references)\n pkts bytes target prot opt in out source destination\n"
                     "    2   160 REJECT all * * ::/0 ::/0 reject-with icmp6-adm-prohibited\n",
    }
    monkeypatch.setattr(health, "run", lambda cmd, timeout=15: subprocess.CompletedProcess(cmd, 0, listings[cmd[4]], ""))
    assert health.read_guard_counters() == {"dns": 14, "ipv6": 2}
