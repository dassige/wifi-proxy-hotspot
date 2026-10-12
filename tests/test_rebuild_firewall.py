import io
import json
import signal
import sys

import pytest

from conftest import load_script

fw = load_script("rasp-proxy-rebuild-firewall.py", "rebuild_firewall")


@pytest.fixture
def config(tmp_path, monkeypatch):
    profiles = tmp_path / "proxies.json"
    rules = tmp_path / "pattern_rules.json"
    profiles.write_text(json.dumps({"profiles": {"Remote": {"local_port": 20000}, "AWS": {"local_port": 20001}}}))
    rules.write_text(json.dumps({
        "bypass_cidr": "192.168.1.0/24",
        "default_action": "direct",
        "rules": [
            {"id": "r1", "action": "Remote", "enabled": True},
            {"id": "r2", "action": "AWS", "enabled": False},   # disabled: skipped entirely
            {"id": "r3", "action": "gone", "enabled": True},   # missing profile: fail safe to direct
            {"id": "r4", "action": "direct"},                  # no "enabled" key means enabled
        ],
    }))
    monkeypatch.setattr(fw, "PROXY_STORE", str(profiles))
    monkeypatch.setattr(fw, "RULES_FILE", str(rules))
    monkeypatch.setattr(sys, "argv", ["rasp-proxy-rebuild-firewall", "wlan0"])
    return rules


def chain(fake, table, name):
    return [c[c.index(name) + 1:] for c in fake.commands("iptables")
            if c[2] == table and "-A" in c and c[c.index("-A") + 1] == name]


def test_redsocks_chain_order_and_targets(fake_run, config):
    fw.main()
    assert chain(fake_run, "nat", "REDSOCKS") == [
        ["-d", "192.168.1.0/24", "-j", "RETURN"],
        ["-p", "tcp", "-m", "set", "--match-set", "wpx_r1", "dst", "-j", "REDIRECT", "--to-ports", "20000"],
        ["-m", "set", "--match-set", "wpx_r3", "dst", "-j", "RETURN"],
        ["-m", "set", "--match-set", "wpx_r4", "dst", "-j", "RETURN"],
        ["-j", "RETURN"],
    ]


def test_quic_chain_mirrors_redsocks(fake_run, config):
    fw.main()
    assert chain(fake_run, "filter", "WPXQUIC") == [
        ["-d", "192.168.1.0/24", "-j", "RETURN"],
        ["-m", "set", "--match-set", "wpx_r1", "dst", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"],
        ["-m", "set", "--match-set", "wpx_r3", "dst", "-j", "RETURN"],
        ["-m", "set", "--match-set", "wpx_r4", "dst", "-j", "RETURN"],
        ["-j", "RETURN"],
    ]


def test_proxied_default_redirects_catch_all(fake_run, config):
    data = json.loads(config.read_text())
    data["default_action"] = "Remote"
    config.write_text(json.dumps(data))
    fw.main()
    assert chain(fake_run, "nat", "REDSOCKS")[-1] == ["-p", "tcp", "-j", "REDIRECT", "--to-ports", "20000"]
    assert chain(fake_run, "filter", "WPXQUIC")[-1] == ["-j", "REJECT", "--reject-with", "icmp-port-unreachable"]


def test_persist_only_after_both_chains_then_prune(fake_run, config):
    fake_run.responses = [(["ipset", "list", "-n"], "wpx_r1\nwpx_old\nwpx_r3\nwpx_r4\nnot_ours\n")]
    fw.main()
    cmds = fake_run.calls
    save = next(i for i, c in enumerate(cmds) if c["cmd"][:2] == ["netfilter-persistent", "save"])
    last_redsocks = max(i for i, c in enumerate(cmds) if "REDSOCKS" in c["cmd"])
    last_quic = max(i for i, c in enumerate(cmds) if "WPXQUIC" in c["cmd"])
    assert last_redsocks < last_quic < save
    assert [c["cmd"] for c in cmds if c["cmd"][:2] == ["ipset", "destroy"]] == [["ipset", "destroy", "wpx_old"]]
    assert ["ipset", "create", "wpx_r2", "hash:ip", "family", "inet", "timeout", "86400", "-exist"] not in \
        [c["cmd"] for c in cmds]


def test_hooks_added_only_when_missing(fake_run, config):
    fake_run.responses = [(["iptables", "-t", "nat", "-C"], "", 1), (["iptables", "-t", "filter", "-C"], "", 1)]
    fw.main()
    cmds = fake_run.commands("iptables")
    assert ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", "wlan0", "-p", "tcp", "-j", "REDSOCKS"] in cmds
    assert ["iptables", "-t", "filter", "-I", "FORWARD", "1", "-i", "wlan0", "-p", "udp", "--dport", "443",
            "-j", "WPXQUIC"] in cmds


@pytest.mark.parametrize("argv", [["x"], ["x", "wlan0; rm -rf /"]])
def test_rejects_bad_arguments(fake_run, config, monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit):
        fw.main()
    assert fake_run.calls == []


def test_rejects_bad_bypass_cidr(fake_run, config):
    data = json.loads(config.read_text())
    data["bypass_cidr"] = "192.168.1.0/99"
    config.write_text(json.dumps(data))
    with pytest.raises(SystemExit):
        fw.main()
    assert not any("REDSOCKS" in c for c in fake_run.commands("iptables"))


def test_flush_dns_cache_signals_only_real_dnsmasq(monkeypatch):
    files = {"/run/nm-dnsmasq-wlan0.pid": "5510\n", "/proc/5510/comm": "dnsmasq\n"}
    monkeypatch.setattr("builtins.open", lambda p, *a, **k: io.StringIO(files[p]) if p in files else (_ for _ in ()).throw(OSError(p)))
    killed = []
    monkeypatch.setattr(fw.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    monkeypatch.setattr(signal, "SIGHUP", getattr(signal, "SIGHUP", 1), raising=False)  # absent on Windows
    fw.flush_dns_cache("wlan0")
    assert killed == [(5510, signal.SIGHUP)]
    files["/proc/5510/comm"] = "python3\n"        # stale pidfile, PID reused
    fw.flush_dns_cache("wlan0")
    assert len(killed) == 1
    del files["/run/nm-dnsmasq-wlan0.pid"]         # dnsmasq not running (boot)
    fw.flush_dns_cache("wlan0")
    assert len(killed) == 1
