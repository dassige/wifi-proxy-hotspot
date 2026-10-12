"""Batch F: device nicknames and per-device routing policies."""
import copy
import json
import subprocess
import sys

import pytest

from conftest import SAMPLE_PROFILES, load_script, sample_rules
from test_app_render import check_page, render_page

fw = load_script("rasp-proxy-rebuild-firewall.py", "rebuild_firewall_devices")
health = load_script("rasp-proxy-health.py", "rasp_proxy_health_devices")
TV = "aa:bb:cc:dd:ee:01"
PHONE = "aa:bb:cc:dd:ee:02"


# --- firewall ----------------------------------------------------------------------

@pytest.fixture
def fw_rules(tmp_path, monkeypatch):
    rules = tmp_path / "pattern_rules.json"
    (tmp_path / "proxies.json").write_text(json.dumps({"profiles": {"Remote": {"local_port": 20000}}}))
    rules.write_text(json.dumps({
        "bypass_cidr": "192.168.1.0/24", "default_action": "direct",
        "rules": [{"id": "r1", "action": "Remote", "enabled": True}],
        "device_policies": {TV.upper(): "Remote", PHONE: "direct", "not-a-mac": "Remote", "aa:bb:cc:dd:ee:03": "gone"},
    }))
    monkeypatch.setattr(fw, "PROXY_STORE", str(tmp_path / "proxies.json"))
    monkeypatch.setattr(fw, "RULES_FILE", str(rules))
    monkeypatch.setattr(sys, "argv", ["rasp-proxy-rebuild-firewall", "wlan0"])


def chain(fake, table, name):
    return [c[c.index(name) + 1:] for c in fake.commands("iptables")
            if c[2] == table and "-A" in c and c[c.index("-A") + 1] == name]


def test_device_policies_come_after_bypass_and_before_rules(fake_run, fw_rules):
    fw.main()
    assert chain(fake_run, "nat", "REDSOCKS") == [
        ["-d", "192.168.1.0/24", "-j", "RETURN"],
        ["-p", "tcp", "-m", "mac", "--mac-source", TV, "-j", "REDIRECT", "--to-ports", "20000"],
        ["-m", "mac", "--mac-source", PHONE, "-j", "RETURN"],
        ["-m", "mac", "--mac-source", "aa:bb:cc:dd:ee:03", "-j", "RETURN"],  # missing profile: fail safe
        ["-p", "tcp", "-m", "set", "--match-set", "wpx_r1", "dst", "-j", "REDIRECT", "--to-ports", "20000"],
        ["-j", "RETURN"],
    ]
    quic = chain(fake_run, "filter", "WPXQUIC")
    assert quic[1] == ["-m", "mac", "--mac-source", TV, "-j", "REJECT", "--reject-with", "icmp-port-unreachable"]
    assert quic[2] == ["-m", "mac", "--mac-source", PHONE, "-j", "RETURN"]


def test_health_counts_device_policies_in_expected_chain_size(monkeypatch):
    def run(cmd, timeout=15):
        if "-S" in cmd:
            n = {"REDSOCKS": 5, "WPXQUIC": 5}.get(cmd[-1], 0)
            return subprocess.CompletedProcess(cmd, 0, f"-N {cmd[-1]}\n" + f"-A {cmd[-1]} x\n" * n, "")
        if cmd[:3] == ["ipset", "list", "-n"]:
            return subprocess.CompletedProcess(cmd, 0, "wpx_r1\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(health, "run", run)
    rules = [{"id": "r1", "enabled": True}]
    tile = health.check_firewall(rules, device_policies=2)[0]
    assert tile["status"] == "ok" and "2 device policies" in tile["detail"]
    assert health.check_firewall(rules, device_policies=0)[0]["status"] == "fail"


# --- panel logic --------------------------------------------------------------------

@pytest.fixture
def env(app_module, monkeypatch, tmp_path):
    rules_path = tmp_path / "pattern_rules.json"
    rules_path.write_text(json.dumps({"bypass_cidr": "192.168.1.0/24", "default_action": "direct", "rules": [
        {"id": "r1", "patterns": ["*.a.it"], "mode": "wildcard", "action": "Backup Proxy", "description": "A", "enabled": True}]}))
    devices_path = tmp_path / "devices.json"
    devices_path.write_text(json.dumps({TV: {"mac": TV, "hostname": "android-box"}, PHONE: {"mac": PHONE}}))
    profiles_path = tmp_path / "proxies.json"
    profiles_path.write_text(json.dumps({"next_port": 20002, "profiles": copy.deepcopy(SAMPLE_PROFILES)}))
    monkeypatch.setattr(app_module, "PATTERN_RULES_FILE", str(rules_path))
    monkeypatch.setattr(app_module, "DEVICES_STORE", str(devices_path))
    monkeypatch.setattr(app_module, "PROXY_STORE", str(profiles_path))
    monkeypatch.setattr(app_module, "rebuild_firewall", lambda: None)
    monkeypatch.setattr(app_module, "write_redsocks_conf_all", lambda p: None)
    monkeypatch.setattr(app_module.os, "chmod", lambda *a: None)
    return {"rules": rules_path, "devices": devices_path, "profiles": profiles_path}


def stored(path):
    return json.loads(path.read_text())


def test_set_and_clear_a_device_policy(app_module, env):
    msg, err = app_module.set_device_policy(TV, "Remote Proxy")
    assert err is None and 'through "Remote Proxy"' in msg
    assert stored(env["rules"])["device_policies"] == {TV: "Remote Proxy"}
    app_module.set_default_action("direct")                                  # unrelated save keeps it
    assert stored(env["rules"])["device_policies"] == {TV: "Remote Proxy"}
    msg, err = app_module.set_device_policy(TV, "")
    assert "follows the rules" in msg and stored(env["rules"])["device_policies"] == {}


@pytest.mark.parametrize("mac,action,error", [
    ("ff:ff:ff:ff:ff:ff", "direct", "Unknown device"),
    (TV, "nope", "Unknown routing choice"),
])
def test_device_policy_validation(app_module, env, mac, action, error):
    assert app_module.set_device_policy(mac, action) == (None, error)


def test_disabled_profile_cannot_be_chosen(app_module, env):
    data = stored(env["profiles"])
    data["profiles"]["Backup Proxy"]["enabled"] = False
    env["profiles"].write_text(json.dumps(data))
    msg, err = app_module.set_device_policy(TV, "Backup Proxy")
    assert msg is None and "is disabled" in err


def test_profile_used_by_a_device_cannot_be_deleted(app_module, env):
    app_module.set_device_policy(PHONE, "Remote Proxy")
    err = app_module.delete_proxy_profile("Remote Proxy")
    assert err and f'device "{PHONE}" (Devices page)' in err


def test_disabling_a_profile_releases_its_devices(app_module, env):
    app_module.set_device_nickname(TV, "Living-room TV")
    app_module.set_device_policy(TV, "Backup Proxy")
    msg, err = app_module.set_profile_enabled("Backup Proxy", False)
    assert err is None and "1 device that always used it now follows the rules: Living-room TV" in msg
    assert "switched off 1 pattern rule" in msg
    assert stored(env["rules"])["device_policies"] == {}


def test_nicknames_are_tidied_and_clearable(app_module, env):
    assert app_module.set_device_nickname(TV, "  Living   room\tTV  ")
    assert stored(env["devices"])[TV]["nickname"] == "Living room TV"
    app_module.set_device_nickname(TV, "x" * 100)
    assert len(stored(env["devices"])[TV]["nickname"]) == app_module.NICKNAME_MAX
    app_module.set_device_nickname(TV, "   ")
    assert "nickname" not in stored(env["devices"])[TV]
    assert not app_module.set_device_nickname("ff:ff:ff:ff:ff:ff", "x")


def test_lookups_show_nickname_and_device_override(app_module, env, monkeypatch):
    app_module.set_device_nickname(TV, "Living-room TV")
    app_module.set_device_policy(TV, "Remote Proxy")
    monkeypatch.setattr(app_module, "get_lease_map", lambda: {"192.168.4.71": (TV, ""), "192.168.4.80": (PHONE, "")})
    monkeypatch.setattr(app_module, "read_lookups_snapshot", lambda: {"generated": 9e12, "capture": "ok", "clients": {
        "192.168.4.71": [{"name": "www.bbc.co.uk", "count": 1, "last": 2}],
        "192.168.4.80": [{"name": "www.bbc.co.uk", "count": 1, "last": 1}]}})
    v = app_module.get_lookups_view()
    by_ip = {e["ip"]: e for e in v["entries"]}
    assert by_ip["192.168.4.71"]["device"] == "Living-room TV (192.168.4.71)"
    assert by_ip["192.168.4.71"]["proxied"] and by_ip["192.168.4.71"]["via"] == "device setting"
    assert not by_ip["192.168.4.80"]["proxied"] and by_ip["192.168.4.80"]["via"] == "default"


def test_tester_mentions_pinned_devices(app_module, env):
    app_module.set_device_nickname(TV, "Living-room TV")
    app_module.set_device_policy(TV, "direct")
    notes = app_module.explain_hostname("x.a.it")["notes"]
    assert any("1 device with their own routing setting" in n and "Living-room TV" in n for n in notes)


# --- page ------------------------------------------------------------------------------

def test_devices_table_routing_and_rename(app_module, monkeypatch, tmp_path):
    devices = {TV: {"mac": TV, "hostname": "laptop", "nickname": "<b>Dad's</b> laptop"}}
    profiles = copy.deepcopy(SAMPLE_PROFILES)
    profiles["Backup Proxy"]["enabled"] = False
    html = render_page(app_module, monkeypatch, profiles=profiles, devices=devices,
                       config_extra={"device_policies": {TV: "Remote Proxy"}})
    check_page(html, tmp_path)
    assert "&lt;b&gt;Dad&#39;s&lt;/b&gt; laptop" in html and "<b>Dad's</b>" not in html   # escaped
    assert '<option value="Remote Proxy" selected>Always through Remote Proxy</option>' in html
    assert '<option value="Backup Proxy" disabled>Always through Backup Proxy (disabled)</option>' in " ".join(html.split())
    assert 'action="/device/rename"' in html and 'class="policy-set"' in html
    assert """data-devices='["\\u003cb\\u003eDad\\u0027s\\u003c/b\\u003e laptop"]'""" in html
