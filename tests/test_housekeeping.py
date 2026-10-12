"""Batch H: complete backup/restore, and re-enabling a profile restoring what
disabling it switched off."""
import copy
import json

import pytest

import mailer
from conftest import SAMPLE_PROFILES
from test_app_render import check_page, render_page

TV = "aa:bb:cc:dd:ee:01"
PHONE = "aa:bb:cc:dd:ee:02"


@pytest.fixture
def env(app_module, monkeypatch, tmp_path):
    paths = {k: tmp_path / f"{k}.json" for k in ("rules", "devices", "profiles", "alerts")}
    paths["rules"].write_text(json.dumps({"bypass_cidr": "192.168.1.0/24", "default_action": "direct", "rules": [
        {"id": "r1", "patterns": ["*.a.it"], "pattern": "*.a.it", "mode": "wildcard", "action": "Backup Proxy", "description": "A", "enabled": True},
        {"id": "r2", "patterns": ["*.b.it"], "pattern": "*.b.it", "mode": "wildcard", "action": "Backup Proxy", "description": "B", "enabled": True},
        {"id": "r3", "patterns": ["*.c.it"], "pattern": "*.c.it", "mode": "wildcard", "action": "Remote Proxy", "description": "C", "enabled": True},
    ]}))
    paths["devices"].write_text(json.dumps({TV: {"mac": TV, "nickname": "Living-room TV"}, PHONE: {"mac": PHONE}}))
    paths["profiles"].write_text(json.dumps({"next_port": 20002, "profiles": copy.deepcopy(SAMPLE_PROFILES)}))
    monkeypatch.setattr(app_module, "PATTERN_RULES_FILE", str(paths["rules"]))
    monkeypatch.setattr(app_module, "DEVICES_STORE", str(paths["devices"]))
    monkeypatch.setattr(app_module, "PROXY_STORE", str(paths["profiles"]))
    monkeypatch.setattr(mailer, "ALERTS_FILE", str(paths["alerts"]))
    for name in ("rebuild_firewall", "write_redsocks_conf_all"):
        monkeypatch.setattr(app_module, name, lambda *a: None)
    monkeypatch.setattr(app_module.os, "chmod", lambda *a: None)
    denylist = []
    monkeypatch.setattr(app_module, "apply_device_denylist", lambda store: denylist.append(
        sorted(m for m, d in store.items() if d.get("blocked"))))
    paths["denylist"] = denylist
    return paths


def read(path):
    return json.loads(path.read_text())


# --- re-enable restores ----------------------------------------------------------------

def disable_aws(app_module):
    app_module.set_device_policy(TV, "Backup Proxy")
    msg, err = app_module.set_profile_enabled("Backup Proxy", False)
    assert err is None


def test_disable_remembers_what_it_switched_off(app_module, env):
    disable_aws(app_module)
    remembered = read(env["profiles"])["profiles"]["Backup Proxy"]["disabled_with"]
    assert remembered == {"rules": ["r1", "r2"], "devices": [TV]}
    labels = app_module.restore_labels("Backup Proxy", read(env["profiles"])["profiles"]["Backup Proxy"], app_module.load_pattern_config())
    assert labels == ["rule: A", "rule: B", "device: Living-room TV"]


def test_reenable_with_restore_puts_everything_back(app_module, env):
    disable_aws(app_module)
    msg, err = app_module.set_profile_enabled("Backup Proxy", True, restore=True)
    assert err is None and "2 rules switched back on and 1 device routed through it again" in msg
    rules = {r["id"]: r["enabled"] for r in read(env["rules"])["rules"]}
    assert rules == {"r1": True, "r2": True, "r3": True}
    assert read(env["rules"])["device_policies"] == {TV: "Backup Proxy"}
    assert "disabled_with" not in read(env["profiles"])["profiles"]["Backup Proxy"]


def test_restore_skips_what_was_changed_since(app_module, env):
    disable_aws(app_module)
    config = app_module.load_pattern_config()
    config["rules"][1]["action"] = "Remote Proxy"            # r2 now points elsewhere
    app_module.save_pattern_config(config)
    app_module.set_device_policy(TV, "direct")                # TV given another setting
    msg, err = app_module.set_profile_enabled("Backup Proxy", True, restore=True)
    assert "1 rule switched back on" in msg and "device" not in msg
    rules = {r["id"]: r["enabled"] for r in read(env["rules"])["rules"]}
    assert rules["r1"] is True and rules["r2"] is False
    assert read(env["rules"])["device_policies"] == {TV: "direct"}


def test_reenable_without_restore_leaves_them_off(app_module, env):
    disable_aws(app_module)
    msg, err = app_module.set_profile_enabled("Backup Proxy", True, restore=False)
    assert "stays off" in msg
    assert not any(r["enabled"] for r in read(env["rules"])["rules"] if r["action"] == "Backup Proxy")
    assert "disabled_with" not in read(env["profiles"])["profiles"]["Backup Proxy"]   # the offer is used up


def test_page_offers_restore_on_the_toggle(app_module, monkeypatch, tmp_path):
    profiles = copy.deepcopy(SAMPLE_PROFILES)
    profiles["Backup Proxy"].update(enabled=False, disabled_with={"rules": ["r9"], "devices": []})
    rules = [{"id": "r9", "patterns": ["*.x.it"], "mode": "wildcard", "action": "Backup Proxy", "description": "X", "enabled": False}]
    html = render_page(app_module, monkeypatch, profiles=profiles, rules=rules)
    check_page(html, tmp_path)
    assert """data-restore='["rule: X"]'""" in html and 'name="restore" value="0"' in html


# --- backup / restore ------------------------------------------------------------------

def test_export_has_everything(app_module, env):
    mailer.save_alerts_config(dict(mailer.DEFAULTS, smtp_host="smtp.example.com", password="pw"))
    app_module.set_device_policy(PHONE, "direct")
    data = app_module.export_config()
    assert data["format"] == 2 and data["alerts"]["smtp_host"] == "smtp.example.com"
    assert data["devices"] == {TV: {"nickname": "Living-room TV"}}               # PHONE has nothing to keep
    assert data["patterns"]["device_policies"] == {PHONE: "direct"}
    assert {"leak_guards", "resolve_via_proxy"} <= set(data["patterns"])


def test_import_round_trip_and_blocklist(app_module, env):
    exported = app_module.export_config()
    exported["devices"] = {TV: {"nickname": "TV (lounge)", "blocked": True}, "11:22:33:44:55:66": {"nickname": "New"}}
    exported["alerts"] = dict(mailer.DEFAULTS, smtp_host="smtp.new.example", recipients="x@y.z")
    assert app_module.import_config(json.loads(json.dumps(exported))) is None
    devices = read(env["devices"])
    assert devices[TV]["nickname"] == "TV (lounge)" and devices[TV]["blocked"] is True
    assert devices["11:22:33:44:55:66"]["nickname"] == "New"
    assert env["denylist"] == [[TV]]                                             # block list re-applied once
    assert mailer.load_alerts_config()["smtp_host"] == "smtp.new.example"


def test_old_format_files_still_import(app_module, env):
    mailer.save_alerts_config(dict(mailer.DEFAULTS, smtp_host="keep.me"))
    old = {k: v for k, v in app_module.export_config().items() if k in ("bypass_cidr", "proxies", "patterns")}
    assert app_module.import_config(old) is None
    assert mailer.load_alerts_config()["smtp_host"] == "keep.me" and env["denylist"] == []


@pytest.mark.parametrize("section,value", [
    ("alerts", {"evil": 1}), ("alerts", "x"),
    ("devices", {"not-a-mac": {}}), ("devices", {TV: {"blocked": "yes"}}), ("devices", {TV: {"nickname": 5}}),
])
def test_bad_optional_sections_are_rejected_before_any_write(app_module, env, section, value):
    data = app_module.export_config()
    data[section] = value
    before = env["rules"].read_text(), env["devices"].read_text()
    assert app_module.import_config(data).startswith("Invalid file")
    assert (env["rules"].read_text(), env["devices"].read_text()) == before
