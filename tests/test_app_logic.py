"""app.py logic with its storage and OS calls faked."""
import copy
import json
import os
import time

import pytest

import mailer
from conftest import SAMPLE_PROFILES


# --- pattern rules ---------------------------------------------------------------

@pytest.mark.parametrize("pattern,mode,needle", [
    ("*.discoveryplus.com/*", "wildcard", 'Use just the hostname part, e.g. "*.discoveryplus.com"'),
    ("https://www.raiplay.it/dirette", "wildcard", '"www.raiplay.it"'),
    ("raiplay.it:443", "match", "port number"),
    ("rai play.it", "wildcard", "only contain"),
    ("*.rai.it", "match", "Choose Wildcard"),
    ("*..rai.it", "wildcard", "empty part"),
    (".rai.it", "match", "empty part"),
    ("", "wildcard", "required"),
    ("a" * 254, "wildcard", "required"),
    ("([", "regexp", "Invalid regular expression"),
])
def test_pattern_problem_rejects(app_module, pattern, mode, needle):
    assert needle in app_module.pattern_problem(pattern, mode)


@pytest.mark.parametrize("pattern,mode", [
    ("*.netrw.it", "wildcard"), ("*raiplay.it", "wildcard"), ("*skycdn-it.akamaized.net", "wildcard"),
    ("rai?.it", "wildcard"), ("*.bbc.co.uk", "wildcard"), ("RaiPlay.it", "wildcard"), ("raiplay.it", "match"),
    (r"^(.*\.)?raiplay\.it$", "regexp"),
])
def test_pattern_problem_accepts(app_module, pattern, mode):
    assert app_module.pattern_problem(pattern, mode) is None


def test_rule_notes(app_module, monkeypatch):
    profiles = copy.deepcopy(SAMPLE_PROFILES)
    profiles["Backup Proxy"]["enabled"] = False
    monkeypatch.setattr(app_module, "load_store", lambda: {"profiles": profiles})
    assert "shared CDN" in app_module.rule_notes("*.akamaized.net", "wildcard", "Remote Proxy")
    assert app_module.rule_notes("*skycdn-it.akamaized.net", "wildcard", "Remote Proxy") == ""
    assert "is disabled" in app_module.rule_notes("*.x.it", "wildcard", "Backup Proxy")


def test_editing_pattern_or_mode_gives_rule_a_fresh_id(app_module, monkeypatch):
    cfg = {"bypass_cidr": "192.168.1.0/24", "default_action": "direct", "rules": [
        {"id": "aaaa1111", "pattern": "*.x.it", "mode": "wildcard", "action": "direct", "description": "", "enabled": True}]}
    monkeypatch.setattr(app_module, "load_pattern_config", lambda: cfg)
    monkeypatch.setattr(app_module, "save_pattern_config", lambda c: None)
    app_module.upsert_pattern_rule("aaaa1111", "*.x.it", "wildcard", "Remote", "new description")
    assert cfg["rules"][0]["id"] == "aaaa1111"          # action/description only: same ipset
    app_module.upsert_pattern_rule("aaaa1111", "*.y.it", "wildcard", "Remote", "")
    new_id = cfg["rules"][0]["id"]
    assert new_id != "aaaa1111" and len(new_id) == 8
    app_module.upsert_pattern_rule(new_id, "*.y.it", "match", "Remote", "")
    assert cfg["rules"][0]["id"] != new_id


# --- DNS Lookups page ------------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("raicinque1-push.cdn.netrw.it", ("*.netrw.it", "wildcard")),
    ("hlslive-web-gcdn-skycdn-it.akamaized.net", ("hlslive-web-gcdn-skycdn-it.akamaized.net", "match")),
    ("www.bbc.co.uk", ("*.bbc.co.uk", "wildcard")),
    ("raiplay.it", ("raiplay.it", "match")),
    ("d1.cloudfront.net", ("d1.cloudfront.net", "match")),
])
def test_suggest_rule_pattern(app_module, name, expected):
    assert app_module.suggest_rule_pattern(name) == expected


def lookups_view(app, monkeypatch, snapshot, rules):
    monkeypatch.setattr(app, "read_lookups_snapshot", lambda: snapshot)
    monkeypatch.setattr(app, "load_pattern_config", lambda: {"bypass_cidr": "192.168.1.0/24",
                                                              "default_action": "direct", "rules": rules})
    monkeypatch.setattr(app, "load_store", lambda: {"profiles": SAMPLE_PROFILES})
    monkeypatch.setattr(app, "get_lease_map", lambda: {"192.168.4.71": ("aa:bb:cc:dd:ee:01", "laptop")})
    monkeypatch.setattr(app, "load_devices_store", lambda: {})
    return app.get_lookups_view()


def test_lookups_view_routes_and_suggestions(app_module, monkeypatch):
    now = time.time()
    snapshot = {"generated": now - 3, "capture": "ok", "clients": {
        "192.168.4.71": [
            {"name": "raicinque1-push.cdn.netrw.it", "last": now - 5, "count": 7, "bypass": []},
            {"name": "www.tv8.it", "last": now - 20, "count": 2, "bypass": ["8.8.8.8", "<bad>"]},
            {"name": "<img src=x>", "last": now, "count": 1, "bypass": []},
        ],
        "192.168.4.80": [{"name": "www.bbc.co.uk", "last": now - 1, "count": 1, "bypass": []}],
    }}
    rules = [
        {"id": "f773a189", "pattern": "*.netrw.it", "mode": "wildcard", "action": "Remote Proxy", "enabled": True},
        {"id": "e77e5fff", "pattern": "*tv8.it", "mode": "wildcard", "action": "Remote Proxy", "enabled": False},
        {"id": "badregex", "pattern": "([", "mode": "regexp", "action": "Remote Proxy", "enabled": True},
    ]
    v = lookups_view(app_module, monkeypatch, snapshot, rules)
    assert v["status"] == "ok"
    assert [c["label"] for c in v["clients"]] == ["192.168.4.80", "laptop (192.168.4.71)"]
    by = {e["name"]: e for e in v["entries"]}
    assert "<img src=x>" not in by                                   # never reaches the page
    netrw = by["raicinque1-push.cdn.netrw.it"]
    assert netrw["proxied"] and netrw["via"] == "rule *.netrw.it" and netrw["rule_id"] == "f773a189"
    assert netrw["rule_label"] == "*.netrw.it"                      # no description: its patterns
    assert by["www.bbc.co.uk"]["rule_label"] == ""
    assert netrw["suggest"]["action"] == "direct"                    # offers the opposite route
    tv8 = by["www.tv8.it"]
    assert not tv8["proxied"] and tv8["via"] == "default"           # its rule is disabled
    assert tv8["bypass"] == ["8.8.8.8"]
    assert tv8["suggest"] == {"pattern": "*.tv8.it", "mode": "wildcard", "action": "Remote Proxy"}
    assert v["entries"][0]["name"] == "www.bbc.co.uk"               # newest first


def test_lookups_view_stale_and_unavailable(app_module, monkeypatch):
    stale = {"generated": time.time() - 999, "capture": "ok", "clients": {}}
    assert lookups_view(app_module, monkeypatch, stale, [])["status"] == "stale"
    broken = {"generated": time.time(), "capture": "no permission", "clients": {}}
    assert lookups_view(app_module, monkeypatch, broken, [])["status"] == "error"
    assert lookups_view(app_module, monkeypatch, None, [])["status"] == "unavailable"


def test_rule_prefill_is_validated(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "get_action_choices", lambda: [("direct", "Direct"), ("Remote", "Remote")])
    g = app_module.get_rule_prefill
    assert g({"new_pattern": "*.Netrw.it", "new_mode": "wildcard", "new_action": "Remote", "new_desc": "x"}) == \
        {"patterns": ["*.netrw.it"], "mode": "wildcard", "action": "Remote", "description": "x"}
    assert g({"new_pattern": '"><script>'}) is None
    assert g({"new_pattern": "a.it", "new_mode": "evil", "new_action": "nope"}) == \
        {"patterns": ["a.it"], "mode": "wildcard", "action": "direct", "description": ""}
    assert g({}) is None


# --- proxy profiles: Enabled toggle ------------------------------------------------

@pytest.fixture
def profile_env(app_module, monkeypatch, tmp_path):
    store_path = tmp_path / "proxies.json"
    profiles = copy.deepcopy(SAMPLE_PROFILES)
    profiles["Backup Proxy"]["monitored"] = False                         # the toggle's original key name
    store_path.write_text(json.dumps({"next_port": 20002, "profiles": profiles}))
    cfg = {"bypass_cidr": "192.168.1.0/24", "default_action": "Remote Proxy", "rules": [
        {"id": "r1", "pattern": "*.a.it", "mode": "wildcard", "action": "Backup Proxy", "description": "A live", "enabled": True},
        {"id": "r2", "pattern": "*.b.it", "mode": "wildcard", "action": "Backup Proxy", "description": "", "enabled": True},
        {"id": "r3", "pattern": "*.c.it", "mode": "wildcard", "action": "Backup Proxy", "description": "off", "enabled": False},
        {"id": "r4", "pattern": "*.d.it", "mode": "wildcard", "action": "Remote Proxy", "description": "", "enabled": True}]}
    env = {"redsocks": [], "rebuilds": [], "cfg": cfg, "path": store_path}
    monkeypatch.setattr(app_module, "PROXY_STORE", str(store_path))
    monkeypatch.setattr(app_module, "write_redsocks_conf_all", lambda p: env["redsocks"].append(1))
    monkeypatch.setattr(app_module, "load_pattern_config", lambda: cfg)
    monkeypatch.setattr(app_module, "save_pattern_config", lambda c: env["rebuilds"].append(json.loads(json.dumps(c))))
    return env


def saved(env):
    return json.loads(env["path"].read_text())["profiles"]


def test_legacy_monitored_key_migrates_without_restarting_redsocks(app_module, profile_env):
    store = app_module.load_store()
    assert store["profiles"]["Backup Proxy"]["enabled"] is False and "monitored" not in store["profiles"]["Backup Proxy"]
    assert profile_env["redsocks"] == []
    assert dict(app_module.get_action_choices())["Backup Proxy"] == "Backup Proxy — Testing (disabled)"


def test_disabling_cascades_to_active_rules_only(app_module, profile_env):
    app_module.set_profile_enabled("Backup Proxy", True)
    msg, err = app_module.set_profile_enabled("Backup Proxy", False)
    assert err is None and "switched off 2 pattern rules that used it: A live, *.b.it" in msg
    assert len(profile_env["rebuilds"]) == 1
    assert {r["id"]: r["enabled"] for r in profile_env["rebuilds"][0]["rules"]} == \
        {"r1": False, "r2": False, "r3": False, "r4": True}
    assert saved(profile_env)["Backup Proxy"]["enabled"] is False
    assert profile_env["redsocks"] == []


def test_reenabling_leaves_rules_off(app_module, profile_env):
    app_module.set_profile_enabled("Backup Proxy", False)
    msg, err = app_module.set_profile_enabled("Backup Proxy", True)
    assert err is None and "stays off" in msg
    assert profile_env["cfg"]["rules"][0]["enabled"] is False and len(profile_env["rebuilds"]) == 1


def test_default_behaviour_profile_cannot_be_disabled(app_module, profile_env):
    msg, err = app_module.set_profile_enabled("Remote Proxy", False)
    assert msg is None and "it's the Default Behaviour" in err
    assert saved(profile_env)["Remote Proxy"].get("enabled", True) is True
    assert app_module.set_profile_enabled("nope", False) == (None, "Unknown proxy profile")


def test_edit_keeps_enabled_and_new_profiles_start_enabled(app_module, profile_env):
    app_module.upsert_proxy_profile("Backup Proxy", "edited", "http-connect", "5.6.7.9", "8888", "", "")
    assert saved(profile_env)["Backup Proxy"]["enabled"] is False
    app_module.upsert_proxy_profile("New", "", "socks5", "9.9.9.9", "1080", "", "")
    assert saved(profile_env)["New"]["enabled"] is True


# --- forms: rejected input renders the panel with the error, keeping input -------

@pytest.fixture
def captured_render(app_module, monkeypatch):
    seen = {}

    def fake_render(message="", edit_name="", edit_pattern_id="", prefill=None, page="", message_kind="info"):
        seen.update(message=message, page=page, kind=message_kind, prefill=prefill, edit=edit_pattern_id)
        return "PAGE"

    profiles = copy.deepcopy(SAMPLE_PROFILES)
    profiles["Backup Proxy"]["enabled"] = False
    monkeypatch.setattr(app_module, "render", fake_render)
    monkeypatch.setattr(app_module, "load_store", lambda: {"profiles": profiles})
    monkeypatch.setattr(app_module, "load_pattern_config", lambda: {"bypass_cidr": "192.168.1.0/24",
                                                                     "default_action": "direct", "rules": []})
    monkeypatch.setattr(app_module, "upsert_pattern_rule", lambda *a: True)
    monkeypatch.setattr(app_module, "set_default_action", lambda a: None)
    return seen


def post(app, view, path, data):
    with app.app.test_request_context(path, method="POST", data=data):
        return getattr(app, view).__wrapped__()


def test_bad_new_rule_keeps_input(app_module, captured_render):
    body, status = post(app_module, "save_pattern_rule", "/pattern-rule/save",
                        {"pattern": "*.discoveryplus.com/*", "mode": "wildcard", "action": "Remote Proxy", "description": "D+"})
    assert status == 400 and captured_render["kind"] == "error" and captured_render["page"] == "pattern-rules"
    assert captured_render["prefill"]["patterns"] == ["*.discoveryplus.com/*"]


def test_bad_rule_edit_reopens_that_rule(app_module, captured_render):
    body, status = post(app_module, "save_pattern_rule", "/pattern-rule/save",
                        {"id": "r1", "pattern": "bad/one", "mode": "wildcard", "action": "Remote Proxy"})
    assert status == 400 and captured_render["prefill"] is None and captured_render["edit"] == "r1"


def test_shared_cdn_rule_saves_with_heads_up(app_module, captured_render):
    post(app_module, "save_pattern_rule", "/pattern-rule/save",
         {"pattern": "*.akamaized.net", "mode": "wildcard", "action": "Remote Proxy"})
    assert captured_render["kind"] == "info" and "shared CDN" in captured_render["message"]


def test_disabled_profile_cannot_be_default(app_module, captured_render):
    body, status = post(app_module, "save_default_action", "/default-action/save", {"default_action": "Backup Proxy"})
    assert status == 400 and "is disabled" in captured_render["message"]


@pytest.mark.parametrize("view,path,data,page", [
    ("save_wifi", "/wifi", {"ssid": ""}, "wifi"),
    ("save_wifi", "/wifi", {"ssid": "x", "passphrase": "short"}, "wifi"),
    ("save_network", "/network", {"bypass_cidr": "nope"}, "network"),
    ("save_proxy_profile", "/proxy-profile/save", {"name": "bad/name", "ip": "1.1.1.1", "port": "1"}, "proxy-profiles"),
    ("save_proxy_profile", "/proxy-profile/save", {"name": "ok", "ip": "1.1.1.1", "port": "99999"}, "proxy-profiles"),
])
def test_form_errors_render_on_their_page(app_module, captured_render, view, path, data, page):
    body, status = post(app_module, view, path, data)
    assert status == 400 and captured_render["page"] == page and captured_render["kind"] == "error"


# --- alerts settings, health view, version ------------------------------------------

def test_alerts_form(app_module):
    current = dict(mailer.DEFAULTS, password="old-pw")
    cfg, err = app_module.parse_alerts_form({
        "enabled": "1", "smtp_host": "smtp.gmail.com", "smtp_port": "587", "security": "starttls",
        "username": "me@gmail.com", "password": "", "recipients": "a@b.com, c@d.org", "notify_boot": "1"}, current)
    assert err is None and cfg["password"] == "old-pw" and cfg["smtp_port"] == 587 and cfg["enabled"]
    assert app_module.parse_alerts_form({"smtp_host": "bad host!"}, current)[1] == "Invalid SMTP server name"
    assert app_module.parse_alerts_form({"smtp_host": "h.com", "smtp_port": "99999"}, current)[1] == "Invalid SMTP port"
    assert "recipient" in app_module.parse_alerts_form({"smtp_host": "h.com", "recipients": "a@b.com, nope"}, current)[1]
    assert "To turn alerts on" in app_module.parse_alerts_form({"enabled": "1"}, current)[1]
    assert cfg["recover_after_min"] == 10 and cfg["min_interval_min"] == 30   # not in the form: kept
    cfg, err = app_module.parse_alerts_form({"recover_after_min": " 0 ", "min_interval_min": "60"}, current)
    assert err is None and (cfg["recover_after_min"], cfg["min_interval_min"]) == (0, 60)
    for bad in ("-1", "abc", "1441", ""):
        assert "At most one email every" in app_module.parse_alerts_form({"min_interval_min": bad}, current)[1]
    assert "Recovered after" in app_module.parse_alerts_form({"recover_after_min": "241"}, current)[1]


def test_health_view_hides_internal_fields(app_module, monkeypatch, tmp_path):
    status = tmp_path / "status.json"
    status.write_text(json.dumps({"generated": time.time(), "overall": "ok", "alerts": {},
                                  "checks": [{"id": "x", "status": "ok", "alert": True}]}))
    monkeypatch.setattr(app_module, "HEALTH_STATUS_FILE", str(status))
    v = app_module.get_health_view()
    assert v["state"] == "ok" and all("alert" not in c for c in v["checks"])
    monkeypatch.setattr(app_module, "HEALTH_STATUS_FILE", str(tmp_path / "missing.json"))
    assert app_module.get_health_view()["state"] == "unavailable"


def test_version_json_beats_unit_environment(app_module, monkeypatch, tmp_path):
    (tmp_path / "version.json").write_text(json.dumps({"version": "1.14.0", "date": "2026/10/01 11:43"}))
    monkeypatch.setattr(app_module, "__file__", str(tmp_path / "app.py"))
    assert app_module._read_version() == ("1.14.0", "2026/10/01 11:43")
    monkeypatch.setattr(app_module, "__file__", str(tmp_path / "elsewhere" / "app.py"))
    monkeypatch.setenv("RASP_PROXY_VERSION", "1.11.2")
    monkeypatch.setenv("RASP_PROXY_VERSION_DATE", "x")
    assert app_module._read_version() == ("1.11.2", "x")
