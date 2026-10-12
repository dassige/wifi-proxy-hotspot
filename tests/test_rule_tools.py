"""Batch D: multi-pattern rules ("service bundles"), presets, the rule tester,
and per-rule activity counters."""
import copy
import json
import time

import pytest

import dns.message
import dns.rrset

import dns_router
from conftest import SAMPLE_PROFILES, load_script
from pattern_match import match_rule, matching_pattern, prepare_rule, rule_patterns
from test_app_render import check_page, render_page

RAI = {"id": "rai1", "patterns": ["*raiplay.it", "*.netrw.it", "*.msvdn.net", "mediapolis.rai.it"],
       "pattern": "*raiplay.it", "mode": "wildcard", "action": "Remote Proxy", "description": "RaiPlay", "enabled": True}


# --- matcher -------------------------------------------------------------------

def test_any_pattern_matches_and_reports_which():
    r = prepare_rule(RAI)
    assert matching_pattern("raicinque1-push.cdn.netrw.it", r) == "*.netrw.it"
    assert matching_pattern("mediapolis.rai.it", r) == "mediapolis.rai.it"
    assert matching_pattern("www.rai.it", r) is None


def test_single_pattern_rules_still_work():
    old = {"id": "x", "pattern": "*.netrw.it", "mode": "wildcard"}
    assert rule_patterns(old) == ["*.netrw.it"]
    assert match_rule("a.netrw.it", [prepare_rule(old)])


def test_regexp_list_skips_invalid_and_exact_list():
    r = prepare_rule({"id": "x", "patterns": ["([", r"(.*\.)?rai\.it"], "mode": "regexp"})
    assert matching_pattern("mediapolis.rai.it", r) == r"(.*\.)?rai\.it"
    assert prepare_rule({"id": "x", "patterns": ["(["], "mode": "regexp"}) is None
    exact = prepare_rule({"id": "x", "patterns": ["Raiplay.it", "rai.it"], "mode": "match"})
    assert matching_pattern("raiplay.it", exact) == "raiplay.it" and matching_pattern("www.rai.it", exact) is None


def test_dns_router_tags_any_patterns_hit_into_the_rules_one_ipset(tmp_path, monkeypatch, fake_run):
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"rules": [RAI], "resolve_via_proxy": False}))
    monkeypatch.setattr(dns_router, "RULES_FILE", str(rules))
    monkeypatch.setattr(dns_router, "PROXY_STORE", str(tmp_path / "none.json"))
    dns_router._rules_cache["mtime"] = None
    dns_router._tagged.clear()

    def fake_udp(request, server, timeout=None):
        r = dns.message.make_response(request)
        r.answer.append(dns.rrset.from_text(request.question[0].name, 20, "IN", "A", "195.35.118.38"))
        return r

    monkeypatch.setattr(dns_router.dns.query, "udp", fake_udp)
    dns_router.handle_query(dns.message.make_query("x.cdn.netrw.it", "A").to_wire(), ["192.168.1.1"])
    assert fake_run.calls[-1]["input"] == "add wpx_rai1 195.35.118.38\n"


# --- saving bundles ------------------------------------------------------------

def test_parse_patterns(app_module):
    assert app_module.parse_patterns(" *.a.it \n\n*.B.it, *.a.it\r\nc.it ") == ["*.a.it", "*.B.it", "c.it"]


def test_patterns_problem(app_module):
    assert "At least one" in app_module.patterns_problem([], "wildcard")
    assert "At most" in app_module.patterns_problem(["a.it"] * 51, "wildcard")
    assert "hostnames only" in app_module.patterns_problem(["ok.it", "bad.it/x"], "wildcard")
    assert app_module.patterns_problem(["*.a.it", "b.it"], "wildcard") is None


@pytest.fixture
def rules_cfg(app_module, monkeypatch):
    cfg = {"bypass_cidr": "192.168.1.0/24", "default_action": "direct", "rules": [copy.deepcopy(RAI)]}
    monkeypatch.setattr(app_module, "load_pattern_config", lambda: cfg)
    monkeypatch.setattr(app_module, "save_pattern_config", lambda c: None)
    return cfg


def test_adding_a_pattern_keeps_the_ipset(app_module, rules_cfg):
    app_module.upsert_pattern_rule("rai1", RAI["patterns"] + ["*.rai.it"], "wildcard", "Remote Proxy", "RaiPlay")
    r = rules_cfg["rules"][0]
    assert r["id"] == "rai1" and r["patterns"][-1] == "*.rai.it" and r["pattern"] == "*raiplay.it"


@pytest.mark.parametrize("patterns,mode", [(["*raiplay.it", "*.netrw.it"], "wildcard"), (RAI["patterns"], "regexp")])
def test_removing_a_pattern_or_changing_mode_gets_a_fresh_ipset(app_module, rules_cfg, patterns, mode):
    app_module.upsert_pattern_rule("rai1", patterns, mode, "Remote Proxy", "")
    assert rules_cfg["rules"][0]["id"] != "rai1"


def test_save_route_takes_the_textarea(app_module, rules_cfg, monkeypatch):
    seen = {}
    monkeypatch.setattr(app_module, "render", lambda message="", **k: seen.update(message=message) or "PAGE")
    monkeypatch.setattr(app_module, "load_store", lambda: {"profiles": SAMPLE_PROFILES})
    with app_module.app.test_request_context("/pattern-rule/save", method="POST", data={
            "patterns": "*tv8.it\n*skycdn-it.akamaized.net\n", "mode": "wildcard", "action": "Remote Proxy",
            "description": "TV8"}):
        app_module.save_pattern_rule.__wrapped__()
    new = rules_cfg["rules"][-1]
    assert new["patterns"] == ["*tv8.it", "*skycdn-it.akamaized.net"] and seen["message"].startswith("Routing rule saved.")


def test_presets_prefill_only_known_ones(app_module, monkeypatch):
    profiles = copy.deepcopy(SAMPLE_PROFILES)
    profiles["Remote Proxy"]["enabled"] = False                  # first *enabled* profile is chosen
    monkeypatch.setattr(app_module, "load_store", lambda: {"profiles": profiles})
    monkeypatch.setattr(app_module, "get_action_choices", lambda: [("direct", "Direct")])
    p = app_module.get_rule_prefill({"preset": "raiplay"})
    assert p["patterns"] == app_module.RULE_PRESETS["raiplay"]["patterns"] and p["action"] == "Backup Proxy"
    assert "mediapolis.rai.it" in p["patterns"]
    assert app_module.get_rule_prefill({"preset": "evil"}) is None
    for preset in app_module.RULE_PRESETS.values():                # presets must pass our own validation
        assert app_module.patterns_problem(preset["patterns"], "wildcard") is None


# --- rule tester ---------------------------------------------------------------

@pytest.fixture
def tester(app_module, monkeypatch):
    cfg = {"bypass_cidr": "192.168.1.0/24", "default_action": "direct", "resolve_via_proxy": True, "rules": [
        copy.deepcopy(RAI),
        {"id": "r2", "patterns": ["*.netrw.it"], "mode": "wildcard", "action": "direct", "description": "", "enabled": True},
        {"id": "r3", "patterns": ["*.rai.it"], "mode": "wildcard", "action": "Backup Proxy", "description": "old", "enabled": False},
        {"id": "r4", "patterns": ["gone.it"], "mode": "match", "action": "deleted", "description": "", "enabled": True},
    ]}
    monkeypatch.setattr(app_module, "load_pattern_config", lambda: cfg)
    monkeypatch.setattr(app_module, "load_store", lambda: {"profiles": SAMPLE_PROFILES})
    return cfg


def test_tester_winner_shadowed_disabled(app_module, tester):
    d = app_module.explain_hostname("https://RaiCinque1-Push.cdn.netrw.it:443/live/x.m3u8?a=b")
    assert d["ok"] and d["host"] == "raicinque1-push.cdn.netrw.it"
    assert d["rule"]["index"] == 1 and d["rule"]["pattern"] == "*.netrw.it" and d["proxied"]
    assert d["route"] == "Remote Proxy" and d["decided_by"] == "rule #1"
    assert [r["index"] for r in d["shadowed"]] == [2]
    assert "through the proxy" in d["dns"] and any("QUIC" in n for n in d["notes"])
    d = app_module.explain_hostname("mediapolis.rai.it")
    assert [r["index"] for r in d["disabled"]] == [3] and d["rule"]["index"] == 1


def test_tester_default_and_missing_profile(app_module, tester):
    d = app_module.explain_hostname("www.bbc.co.uk")
    assert d["rule"] is None and d["decided_by"] == "the Default Behaviour" and not d["proxied"]
    assert "ordinary DNS" in d["dns"]
    d = app_module.explain_hostname("gone.it")
    assert not d["proxied"] and any("no longer exists" in n for n in d["notes"])
    tester["resolve_via_proxy"] = False
    assert "ordinary DNS" in app_module.explain_hostname("a.netrw.it")["dns"]


@pytest.mark.parametrize("bad", ["", "not a host", "<script>", "wpad"])
def test_tester_rejects_garbage(app_module, tester, bad):
    assert not app_module.explain_hostname(bad)["ok"]


# --- activity counters -----------------------------------------------------------

def test_rule_activity_attribution(app_module):
    now = time.time()
    rules = [copy.deepcopy(RAI),
             {"id": "r2", "patterns": ["*.netrw.it"], "mode": "wildcard", "action": "direct", "enabled": True},
             {"id": "off", "patterns": ["*.tv8.it"], "mode": "wildcard", "action": "direct", "enabled": False}]
    snapshot = {"clients": {
        "192.168.4.71": [{"name": "a.netrw.it", "count": 5, "last": now - 60},
                         {"name": "www.tv8.it", "count": 3, "last": now}],
        "192.168.4.80": [{"name": "a.netrw.it", "count": 2, "last": now - 10},
                         {"name": "<bad>", "count": 9, "last": now}]}}
    act = app_module.get_rule_activity(rules, snapshot, {"rule_connections": {"rai1": 37, "unknown": 1}})
    assert act["rai1"]["lookups"] == 7 and act["rai1"]["last_name"] == "a.netrw.it" and act["rai1"]["connections"] == 37
    assert act["r2"]["lookups"] == 0                                      # shadowed by rule 1
    assert act["off"]["lookups"] == 0 and act["off"]["connections"] is None
    assert app_module.get_rule_activity(rules, None, None)["rai1"] == \
        {"lookups": 0, "last": 0, "last_name": "", "connections": None}


def test_ago(app_module):
    assert app_module.ago(100, now=130) == "just now" and app_module.ago(0, now=7200) == "2h ago"


def test_health_reads_redsocks_counters(monkeypatch):
    health = load_script("rasp-proxy-health.py", "rasp_proxy_health_counters")
    sample = """Chain REDSOCKS (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       0        0 RETURN     all  --  *      *       0.0.0.0/0            192.168.1.0/24
      37     2220 REDIRECT   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set wpx_c521dadc dst redir ports 20000
       5      300 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set wpx_f773a189 dst
    1204    72240 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0
"""
    import subprocess
    monkeypatch.setattr(health, "run", lambda cmd, timeout=15: subprocess.CompletedProcess(cmd, 0, sample, ""))
    assert health.read_rule_connections() == {"c521dadc": 37, "f773a189": 5}


# --- page ------------------------------------------------------------------------

def test_page_shows_bundles_tester_activity_and_presets(app_module, monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "read_health_status", lambda: {"rule_connections": {"rai1": 12}})
    monkeypatch.setattr(app_module, "read_lookups_snapshot", lambda: {"clients": {
        "192.168.4.71": [{"name": "a.netrw.it", "count": 4, "last": time.time() - 120}]}})
    html = render_page(app_module, monkeypatch, rules=[copy.deepcopy(RAI)], edit_pattern_id="rai1")
    check_page(html, tmp_path)
    assert html.count('<span class="pattern-chip">') == 4
    assert 'id="rule-test-input"' in html
    assert "4 recent lookups" in html and "12 connections since the last rule change" in html
    assert "last: a.netrw.it, 2m ago" in html
    assert ">*raiplay.it\n*.netrw.it\n*.msvdn.net\nmediapolis.rai.it</textarea>" in html   # editing: all patterns
    html = render_page(app_module, monkeypatch, prefill=app_module.RULE_PRESETS["tv8"] | {"action": "direct", "mode": "wildcard"})
    assert "RaiPlay (on demand and live channels)</option>" in html and ">*tv8.it\n*skycdn-it.akamaized.net</textarea>" in html


# --- DNS Lookups: "Add to rule" ------------------------------------------------------

@pytest.mark.parametrize("mode,expected", [
    ("wildcard", "*.netrw.it"),                        # same suggestion as "New rule"
    ("match", "raicinque1-push.cdn.netrw.it"),         # exact mode can't take a wildcard
    ("regexp", r"raicinque1-push\.cdn\.netrw\.it"),
])
def test_pattern_for_mode(app_module, mode, expected):
    pattern = app_module.pattern_for_mode("raicinque1-push.cdn.netrw.it", mode)
    assert pattern == expected and app_module.pattern_problem(pattern, mode) is None
    assert matching_pattern("raicinque1-push.cdn.netrw.it", prepare_rule({"patterns": [pattern], "mode": mode}))


def test_rule_addition(app_module):
    tv8 = {"id": "tv8", "patterns": ["*tv8.it"], "mode": "wildcard", "action": "Remote Proxy", "description": "TV8", "enabled": True}
    off = {"id": "off1", "patterns": ["x.it"], "mode": "match", "action": "direct", "description": "", "enabled": False}
    rules = [copy.deepcopy(RAI), tv8, off]
    g = app_module.get_rule_addition
    a = g({"edit_pattern": "tv8", "add_host": "hlslive-web-gcdn-skycdn-it.akamaized.net"}, rules)
    assert a == {"host": "hlslive-web-gcdn-skycdn-it.akamaized.net", "pattern": "hlslive-web-gcdn-skycdn-it.akamaized.net",
                 "already": False, "shadowed_by": "", "rule_off": False}
    a = g({"edit_pattern": "tv8", "add_host": "A.Netrw.it"}, rules)          # RaiPlay (#1) already wins for it
    assert a["pattern"] == "*.netrw.it" and a["shadowed_by"] == "RaiPlay"
    assert g({"edit_pattern": "rai1", "add_host": "b.netrw.it"}, rules)["already"]
    a = g({"edit_pattern": "off1", "add_host": "y.it"}, rules)
    assert a["pattern"] == "y.it" and a["rule_off"]
    assert g({"edit_pattern": "nope", "add_host": "y.it"}, rules) is None
    assert g({"edit_pattern": "tv8", "add_host": '"><script>'}, rules) is None
    assert g({"edit_pattern": "tv8"}, rules) is None


def test_edit_form_shows_the_added_pattern(app_module, monkeypatch, tmp_path):
    rules = [copy.deepcopy(RAI)]
    addition = app_module.get_rule_addition({"edit_pattern": "rai1", "add_host": "rai-vod.akamaized.net"}, rules)
    html = render_page(app_module, monkeypatch, rules=rules, edit_pattern_id="rai1", addition=addition)
    check_page(html, tmp_path)
    assert ">*raiplay.it\n*.netrw.it\n*.msvdn.net\nmediapolis.rai.it\nrai-vod.akamaized.net</textarea>" in html
    assert "Added <code>rai-vod.akamaized.net</code> for <b>rai-vod.akamaized.net</b>" in html
    addition = app_module.get_rule_addition({"edit_pattern": "rai1", "add_host": "www.raiplay.it"}, rules)
    html = render_page(app_module, monkeypatch, rules=rules, edit_pattern_id="rai1", addition=addition)
    assert "already covers <b>www.raiplay.it</b>" in html and ">*raiplay.it\n*.netrw.it\n*.msvdn.net\nmediapolis.rai.it</textarea>" in html


def test_lookups_view_lists_rules_for_the_picker(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "read_lookups_snapshot", lambda: {"generated": time.time(), "capture": "ok", "clients": {}})
    monkeypatch.setattr(app_module, "load_pattern_config", lambda: {"bypass_cidr": "192.168.1.0/24", "default_action": "direct", "rules": [
        copy.deepcopy(RAI), {"id": "z", "pattern": "z.it", "mode": "match", "action": "direct", "description": "", "enabled": False}]})
    monkeypatch.setattr(app_module, "load_store", lambda: {"profiles": SAMPLE_PROFILES})
    monkeypatch.setattr(app_module, "get_lease_map", lambda: {})
    monkeypatch.setattr(app_module, "load_devices_store", lambda: {})
    assert app_module.get_lookups_view()["rules"] == [
        {"id": "rai1", "label": "#1 RaiPlay → Remote Proxy"}, {"id": "z", "label": "#2 z.it → Direct (off)"}]
