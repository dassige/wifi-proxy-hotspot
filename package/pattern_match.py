"""
Hostname-vs-pattern-rule matching, shared by dns_router.py (which tags the
resolved IPs of matching lookups into ipsets) and app.py (whose DNS Lookups
page and rule tester show which rule each name falls under), so the two can
never disagree about what a rule matches.

A rule holds one or more patterns ("patterns" list; older rules have a
single "pattern" string), all in the rule's one mode, and matches a hostname
if any of them does. So one rule, one toggle and one ipset can cover a whole
service, e.g. RaiPlay's site plus its live-stream CDNs.

Deliberately stdlib-only: app.py imports this, and importing dnspython costs
~1.6s of CPU on a Pi 3B+.
"""
import fnmatch
import re


def rule_patterns(rule):
    patterns = rule.get("patterns")
    if isinstance(patterns, list) and patterns:
        return [str(p) for p in patterns]
    return [rule["pattern"]] if rule.get("pattern") else []


def prepare_rule(rule):
    # Returns a copy ready for match_rule(), or None if the rule can never
    # match (no patterns, or only invalid regular expressions).
    prepared = dict(rule)
    patterns = rule_patterns(rule)
    if prepared.get("mode") == "regexp":
        compiled = []
        for p in patterns:
            try:
                compiled.append((p, re.compile(p, re.IGNORECASE)))
            except re.error:
                continue
        prepared["_compiled"] = compiled
        prepared["_patterns"] = [p for p, _ in compiled]
    else:
        prepared["_patterns"] = [p.lower() for p in patterns]
    return prepared if prepared["_patterns"] else None


def matching_pattern(qname, rule):
    # The first of this prepared rule's patterns that matches, or None.
    # qname must already be lowercased with no trailing dot.
    mode = rule.get("mode")
    try:
        if mode == "regexp":
            for pattern, rx in rule.get("_compiled", []):
                if rx.fullmatch(qname):
                    return pattern
        elif mode == "match":
            if qname in rule["_patterns"]:
                return qname
        elif mode == "wildcard":
            for pattern in rule["_patterns"]:
                if fnmatch.fnmatchcase(qname, pattern):
                    return pattern
    except Exception:
        return None
    return None


def match_rule(qname, rules):
    # First matching rule wins, in list order; rules must come from prepare_rule().
    for rule in rules:
        if matching_pattern(qname, rule) is not None:
            return rule
    return None
