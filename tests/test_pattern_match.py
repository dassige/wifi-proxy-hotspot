from pattern_match import match_rule, prepare_rule


def rules(*specs):
    return [prepare_rule({"id": str(i), "pattern": p, "mode": m, "action": "x"}) for i, (p, m) in enumerate(specs)]


def test_wildcard_star_dot_does_not_match_bare_domain():
    rs = rules(("*.raiplay.it", "wildcard"))
    assert match_rule("www.raiplay.it", rs)
    assert match_rule("raiplay.it", rs) is None


def test_exact_match_is_whole_hostname():
    rs = rules(("raiplay.it", "match"))
    assert match_rule("raiplay.it", rs)
    assert match_rule("www.raiplay.it", rs) is None


def test_patterns_compare_lowercased():
    assert match_rule("www.raiplay.it", rules(("*.RaiPlay.IT", "wildcard")))


def test_regexp_is_fullmatch_and_case_insensitive():
    rs = rules((r"(.*\.)?raiplay\.it", "regexp"))
    assert match_rule("raiplay.it", rs) and match_rule("a.b.raiplay.it", rs)
    assert match_rule("raiplay.it.evil.com", rs) is None


def test_invalid_regexp_is_dropped_not_fatal():
    assert prepare_rule({"pattern": "([", "mode": "regexp"}) is None


def test_first_match_wins_in_order():
    rs = rules(("*.cdn.netrw.it", "wildcard"), ("*.netrw.it", "wildcard"))
    assert match_rule("x.cdn.netrw.it", rs)["id"] == "0"
    assert match_rule("y.netrw.it", rs)["id"] == "1"
