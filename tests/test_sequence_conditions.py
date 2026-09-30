"""An advisory condition of kind ``sequence`` relates two calls on one receiver.

Some flaws span a call sequence: ``Session.get(url, verify=False)`` disables
certificate verification for the pooled connection a later ``Session.get(other)`` on
the same session reuses (requests CVE-2024-35195), and a tornado
``CurlAsyncHTTPClient`` keeps the first fetch's credentials on the reused curl handle.
The entry point is the second call; the condition names the method the first call must
be and, optionally, the argument it must carry. A prior call on the same receiver, on
every path to the entry call, meets it; a receiver followed whole with no such prior
call rules the entry call out, so a project with only single calls stays
``not_affected``; a receiver the engine cannot follow, an order a branch or a loop
leaves uncertain, or an entry call that could be its own prior across loop iterations,
stays pending review.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from coretrace_python import engine
from coretrace_python.cache import CachedModule, ProjectCache, decode, encode
from coretrace_python.dependency import (
    Advisory,
    AdvisoryEntryPoint,
    AdvisoryFileError,
    Condition,
    dump_advisories,
    load_advisories,
    render_vex,
)
from coretrace_python.dependency.correlation import check_conditions
from coretrace_python.engine import ProjectAnalysis
from coretrace_python.findings import Finding, Severity
from coretrace_python.interprocedural import Arguments, CallSite, ExternalSymbol, PriorCall
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceId, SourceSpan

PLUGINS = engine.BUNDLED_PLUGINS
NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)

GET = "python.requests.Session.get"
TEXT = "a prior call on the same session disabled certificate verification"
CONDITION = Condition("sequence", TEXT, "verify", ("False",), method="Session.get")
ADVISORY = Advisory(
    "CVE-2024-35195",
    "requests",
    "<2.32.0",
    "Session keeps verify=False for the connection later requests reuse",
    Severity.MEDIUM,
    entry_points=(
        AdvisoryEntryPoint(SymbolId(GET), "the second request reuses the unverified connection", (CONDITION,)),
    ),
)

LOCK = """version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "requests" }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"""

HEADER = "import requests\n\n\n"
FETCH_BOTH = HEADER + (
    "def fetch_both(url: str, other: str):\n"
    "    s = requests.Session()\n"
    "    s.get(url, verify=False)\n"
    "    return s.get(other)  # reuses the unverified connection\n"
)
FETCH_ONE = HEADER + (
    "def fetch_one(other: str):\n"
    "    s = requests.Session()\n"
    "    return s.get(other)  # nothing to reuse\n"
)
RULED_OUT = f"app.fetch:6 {GET}(no prior Session.get on the receiver)"
TWO_RECEIVERS = HEADER + (
    "def fetch_two(url: str, other: str):\n"
    "    s1 = requests.Session()\n"
    "    s1.get(url, verify=False)\n"
    "    s2 = requests.Session()\n"
    "    return s2.get(other)\n"
)
REVERSED = HEADER + (
    "def fetch_reversed(url: str, other: str):\n"
    "    s = requests.Session()\n"
    "    s.get(other)\n"
    "    return s.get(url, verify=False)\n"
)
PARAMETER = HEADER + "def fetch(s: requests.Session, other: str):\n    return s.get(other)\n"
BRANCHED = HEADER + (
    "def fetch_maybe(url: str, other: str, flag: bool):\n"
    "    s = requests.Session()\n"
    "    if flag:\n"
    "        s.get(url, verify=False)\n"
    "    return s.get(other)\n"
)
ESCAPED = HEADER + (
    "def configure(s):\n"
    "    pass\n"
    "\n"
    "\n"
    "def fetch_helped(url: str, other: str):\n"
    "    s = requests.Session()\n"
    "    s.get(url, verify=False)\n"
    "    configure(s)\n"
    "    return s.get(other)\n"
)
UNPACKED = HEADER + (
    "def fetch_kw(url: str, other: str, **kw):\n"
    "    s = requests.Session()\n"
    "    s.get(url, **kw)\n"
    "    return s.get(other)\n"
)
LOOP = HEADER + (
    "def fetch_all(urls):\n"
    "    s = requests.Session()\n"
    "    for u in urls:\n"
    "        s.get(u, verify=False)\n"
)

CURL_FETCH = "python.tornado.httpclient.CurlAsyncHTTPClient.fetch"
CURL_TEXT = "an earlier fetch on the same client left credentials on the reused curl handle"
CURL_CONDITION = Condition("sequence", CURL_TEXT, method="CurlAsyncHTTPClient.fetch")
CURL_ADVISORY = Advisory(
    "CVE-2026-91992",
    "tornado",
    "<6.5.7",
    "CurlAsyncHTTPClient reuses the previous fetch's credentials, certificate or proxy",
    Severity.HIGH,
    entry_points=(
        AdvisoryEntryPoint(SymbolId(CURL_FETCH), "the reused curl handle keeps per-request state", (CURL_CONDITION,)),
    ),
)
CURL_LOCK = """version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "tornado" }]

[[package]]
name = "tornado"
version = "6.5.0"
source = { registry = "https://pypi.org/simple" }
"""
CURL = (
    "from tornado.httpclient import CurlAsyncHTTPClient\n"
    "\n"
    "\n"
    "async def fetch_pair(first, second):\n"
    "    client = CurlAsyncHTTPClient()\n"
    "    await client.fetch(first)\n"
    "    return await client.fetch(second)\n"
)


def analyse(
    root: Path,
    source: str,
    *,
    lock: str = LOCK,
    advisories: tuple[Advisory, ...] = (ADVISORY,),
    cache: ProjectCache | None = None,
) -> ProjectAnalysis:
    files = {"uv.lock": lock, "app/__init__.py": "", "app/fetch.py": source}
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories(advisories), encoding="utf-8")
    return engine.analyze_project(root, [PLUGINS], cache=cache)


def of_rule(analysis: ProjectAnalysis, rule_id: str) -> list[Finding]:
    return sorted((f for f in analysis.findings if f.rule_id == rule_id), key=lambda f: f.span.start_line)


def statement(analysis: ProjectAnalysis, root: Path, advisory: Advisory = ADVISORY) -> dict[str, Any]:
    evidence = (*analysis.findings, *analysis.suppressed, *analysis.accepted)
    document = render_vex(
        analysis.dependencies, analysis.advisories, evidence, analysis.coverage, root, "coretrace", "0.6.0", NOW
    )
    return next(s for s in json.loads(document)["statements"] if s["vulnerability"]["name"] == advisory.id)


# --------------------------------------------------------------------------- the reproduction


def test_a_prior_call_disabling_verification_meets_the_condition(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, FETCH_BOTH)

    first, second = of_rule(analysis, "reachable-vulnerability")
    assert second.span.start_line == 7
    assert second.metadata["symbol"] == GET
    assert second.metadata["conditions_met"] == f"{TEXT} (prior Session.get at line 6)"
    assert "conditions_pending_review" not in second.metadata
    # The first call could be its own prior across the iterations of a loop.
    assert first.span.start_line == 6
    assert first.metadata["conditions_pending_review"] == TEXT
    assert "conditions_met" not in first.metadata
    (declared,) = of_rule(analysis, "vulnerable-dependency")
    assert "ruled_out" not in declared.metadata
    assert statement(analysis, tmp_path)["status"] == "affected"


def test_a_single_call_without_the_argument_is_ruled_out(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, FETCH_ONE)

    assert of_rule(analysis, "reachable-vulnerability") == []
    assert of_rule(analysis, "exploitable-vulnerability") == []
    (declared,) = of_rule(analysis, "vulnerable-dependency")
    assert declared.metadata["level"] == "imported"
    assert declared.metadata["ruled_out"] == RULED_OUT
    found = statement(analysis, tmp_path)
    assert found["status"] == "not_affected"
    assert found["impact_statement"].endswith(f" Calls ruled out by their arguments: {RULED_OUT}.")


def test_calls_on_different_receivers_do_not_relate(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, TWO_RECEIVERS)

    # The fetching call has its own receiver and no prior call on it: ruled out. The
    # disabling call itself carries verify=False, so it is pending, never ruled out.
    (disabling,) = of_rule(analysis, "reachable-vulnerability")
    assert disabling.span.start_line == 6
    assert disabling.metadata["conditions_pending_review"] == TEXT
    assert "conditions_met" not in disabling.metadata
    (declared,) = of_rule(analysis, "vulnerable-dependency")
    assert declared.metadata["ruled_out"] == f"app.fetch:8 {GET}(no prior Session.get on the receiver)"
    assert statement(analysis, tmp_path)["status"] == "affected"


def test_a_later_matching_call_leaves_the_earlier_one_pending(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, REVERSED)

    first, second = of_rule(analysis, "reachable-vulnerability")
    assert (first.span.start_line, second.span.start_line) == (6, 7)
    for found in (first, second):
        assert found.metadata["conditions_pending_review"] == TEXT
        assert "conditions_met" not in found.metadata
    (declared,) = of_rule(analysis, "vulnerable-dependency")
    assert "ruled_out" not in declared.metadata
    assert statement(analysis, tmp_path)["status"] == "affected"


# --------------------------------------------------------------------------- pending receivers


@pytest.mark.parametrize(
    "source, line",
    [
        (PARAMETER, 5),
        (BRANCHED, 8),
        (ESCAPED, 12),
        (UNPACKED, 7),
    ],
    ids=["parameter-receiver", "prior-under-if", "receiver-passed-to-helper", "prior-with-unpacked-arguments"],
)
def test_a_receiver_or_an_order_the_engine_cannot_follow_is_pending(
    tmp_path: Path, source: str, line: int
) -> None:
    analysis = analyse(tmp_path, source)

    found = next(f for f in of_rule(analysis, "reachable-vulnerability") if f.span.start_line == line)
    assert found.metadata["conditions_pending_review"] == TEXT
    assert "conditions_met" not in found.metadata
    (declared,) = of_rule(analysis, "vulnerable-dependency")
    assert "ruled_out" not in declared.metadata
    assert statement(analysis, tmp_path)["status"] == "affected"


def test_a_lone_call_in_a_loop_may_be_its_own_prior(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, LOOP)

    (found,) = of_rule(analysis, "reachable-vulnerability")
    assert found.span.start_line == 7
    assert found.metadata["conditions_pending_review"] == TEXT
    assert "conditions_met" not in found.metadata
    (declared,) = of_rule(analysis, "vulnerable-dependency")
    assert "ruled_out" not in declared.metadata
    assert statement(analysis, tmp_path)["status"] == "affected"


def test_a_method_only_condition_relates_the_two_fetches_of_one_client(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, CURL, lock=CURL_LOCK, advisories=(CURL_ADVISORY,))

    first, second = of_rule(analysis, "reachable-vulnerability")
    assert second.span.start_line == 7
    assert second.metadata["symbol"] == CURL_FETCH
    assert second.metadata["conditions_met"] == f"{CURL_TEXT} (prior CurlAsyncHTTPClient.fetch at line 6)"
    assert first.span.start_line == 6
    assert first.metadata["conditions_pending_review"] == CURL_TEXT
    assert statement(analysis, tmp_path, CURL_ADVISORY)["status"] == "affected"


# --------------------------------------------------------------------------- advisory files


def test_the_condition_round_trips_through_advisory_files(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_text(dump_advisories((ADVISORY,)), encoding="utf-8")

    assert load_advisories(path) == (ADVISORY,)
    (entry,) = json.loads(path.read_text())["advisories"][0]["entry_points"]
    assert entry["conditions"] == [
        {"kind": "sequence", "text": TEXT, "argument": "verify", "values": ["False"], "method": "Session.get"}
    ]


@pytest.mark.parametrize(
    "condition",
    [
        {"kind": "sequence", "text": TEXT},
        {"kind": "sequence", "text": TEXT, "method": ""},
        {"kind": "sequence", "text": TEXT, "method": "Session.get", "values": ["False"]},
        {"kind": "argument", "text": TEXT, "argument": "verify", "values": ["False"], "method": "Session.get"},
    ],
    ids=["no-method", "empty-method", "values-without-argument", "method-on-another-kind"],
)
def test_an_invalid_sequence_condition_is_rejected(tmp_path: Path, condition: dict[str, Any]) -> None:
    document = json.loads(dump_advisories((ADVISORY,)))
    document["advisories"][0]["entry_points"][0]["conditions"] = [condition]
    path = tmp_path / "advisories.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(AdvisoryFileError):
        load_advisories(path)


# --------------------------------------------------------------------------- the cache


SPAN = SourceSpan(SourceId("/p/a.py"), 7, 12, 7, 24)
PRIOR = PriorCall(
    SymbolId(GET),
    SourceSpan(SourceId("/p/a.py"), 6, 5, 6, 30),
    Arguments((None,), (("verify", "False"),)),
    True,
)


def test_prior_calls_round_trip_through_the_cache_codec() -> None:
    related = CallSite("f", SPAN, ExternalSymbol(SymbolId(GET)), Arguments((None,)), (PRIOR,))
    unfollowed = CallSite("g", SPAN, ExternalSymbol(SymbolId(GET)))

    text = json.dumps(encode(CachedModule((), {}, (related, unfollowed), ())))
    restored = decode(json.loads(text))

    assert restored.sites == (related, unfollowed)
    assert restored.sites[0].prior_calls == (PRIOR,)
    assert restored.sites[1].prior_calls is None


def test_findings_served_from_the_cache_are_identical(tmp_path: Path) -> None:
    cache = ProjectCache(tmp_path / "cache")

    first = analyse(tmp_path / "src", FETCH_BOTH, cache=cache)
    second = analyse(tmp_path / "src", FETCH_BOTH, cache=cache)

    assert second.findings == first.findings
    met = [f for f in second.findings if f.rule_id == "reachable-vulnerability" and "conditions_met" in f.metadata]
    assert len(met) == 1


# --------------------------------------------------------------------------- the decision


ENTRY = AdvisoryEntryPoint(SymbolId(GET), "reuses the connection", (CONDITION,))
BARE = Arguments((None,))
DISABLING = Arguments((None,), (("verify", "False"),))
UNDECIDED = Arguments((None,), (), True)


def prior(dominates: bool, arguments: Arguments = DISABLING, symbol: str = GET, line: int = 5) -> PriorCall:
    return PriorCall(SymbolId(symbol), SourceSpan(SourceId("/p/a.py"), line, 5, line, 30), arguments, dominates)


def test_a_dominating_satisfying_prior_call_meets_the_condition() -> None:
    check = check_conditions(ENTRY, BARE, prior_calls=(prior(True),))

    (met,) = check.met
    assert met.text == f"{TEXT} (prior Session.get at line 5)"
    assert check.pending == ()
    assert check.contradicted is None


def test_the_first_satisfying_dominating_prior_call_names_the_line() -> None:
    check = check_conditions(ENTRY, BARE, prior_calls=(prior(True, line=3), prior(True, line=4)))

    (met,) = check.met
    assert met.text.endswith("(prior Session.get at line 3)")


def test_the_method_may_be_the_full_canonical_name() -> None:
    condition = Condition("sequence", TEXT, "verify", ("False",), method=GET)
    entry = AdvisoryEntryPoint(SymbolId(GET), "reuses the connection", (condition,))

    check = check_conditions(entry, BARE, prior_calls=(prior(True),))

    assert len(check.met) == 1
    assert check.contradicted is None


@pytest.mark.parametrize(
    "arguments, prior_calls",
    [
        (BARE, None),
        (BARE, (prior(False),)),
        (BARE, (prior(True, UNDECIDED),)),
        (DISABLING, ()),
        (UNDECIDED, ()),
        (None, ()),
    ],
    ids=[
        "unfollowed-receiver",
        "satisfying-but-non-dominating",
        "prior-arguments-undecided",
        "the-call-is-its-own-prior",
        "own-arguments-undecided",
        "no-arguments-known",
    ],
)
def test_uncertain_priors_leave_the_condition_pending(
    arguments: Arguments | None, prior_calls: tuple[PriorCall, ...] | None
) -> None:
    check = check_conditions(ENTRY, arguments, prior_calls=prior_calls)

    assert check.met == ()
    assert check.pending == (CONDITION,)
    assert check.contradicted is None


@pytest.mark.parametrize(
    "prior_calls",
    [
        (),
        (prior(True, BARE),),
        (prior(True, symbol="python.requests.Session.post"),),
    ],
    ids=["alone-on-the-receiver", "prior-without-the-argument", "another-method"],
)
def test_a_followed_receiver_without_a_satisfying_prior_call_is_contradicted(
    prior_calls: tuple[PriorCall, ...],
) -> None:
    check = check_conditions(ENTRY, BARE, prior_calls=prior_calls)

    assert check.met == ()
    assert check.contradicted == CONDITION
    assert check.passed is None
