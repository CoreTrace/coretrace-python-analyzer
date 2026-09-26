"""An open-redirect flow is judged on the destination a browser resolves from the target,
as far as ``+`` and f-strings build it, with its own criteria rather than SSRF's.

- A target whose constant text starts a reference a browser resolves on the current site
  (``/profile/``, ``?page=``, ``profile/``) keeps the browser on the site, where any
  further redirect is the project's own code, analysed on its own: refuted.
- A target whose constant text fixes an absolute ``scheme://host`` sends the browser to
  that host, but the input chooses the path, where that host may redirect again: a
  hotspot.
- Anything else stays a vulnerability: ``"/" + next`` (``//evil.com`` is another host),
  a backslash or a control character after the slash, a host left open, an unknown base,
  a target built in a helper function.
"""

from __future__ import annotations

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.source import SourceManager

PLUGINS = [engine.BUNDLED_PLUGINS]

FLASK = (
    "from flask import Flask, redirect, request\n\n"
    "app = Flask(__name__)\n"
    "HOME = '/account/'\n\n"
    "@app.route('/go/<uid>')\n"
    "def go(uid):\n"
    "    return {call}\n"
)


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("app.py", text), PLUGINS)


def redirects(text: str) -> list[tuple[int, str]]:
    return [(f.span.start_line, f.metadata["verdict"]) for f in check(text) if f.rule_id == "open-redirect"]


@pytest.mark.parametrize(
    "call",
    [
        "redirect('/profile/' + uid)",
        "redirect(f'/users/{uid}/edit')",
        "redirect('?page=' + uid)",
        "redirect('#' + uid)",
        "redirect('profile/' + uid)",
        "redirect(HOME + uid)",
    ],
)
def test_a_target_on_the_current_site_is_no_open_redirect(call: str) -> None:
    assert redirects(FLASK.format(call=call)) == []


@pytest.mark.parametrize(
    "call",
    [
        "redirect('https://example.com/' + uid)",
        "redirect(f'https://example.com/login?next={uid}')",
    ],
)
def test_a_target_on_a_fixed_host_is_a_hotspot(call: str) -> None:
    assert redirects(FLASK.format(call=call)) == [(8, "hotspot")]


@pytest.mark.parametrize(
    "call",
    [
        # ``next='/evil.com'`` makes ``//evil.com``, another host.
        "redirect('/' + request.args['next'])",
        "redirect('/\\\\' + uid)",
        "redirect('/\\t' + uid)",
        "redirect('https://example.com' + uid)",
        "redirect('a:b/' + uid)",
        "redirect('java' + uid)",
        "redirect(request.args['next'])",
    ],
)
def test_a_target_the_input_may_send_elsewhere_stays_a_vulnerability(call: str) -> None:
    assert redirects(FLASK.format(call=call)) == [(8, "vulnerability")]


def test_an_unknown_base_stays_a_vulnerability() -> None:
    text = FLASK.format(call="redirect(HOME + uid)").replace("HOME = '/account/'\n", "from settings import HOME\n")

    assert redirects(text) == [(8, "vulnerability")]


def test_a_target_built_in_a_helper_function_stays_a_vulnerability() -> None:
    text = FLASK.format(call="profile(uid)") + "\ndef profile(name):\n    return redirect('/profile/' + name)\n"

    assert redirects(text) == [(8, "vulnerability")]


def test_the_hotspot_evidence_names_the_fixed_host_and_the_further_redirect() -> None:
    (finding,) = [f for f in check(FLASK.format(call="redirect('https://example.com/' + uid)")) if f.rule_id == "open-redirect"]

    assert "'https://example.com/'" in finding.metadata["evidence"] and "redirect" in finding.metadata["evidence"]


@pytest.mark.parametrize(
    "target, verdicts",
    [("'/items/' + pk", []), ("request.GET['next']", [(5, "vulnerability")])],
)
def test_django_redirects_follow_the_same_criteria(target: str, verdicts: list[tuple[int, str]]) -> None:
    text = (
        "from django.shortcuts import redirect\nfrom django.urls import path\n\n"
        "def go(request, pk):\n"
        f"    return redirect({target})\n\n"
        "urlpatterns = [path('go/<pk>/', go)]\n"
    )

    assert redirects(text) == verdicts
