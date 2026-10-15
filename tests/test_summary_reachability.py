"""Acceptance tests for issue #258: a summary keeps nothing of the blocks constant
propagation proves unreachable.

A project function's summary carries its sinks, its return, the arguments it mutates
and the values merged at a join to its callers. A block that can never run contributes
none of them: no flow is reported at a caller for code under ``if False:`` or
``while False:``, through one or several functions. A block that may run is kept,
whatever decides it at run time: a parameter, or a module-level name the analysis of
one function does not resolve.
"""

from __future__ import annotations

import pytest

from coretrace_python import engine
from coretrace_python.source import SourceManager


def injections(body: str) -> list[tuple[int, str]]:
    text = "import os\n\n\n" + body
    findings = engine.check(SourceManager().add_source("app.py", text), [engine.BUNDLED_PLUGINS])
    return [(f.span.start_line, f.metadata["verdict"]) for f in findings if f.rule_id == "command-injection"]


@pytest.mark.parametrize(
    "body",
    [
        # A sink.
        "def helper(cmd):\n    if False:\n        os.system(cmd)\n\n\ndef caller():\n    helper(input())\n",
        "def helper(cmd):\n    while False:\n        os.system(cmd)\n\n\ndef caller():\n    helper(input())\n",
        # A return.
        "def helper(cmd):\n    if False:\n        return cmd\n    return 'ls'\n\n\ndef caller():\n    os.system(helper(input()))\n",
        # A value merged at a join from the block that cannot run.
        (
            "def helper(cmd):\n    result = 'ls'\n    if False:\n        result = cmd\n    return result\n\n\n"
            "def caller():\n    os.system(helper(input()))\n"
        ),
        # A mutated argument.
        (
            "def helper(items, cmd):\n    if False:\n        items.append(cmd)\n\n\n"
            "def caller():\n    items = []\n    helper(items, input())\n    os.system(items[0])\n"
        ),
        # Through two functions.
        (
            "def inner(cmd):\n    if False:\n        os.system(cmd)\n\n\ndef outer(cmd):\n    inner(cmd)\n\n\n"
            "def caller():\n    outer(input())\n"
        ),
    ],
)
def test_nothing_of_a_block_that_cannot_run_reaches_the_callers(body: str) -> None:
    assert injections(body) == []


@pytest.mark.parametrize(
    ("body", "line"),
    [
        # Decided at run time by a parameter.
        ("def helper(cmd, flag):\n    if flag:\n        os.system(cmd)\n\n\ndef caller(flag):\n    helper(input(), flag)\n", 10),
        # A module-level name, not resolved within the function.
        ("DEBUG = False\n\n\ndef helper(cmd):\n    if DEBUG:\n        os.system(cmd)\n\n\ndef caller():\n    helper(input())\n", 13),
        # The same effects in blocks that run.
        ("def helper(cmd):\n    if True:\n        os.system(cmd)\n\n\ndef caller():\n    helper(input())\n", 10),
        (
            (
                "def helper(cmd):\n    result = 'ls'\n    if True:\n        result = cmd\n    return result\n\n\n"
                "def caller():\n    os.system(helper(input()))\n"
            ),
            12,
        ),
        (
            (
                "def helper(items, cmd):\n    if True:\n        items.append(cmd)\n\n\n"
                "def caller():\n    items = []\n    helper(items, input())\n    os.system(items[0])\n"
            ),
            12,
        ),
    ],
)
def test_a_block_that_may_run_keeps_its_effects(body: str, line: int) -> None:
    assert injections(body) == [(line, "vulnerability")]
