"""Review of #258 (PR #259): a nested function that may leave a ``nonlocal`` unwritten
leaves the caller's variable as it was before the call.

The summary of a nested function says, for each ``nonlocal`` it writes, what it writes
and whether it may also return without writing it (``NonlocalWrite.kept``); no record
means it never writes it. The caller then keeps the value its variable held before the
call wherever the name may be left unwritten, joined with what the function may write:
a write under ``if False:``, on some paths only, after an exception, or no write at
all. Only a write on every path that returns replaces the value.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cache import ProjectCache
from coretrace_python.source import SourceManager


def injections(body: str) -> list[tuple[int, str]]:
    text = "import os\n\n\n" + body
    findings = engine.check(SourceManager().add_source("app.py", text), [engine.BUNDLED_PLUGINS])
    return [(f.span.start_line, f.metadata["verdict"]) for f in findings if f.rule_id == "command-injection"]


def nested(write: str, before_call: str = "") -> str:
    """``run`` reads input into ``cmd``, defines ``keep`` writing it as ``write`` says,
    calls it and runs ``cmd``; the call to ``os.system`` is the last line."""

    lines = ["def run(flag):", "    cmd = input()", "    def keep():", "        nonlocal cmd"]
    lines += [f"        {line}" for line in write.splitlines()]
    lines += [f"    {line}" for line in before_call.splitlines()]
    lines += ["    keep()", "    os.system(cmd)"]
    return "\n".join(lines) + "\n"


def last_line(body: str) -> int:
    return ("import os\n\n\n" + body).count("\n")


@pytest.mark.parametrize(
    "write",
    [
        # The review's cases: the only write cannot run.
        "if False:\n    cmd = cmd",
        "while False:\n    cmd = cmd",
        "if False:\n    cmd = 'ls'",
        # No write at all.
        "print(cmd)",
        # A write on some paths only.
        "if flag:\n    cmd = 'ls'",
        # A write an exception may skip.
        "try:\n    print(len(cmd))\n    cmd = 'ls'\nexcept ValueError:\n    pass",
    ],
)
def test_a_value_the_nested_function_may_leave_unwritten_keeps_its_taint(write: str) -> None:
    body = nested(write)

    assert injections(body) == [(last_line(body), "vulnerability")]


@pytest.mark.parametrize(
    "write",
    [
        "cmd = 'ls'",
        "if flag:\n    cmd = 'ls'\nelse:\n    cmd = 'pwd'",
        "cmd = 'ls'\nif flag:\n    cmd = 'pwd'",
    ],
)
def test_a_safe_value_written_on_every_path_replaces_it(write: str) -> None:
    assert injections(nested(write)) == []


def test_what_the_nested_function_writes_still_reaches_the_caller() -> None:
    body = (
        "def run():\n    cmd = 'ls'\n    def keep():\n        nonlocal cmd\n        cmd = input()\n"
        "    keep()\n    os.system(cmd)\n"
    )

    assert injections(body) == [(last_line(body), "vulnerability")]


def test_the_value_kept_is_the_one_before_the_call_not_at_the_definition() -> None:
    # Safe when ``keep`` is defined, input when it is called.
    body = (
        "def run():\n    cmd = 'ls'\n    def keep():\n        nonlocal cmd\n        if False:\n            cmd = cmd\n"
        "    cmd = input()\n    keep()\n    os.system(cmd)\n"
    )

    assert injections(body) == [(last_line(body), "vulnerability")]


def test_the_kept_value_reaches_the_caller_of_the_enclosing_function() -> None:
    body = (
        "def run(value):\n    cmd = value\n    def keep():\n        nonlocal cmd\n        if False:\n            cmd = 'ls'\n"
        "    keep()\n    return cmd\n\n\ndef caller():\n    os.system(run(input()))\n"
    )

    assert injections(body) == [(last_line(body), "vulnerability")]


def test_the_kept_flag_survives_the_cache(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "app").mkdir(parents=True)
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app" / "main.py").write_text("import os\n\n\n" + nested("if flag:\n    cmd = 'ls'"), encoding="utf-8")
    cache = ProjectCache(tmp_path / "cache")

    analysis = engine.analyze_project(root, [engine.BUNDLED_PLUGINS], cache=cache)
    entry = cache.load(analysis.keys["app.main"])

    assert entry is not None
    assert [(w.name, w.kept) for w in entry.summaries["run.keep"].nonlocal_writes] == [("cmd", True)]
