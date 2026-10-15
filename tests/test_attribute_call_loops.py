"""Review of #240, part 2 (PR #257): a check before the invocation proves the selected
name only for the selection it can see.

When the callable reaches its invocation across a loop's back edge, it was selected in
an earlier iteration: a check at the invocation tests the name of the current iteration,
not the one that selected it, so it proves nothing and the hotspot stays. A check where
``getattr`` selects still proves the name, and within one iteration a check before the
invocation does too.
"""

from __future__ import annotations

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.source import SourceManager


def injections(body: str) -> list[Finding]:
    text = "class Handler:\n    def run(self):\n" + "".join(f"        {line}\n" for line in body.splitlines())
    findings = engine.check(SourceManager().add_source("app.py", text), [engine.BUNDLED_PLUGINS])
    return [f for f in findings if f.rule_id == "code-injection"]


def test_a_check_at_the_invocation_does_not_prove_a_name_selected_in_an_earlier_iteration() -> None:
    # The review's case: with the inputs "dangerous", "start", "stop", the second
    # iteration calls self.dangerous(), selected by the first.
    body = (
        "name = input()\n"
        "handler = print\n"
        "for _ in range(2):\n"
        "    if name in ('start', 'stop'):\n"
        "        handler()\n"
        "    handler = getattr(self, name)\n"
        "    name = input()\n"
    )

    (finding,) = injections(body)

    assert (finding.metadata["verdict"], finding.span.start_line) == ("hotspot", 7)
    assert (finding.metadata["selected_line"], finding.metadata["invoked_line"]) == ("8", "7")


def test_a_check_at_the_selection_proves_the_name_across_iterations() -> None:
    body = (
        "name = input()\n"
        "handler = print\n"
        "for _ in range(2):\n"
        "    handler()\n"
        "    if name in ('start', 'stop'):\n"
        "        handler = getattr(self, name)\n"
        "    name = input()\n"
    )

    assert injections(body) == []


@pytest.mark.parametrize(
    "body",
    [
        # Selected and called in the same iteration, the check in between.
        (
            "for _ in range(2):\n    name = input()\n    handler = getattr(self, name)\n"
            "    if name in ('start', 'stop'):\n        handler()\n"
        ),
        (
            "for _ in range(2):\n    name = input()\n    if name in ('start', 'stop'):\n"
            "        getattr(self, name)()\n"
        ),
    ],
)
def test_within_one_iteration_a_check_before_the_invocation_proves_the_name(body: str) -> None:
    assert injections(body) == []


def test_a_name_fixed_before_the_loop_is_not_proven_across_iterations_in_this_version() -> None:
    # Sound to prove, since the name never changes, but the check is at the invocation
    # and the callable crosses the back edge: the hotspot is kept.
    body = (
        "name = input()\n"
        "handler = print\n"
        "for _ in range(2):\n"
        "    if name in ('start', 'stop'):\n"
        "        handler()\n"
        "    handler = getattr(self, name)\n"
    )

    (finding,) = injections(body)

    assert finding.metadata["verdict"] == "hotspot"
