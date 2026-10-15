"""Review of #240, part 2 (PR #257): what anchoring a flow at the invocation must keep.

The selection and the invocation are two sites of one flow. A check that proves the name
where ``getattr`` selects proves it for every invocation, even past a join, and a check
before the invocation counts too; the flow is refuted when either site cannot run, in the
function and, for the invocation, through a project helper. Calling the result of a call,
or an item of it, does not call the symbol it comes from: its arguments are not the
call's, so ``h(None, input())`` with ``h = getattr(self, 'factory')`` selects nothing, and
``eval('lambda x: x')(input())`` evaluates constant code. The chains that resolve the
attributes of a result are kept.
"""

from __future__ import annotations

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.source import SourceManager


def findings(text: str, rule: str) -> list[Finding]:
    analysed = engine.check(SourceManager().add_source("app.py", text), [engine.BUNDLED_PLUGINS])
    return [f for f in analysed if f.rule_id == rule]


def method(body: str) -> str:
    return "import os\n\n\nclass Handler:\n    def run(self):\n        name = input()\n" + "".join(
        f"        {line}\n" for line in body.splitlines()
    )


@pytest.mark.parametrize(
    "guard",
    ["name in ('start', 'stop')", "name == 'start'"],
)
def test_a_check_proving_the_name_at_the_selection_holds_past_a_join(guard: str) -> None:
    body = f"if {guard}:\n    handler = getattr(self, name)\nelse:\n    handler = print\nhandler()"

    assert findings(method(body), "code-injection") == []


def test_a_check_of_the_shape_at_the_selection_still_leaves_a_hotspot() -> None:
    body = "if name.isidentifier():\n    handler = getattr(self, name)\nelse:\n    handler = print\nhandler()"

    (finding,) = findings(method(body), "code-injection")
    assert finding.metadata["verdict"] == "hotspot"


@pytest.mark.parametrize(
    "body",
    [
        # The selection cannot run.
        "if False:\n    handler = getattr(self, name)\nelse:\n    handler = print\nhandler()",
        # The invocation cannot run.
        "handler = getattr(self, name)\nif False:\n    handler()",
    ],
)
def test_a_selection_or_an_invocation_that_cannot_run_is_not_reported(body: str) -> None:
    assert findings(method(body), "code-injection") == []


HELPER = "def select(obj, name):\n{body}\n\n\nclass Handler:\n    def run(self):\n        select(self, input())\n"


@pytest.mark.parametrize(
    ("body", "reported"),
    [
        ("    handler = getattr(obj, name)\n    if False:\n        handler()", False),
        ("    if False:\n        getattr(obj, name)()", False),
        ("    handler = getattr(obj, name)\n    handler()", True),
    ],
)
def test_through_a_helper_both_sites_must_be_able_to_run(body: str, reported: bool) -> None:
    text = HELPER.format(body=body)
    found = findings(text, "code-injection")

    # Reported at the call of the helper, the last line.
    assert [f.span.start_line for f in found] == ([text.count("\n")] if reported else [])


FACTORY = "class Handler:\n    def factory(self, unused, text):\n        return print\n\n    def run(self):\n"


@pytest.mark.parametrize(
    "text",
    [
        # The review's case: the input is an argument of the selected method.
        FACTORY + "        h = getattr(self, 'factory')\n        h(None, input())()\n",
        FACTORY + "        getattr(self, 'factory')(None, input())()\n",
        # The same confusion with the other sinks of the rule.
        "def run():\n    eval('lambda x: x')(input())\n",
        "import importlib\n\n\ndef run():\n    importlib.import_module('plugins')(input())\n",
        "import runpy\n\n\ndef run():\n    runpy.run_path('jobs/report.py')['main'](input())\n",
    ],
)
def test_the_arguments_of_a_returned_callable_are_not_the_call_s(text: str) -> None:
    assert findings(text, "code-injection") == []


@pytest.mark.parametrize(
    ("text", "rule", "line"),
    [
        ("def run():\n    eval(input())('x')\n", "code-injection", 2),
        ("class Handler:\n    def run(self):\n        getattr(self, input())(None)()\n", "code-injection", 3),
        ("import runpy\n\n\ndef run():\n    runpy.run_path(input()).get('main')\n", "code-injection", 5),
        ("import tarfile\n\n\ndef run(p):\n    tarfile.open(p).extractall('/tmp/x')\n", "unsafe-archive-extraction", 5),
    ],
)
def test_the_call_itself_and_the_chains_on_its_result_are_still_reported(text: str, rule: str, line: int) -> None:
    assert [f.span.start_line for f in findings(text, rule)] == [line]
