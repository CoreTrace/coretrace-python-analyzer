"""Code injection: attacker input reaching the code ``eval`` or ``exec`` runs.

``dangerous-eval`` reports every call to ``eval`` or ``exec``, whatever it evaluates;
``code-injection`` reports the calls attacker input reaches, through the same taint
engine and refutation as the other injection rules. Only the code counts: attacker data
in the ``globals`` or ``locals`` a call passes is data, not code.
"""

from __future__ import annotations

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding, Severity
from coretrace_python.source import SourceManager

PLUGINS = [engine.BUNDLED_PLUGINS]


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("app.py", text), PLUGINS)


def injected(text: str) -> list[int]:
    return [f.span.start_line for f in check(text) if f.rule_id == "code-injection"]


@pytest.mark.parametrize(
    "body",
    [
        "    return eval(input())\n",
        "    exec(input())\n",
        "    code = compile(input(), '<input>', 'exec')\n    exec(code)\n",
        "    source = 'result = ' + input()\n    exec(source, {})\n",
    ],
)
def test_attacker_input_in_the_code_eval_or_exec_runs_is_a_code_injection(body: str) -> None:
    findings = [f for f in check(f"def run():\n{body}") if f.rule_id == "code-injection"]

    assert [f.span.start_line for f in findings] == [len(body.splitlines()) + 1]
    assert findings[0].severity is Severity.HIGH
    assert findings[0].metadata["source_label"] == "stdin"


@pytest.mark.parametrize(
    "body",
    [
        "    return eval('1 + 1')\n",
        "    return eval('x + 1', {'x': input()})\n",
        "    exec('total = a + b', {}, {'a': input(), 'b': 1})\n",
        "    import ast\n    return ast.literal_eval(input())\n",
    ],
)
def test_constant_code_or_attacker_data_beside_it_is_no_code_injection(body: str) -> None:
    assert injected(f"def run():\n{body}") == []


def test_dangerous_eval_still_reports_the_call_beside_the_injection() -> None:
    rules = sorted(f.rule_id for f in check("def run():\n    return eval(input())\n"))

    assert rules == ["code-injection", "dangerous-eval"]


def test_code_reaching_eval_through_a_project_function_is_reported_at_the_call() -> None:
    text = "def evaluate(expression):\n    return eval(expression)\n\ndef run():\n    return evaluate(input())\n"

    (finding,) = [f for f in check(text) if f.rule_id == "code-injection"]
    assert (finding.span.start_line, finding.metadata["through"], finding.metadata["sink_line"]) == (5, "evaluate", "2")
