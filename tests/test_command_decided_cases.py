"""Acceptance tests for issue #219: four calls decided in #208, pinned.

Every element after ``pwsh -Command`` is the command, whatever comes first (``&``, a
cmdlet), so the attacker's element is a command injection. An element after
``node -pe CODE`` behind a constant prefix is an argument of the code, no option at
all. An element after ``pwsh -File SCRIPT`` is an argument of the script, an option it
may read: ``medium``. The table of ``test_command_arguments.py`` states the rules.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.source import SourceManager

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"

HIGH = ("high", "vulnerability", "high")
MEDIUM = ("medium", "vulnerability", "high")


def judged(call: str) -> list[tuple[str, str, str]]:
    """Severity, verdict and confidence of each command-injection finding on ``call``,
    made with ``x`` read from the command line."""

    text = f"import subprocess\nimport sys\n\n\ndef run():\n    x = sys.argv[1]\n    {call}\n"
    findings = engine.check(SourceManager().add_source("app/run.py", text), [PLUGINS])
    return [
        (f.severity.value, f.metadata["verdict"], f.confidence.value)
        for f in findings
        if f.rule_id == "command-injection"
    ]


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        ('subprocess.run(["pwsh", "-command", "&", x])', HIGH),
        ('subprocess.run(["pwsh", "-Command", "Get-Item", x])', HIGH),
        ('subprocess.run(["node", "-pe", "CODE", f"v{x}"])', None),
        ('subprocess.run(["pwsh", "-File", "s.ps1", x])', MEDIUM),
    ],
)
def test_a_decided_case_keeps_its_result(call: str, expected: tuple[str, str, str] | None) -> None:
    assert judged(call) == ([] if expected is None else [expected])
