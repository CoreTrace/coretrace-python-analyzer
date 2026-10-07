"""Acceptance tests for issue #218: the script after ``-File`` is a file name.

PowerShell takes the element after ``-File`` as the script, whatever it is spelled
like: a script named ``-c`` or ``-Command`` is no ``-Command`` option, so the elements
after it are arguments of the script, and one behind a constant prefix is refuted, as
after ``-File s.ps1``. A ``-Command`` before ``-File`` still makes every later element
the command.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.source import SourceManager

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"

HIGH = ("high", "vulnerability", "high")


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


@pytest.mark.parametrize("program", ["pwsh", "powershell"])
@pytest.mark.parametrize("script", ["-c", "-e", "-ec", "-Command"])
def test_a_script_spelled_like_an_option_is_a_file_name(program: str, script: str) -> None:
    assert judged(f'subprocess.run(["{program}", "-File", "{script}", f"v{{x}}"])') == []


@pytest.mark.parametrize("program", ["pwsh", "powershell"])
def test_a_command_option_before_the_file_still_takes_the_rest(program: str) -> None:
    assert judged(f'subprocess.run(["{program}", "-Command", "-File", "s.ps1", f"v{{x}}"])') == [
        HIGH
    ]
