"""Acceptance tests for issue #220: what kind of injection a command-injection finding is.

The rule id stays ``command-injection`` for every case, so suppressions and baselines
keep matching. When the rule reads a command element by element, it says what the
attacker's input is there in the ``injection`` metadata:

- ``command``: the input is run, or chooses what runs: a shell string, the program, an
  operand the program runs, an element after an option that runs the rest of the
  command, the value of an option that runs the command it chooses;
- ``option``: the input can only reach the program as an option it may read (a whole
  element, ``--{x}``, an argument of a script) or as the value of an option the model
  does not establish to run it (``curl --output=``, an option it does not describe).
  Its message is titled ``Option injection``.

When the kind cannot be established (an option whose effect is to examine, an unknown
program or element before the input, a command that is not a list or tuple the rule
reads, a sink the rule does not read element by element),
the metadata is absent and the title stays ``Command injection``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.source import SourceManager

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"
COMMAND = ("Command injection", "command")
OPTION = ("Option injection", "option")
UNDETERMINED = ("Command injection", None)


def kinds(call: str) -> list[tuple[str, str, str | None]]:
    """Rule id, message title and ``injection`` metadata of each command-injection finding
    on ``call``, made with ``x`` read from the command line and ``extra`` unknown."""

    text = f"import os\nimport subprocess\nimport sys\n\n\ndef run(extra):\n    x = sys.argv[1]\n    {call}\n"
    findings = engine.check(SourceManager().add_source("app/run.py", text), [PLUGINS])
    return [
        (f.rule_id, f.message.split(":", 1)[0], f.metadata.get("injection"))
        for f in findings
        if f.rule_id == "command-injection"
    ]


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        ('subprocess.run(f"git tag {x}", shell=True)', COMMAND),
        ('subprocess.run([x, "-l"])', COMMAND),
        ('subprocess.run(["sh", "-c", x])', COMMAND),
        ('subprocess.run(["python", "-c", x])', COMMAND),
        ('subprocess.run(["pwsh", "-Command", "Get-Item", x])', COMMAND),
        ('subprocess.run(["ssh", "host", f"cat {x}"])', COMMAND),
        ('subprocess.run(["sudo", x])', COMMAND),
        ('subprocess.run(["git", "fetch", f"--upload-pack={x}"])', COMMAND),
        ('subprocess.run(["ls", x])', OPTION),
        ('subprocess.run(["git", "push", "origin", x])', OPTION),
        ('subprocess.run(["curl", f"--output={x}"])', OPTION),
        ('subprocess.run(["ls", f"--{x}"])', OPTION),
        ('subprocess.run(["node", "app.js", x])', OPTION),
        ('subprocess.run(["notmodelled", "-c", f"echo {x}"])', OPTION),
        ("subprocess.run(x, shell=extra)", UNDETERMINED),
        ('subprocess.run(["python", "-m", x])', UNDETERMINED),
        ('subprocess.run(["tar", "-I", x, "-xf", "a.tar"])', UNDETERMINED),
        ('subprocess.run(["ls", *extra, x])', UNDETERMINED),
        ('subprocess.run(["ls", x], executable=extra)', UNDETERMINED),
        ('os.system("ls " + x)', UNDETERMINED),
        # Not a list the rule reads: a string naming the program, or a list built elsewhere.
        ("subprocess.run(x)", UNDETERMINED),
    ],
)
def test_the_finding_says_what_kind_of_injection_it_is(
    call: str, expected: tuple[str, str | None]
) -> None:
    assert kinds(call) == [("command-injection", *expected)]


def test_a_suppression_of_the_rule_still_applies_to_an_option_injection() -> None:
    text = (
        "import subprocess\nimport sys\n\n\ndef run():\n"
        '    subprocess.run(["ls", sys.argv[1]])  # coretrace: ignore[command-injection]\n'
    )
    analysis = engine.analyze_file(SourceManager().add_source("app/run.py", text), [PLUGINS])

    assert [f.rule_id for f in analysis.findings] == []
    assert [(f.rule_id, f.metadata["injection"]) for f in analysis.suppressed] == [
        ("command-injection", "option")
    ]
