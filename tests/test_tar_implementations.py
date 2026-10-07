"""Acceptance tests for issue #221: GNU tar and bsdtar read some options differently.

GNU tar runs the command that ``-I``, ``--to-command`` and ``--checkpoint-action`` name;
bsdtar (libarchive: macOS, FreeBSD, Windows) reads ``-I`` as a file of include patterns
and rejects the other two. ``gtar`` is GNU tar, so those options run a command:
``high``. ``bsdtar`` runs nothing there: ``-I`` is the value of an option whose effect
is not a command (``medium``), and the GNU options are not its own, so the input after
one is judged as after any option the model does not describe. A bare ``tar`` may be
either: running is possible, its exploitability is to examine (``high``, hotspot).
``--use-compress-program`` runs the compressor it names on both.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.source import SourceManager

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"

HIGH = ("high", "vulnerability", "high")
MEDIUM = ("medium", "vulnerability", "high")
HIGH_TO_REVIEW = ("high", "hotspot", "medium")


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
        ('subprocess.run(["tar", f"-I{x}", "-xf", "a.tar"])', HIGH_TO_REVIEW),
        ('subprocess.run(["tar", "-I", x, "-xf", "a.tar"])', HIGH_TO_REVIEW),
        ('subprocess.run(["tar", "--to-command", x, "-xf", "a.tar"])', HIGH_TO_REVIEW),
        (
            'subprocess.run(["tar", f"--checkpoint-action=exec={x}", "-xf", "a.tar"])',
            HIGH_TO_REVIEW,
        ),
        ('subprocess.run(["/usr/bin/gtar", f"-I{x}", "-xf", "a.tar"])', HIGH),
        ('subprocess.run(["gtar", "--to-command", x, "-xf", "a.tar"])', HIGH),
        ('subprocess.run(["gtar", f"--checkpoint-action=exec={x}", "-xf", "a.tar"])', HIGH),
        ('subprocess.run(["bsdtar", f"-I{x}", "-xf", "a.tar"])', MEDIUM),
        # Not an option of bsdtar: the input after it may be an option of its own, and
        # --use-compress-program=CMD fits in one element.
        ('subprocess.run(["bsdtar", "--to-command", x, "-xf", "a.tar"])', HIGH_TO_REVIEW),
        ('subprocess.run(["tar", "--use-compress-program", x, "-xf", "a.tar"])', HIGH),
        ('subprocess.run(["gtar", "--use-compress-program", x, "-xf", "a.tar"])', HIGH),
        ('subprocess.run(["bsdtar", "--use-compress-program", x, "-xf", "a.tar"])', HIGH),
        ('subprocess.run(["bsdtar", "-xf", "a.tar", "--", x])', None),
        ('subprocess.run(["gtar", "-xf", "a.tar", "--", x])', None),
    ],
)
def test_the_reading_follows_the_tar_implementation(
    call: str, expected: tuple[str, str, str] | None
) -> None:
    assert judged(call) == ([] if expected is None else [expected])
