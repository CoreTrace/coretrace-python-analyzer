"""Acceptance tests for issue #208: what the attacker controls in a process's command.

A string that a shell interprets, a string naming the program, or the program itself is
a command injection, ``high``. An element of an argument list run without a shell
cannot inject a command, only an option: ``medium`` by default when the executable is
fixed, ``high`` when the option's dangerous behaviour is established by model data
(``git push --receive-pack=<cmd>``, ``ssh -o ProxyCommand=...``, ``sh -c``). A constant
prefix is judged by what the attacker still controls: ``f"v{x}"`` is no option at all,
``f"--output={x}"`` is the value of a fixed option, ``f"--{x}"`` leaves the option open.
A value after an option is that option's value only when the model establishes that the
option consumes it, and a free element when the model establishes that the options before
it take no value (``rm -rf``); otherwise the finding stays, for review. Severity is set per case:
the ``hotspot`` verdict lowers the confidence, never the severity.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.frontend import build_hir
from coretrace_python.ir.lowering import lower_module
from coretrace_python.ir.model import BuildList, BuildTuple
from coretrace_python.source import SourceManager

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"

HIGH = ("high", "vulnerability", "high")
MEDIUM = ("medium", "vulnerability", "high")
HIGH_TO_REVIEW = ("high", "hotspot", "medium")
MEDIUM_TO_REVIEW = ("medium", "hotspot", "medium")


def judged(call: str) -> list[tuple[str, str, str]]:
    """Severity, verdict and confidence of each command-injection finding on ``call``,
    made with ``x`` read from the command line and ``extra`` of unknown value."""

    text = f"import os\nimport subprocess\nimport sys\n\n\ndef run(extra):\n    x = sys.argv[1]\n    {call}\n"
    findings = engine.check(SourceManager().add_source("app/run.py", text), [PLUGINS])
    return [
        (f.severity.value, f.metadata["verdict"], f.confidence.value)
        for f in findings
        if f.rule_id == "command-injection"
    ]


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        # 1, 2, 3, 8: the attacker reaches a shell or chooses the program.
        ('subprocess.run(f"git tag {x}", shell=True)', HIGH),
        ('os.system("ls " + x)', HIGH),
        ("subprocess.run(x)", HIGH),
        ('subprocess.run([x, "-l"])', HIGH),
        ('subprocess.run(["ls"], executable=x)', HIGH),
        ("subprocess.run(x, shell=extra)", HIGH_TO_REVIEW),
        # 4: a free element is an option the attacker chooses.
        ('subprocess.run(["ls", x])', MEDIUM),
        ('subprocess.run(["git", "status", x])', MEDIUM),
        ('subprocess.run(["git", "push", "origin", x])', HIGH),
        ('subprocess.run(["/usr/bin/git", "push", "origin", x])', HIGH),
        # 5, 5b, 5c: a constant prefix.
        ('subprocess.run(["git", "tag", f"v{x}"])', None),
        ('subprocess.run(["git", "commit", "-m", f"release {x}"])', None),
        ('subprocess.run(["curl", f"--output={x}"])', MEDIUM),
        ('subprocess.run(["git", "fetch", f"--upload-pack={x}"])', HIGH),
        ('subprocess.run(["ssh", f"-o{x}", "host"])', HIGH),
        ('subprocess.run(["ls", f"--{x}"])', MEDIUM),
        # 6: after the end of options, for a program known to honour it.
        ('subprocess.run(["git", "log", "--", x])', None),
        ('subprocess.run(["ls", "--", x])', MEDIUM),
        # 7: after an option that may take a value.
        ('subprocess.run(["ssh", "-o", x, "host"])', HIGH),
        ('subprocess.run(["sh", "-c", x])', HIGH),
        ('subprocess.run(["find", ".", "-exec", x, ";"])', HIGH),
        ('subprocess.run(["xcrun", "notarytool", "--keychain", x])', MEDIUM_TO_REVIEW),
        ('subprocess.run(["git", "push", "--force", x])', HIGH_TO_REVIEW),
        # Short options grouped in one element, read as getopt does.
        ('subprocess.run(["rm", "-rf", x])', MEDIUM),
        ('subprocess.run(["rm", "-r", "-f", x])', MEDIUM),
        ('subprocess.run(["rm", "-rz", x])', MEDIUM_TO_REVIEW),
        ('subprocess.run(["ssh", "-vo", x, "host"])', HIGH),
        ('subprocess.run(["ssh", "-ov", x, "host"])', HIGH),
        # Unpacked parts keep their place in the command.
        ('subprocess.run(["xcrun", "notarytool", *(["--keychain", x])])', MEDIUM_TO_REVIEW),
        ("subprocess.run([*extra, x])", HIGH),
        ('subprocess.run(["ls", *extra, x])', MEDIUM),
        ('subprocess.run(["ls", *x.split()])', MEDIUM),
    ],
)
def test_the_result_follows_what_the_attacker_controls(
    call: str, expected: tuple[str, str, str] | None
) -> None:
    assert judged(call) == ([] if expected is None else [expected])


def test_an_unpacked_element_keeps_its_place_in_a_list_or_tuple_display() -> None:
    module = lower_module(
        build_hir(
            SourceManager().add_source("m.py", "def f(a, b):\n    use([1, *a, 2, *b], (*a, 1))\n")
        )
    )
    instructions = [i for block in module.functions[0].blocks for i in block.instructions]
    (built_list,) = [i for i in instructions if isinstance(i, BuildList)]
    (built_tuple,) = [i for i in instructions if isinstance(i, BuildTuple)]

    assert built_list.unpacked_at == (1, 3)
    assert built_tuple.unpacked_at == (0,)
