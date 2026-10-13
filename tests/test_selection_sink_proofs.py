"""Review of #240 (PR #250): a check of the shape of a name does not prove an import.

``isidentifier()``, ``isalnum()``, ``isdigit()`` or a ``re.fullmatch`` validator limit the
characters of a name, not the modules or files it can name: the input still chooses
the code that runs. For the sinks that select code by name (``Sink.selects``), only a
check that limits the value to constants proves it: membership in a constant
collection or equality with a constant. A guard that only checks the shape leaves a
hotspot. ``eval``, ``exec`` and every other sink keep the proofs they had.
"""

from __future__ import annotations

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.source import SourceManager

HEADER = "import importlib\nimport os\nimport re\nimport runpy\n\n\ndef run():\n    name = input()\n"


def findings(body: str, rule: str) -> list[Finding]:
    text = HEADER + "".join(f"    {line}\n" for line in body.splitlines())
    analysed = engine.check(SourceManager().add_source("app.py", text), [engine.BUNDLED_PLUGINS])
    return [f for f in analysed if f.rule_id == rule]


SINKS = [
    "importlib.import_module(name)",
    "__import__(name)",
    "runpy.run_module(name)",
    "runpy.run_path(name)",
]


@pytest.mark.parametrize("sink", SINKS)
@pytest.mark.parametrize(
    "guard",
    [
        "name.isidentifier()",
        "name.isalnum()",
        "name.isdigit()",
        "name.isascii()",
        "re.fullmatch(r'[a-z_]+', name)",
    ],
)
def test_a_check_of_the_shape_of_the_name_leaves_a_hotspot(sink: str, guard: str) -> None:
    (finding,) = findings(f"if {guard}:\n    {sink}", "code-injection")

    assert finding.metadata["verdict"] == "hotspot"
    assert finding.confidence.value == "medium"


@pytest.mark.parametrize("sink", SINKS)
@pytest.mark.parametrize("guard", ["name in ('csv', 'json')", "name == 'json'"])
def test_a_check_against_constants_still_proves_the_name(sink: str, guard: str) -> None:
    assert findings(f"if {guard}:\n    {sink}", "code-injection") == []


@pytest.mark.parametrize(
    ("body", "rule"),
    [
        ("if name.isidentifier():\n    eval(name)", "code-injection"),
        ("if name.isalnum():\n    exec(name)", "code-injection"),
        ("if name.isalnum():\n    os.system(name)", "command-injection"),
    ],
)
def test_other_sinks_keep_the_proofs_they_had(body: str, rule: str) -> None:
    assert findings(body, rule) == []
