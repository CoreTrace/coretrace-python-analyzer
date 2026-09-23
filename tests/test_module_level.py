"""Module-level statements and class bodies are analysed like functions.

They are lowered as synthetic functions — ``<module>`` for the module body, ``Cls.<body>``
for a top-level class — so their calls are call sites, their values carry taint and an
advisory's entry point called at import time is reachable. Definitions inside them stay
the separate functions they always were.
"""

from __future__ import annotations

from pathlib import Path

from coretrace_python import engine
from coretrace_python.dependency import Advisory, AdvisoryEntryPoint, dump_advisories
from coretrace_python.findings import Finding, Severity
from coretrace_python.frontend import build_hir
from coretrace_python.ir.lowering import analyzable_functions
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager

REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"

ADVISORY = Advisory(
    "CVE-2099-0003",
    "vulnlib",
    "<1.1",
    "configure trusts its arguments",
    Severity.HIGH,
    entry_points=(AdvisoryEntryPoint(SymbolId("python.vulnlib.configure"), "commit abc1234"),),
    modules=("vulnlib",),
)


def project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, str, int, str | None]]:
    return sorted((Path(str(f.span.source_id)).name, f.rule_id, f.span.start_line, f.function) for f in findings)


# --------------------------------------------------------------------------- synthetic functions


def test_the_module_body_and_class_bodies_are_analysable_functions() -> None:
    module = build_hir(SourceManager().add_source("app/settings.py", "import os\n\nDEBUG = os.getenv('D')\n\nclass Config:\n    key = os.getenv('K')\n\n    def get(self):\n        return self.key\n\ndef helper():\n    pass\n"))

    names = [f.name for f in analyzable_functions(module)]

    assert names == ["<module>", "Config.<body>", "get", "helper"]
    body = analyzable_functions(module)[0]
    assert body.parameters == () and body.span == module.span
    assert all(not isinstance(s, type(module.body[3])) for s in body.body), "the class definition stays out of the module body"


def test_an_empty_module_body_has_no_synthetic_function() -> None:
    module = build_hir(SourceManager().add_source("app/empty.py", "def f():\n    pass\n"))

    assert [f.name for f in analyzable_functions(module)] == ["f"]


# --------------------------------------------------------------------------- findings


def test_a_module_level_injection_is_reported_in_the_module_function(tmp_path: Path) -> None:
    root = project(tmp_path, {"run.py": "import os\n\nos.system(input())\n"})

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert rules(findings) == [("run.py", "command-injection", 3, "<module>")]


def test_a_module_level_call_to_an_advisory_entry_point_is_reachable(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {"requirements.txt": "vulnlib==1.0\n", "project/__init__.py": "", "project/asgi.py": "import vulnlib\n\napplication = vulnlib.configure()\n"},
    )
    (root / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert ("asgi.py", "reachable-vulnerability", 3, "<module>") in rules(findings)


def test_a_class_body_call_to_an_advisory_entry_point_is_reachable(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {"requirements.txt": "vulnlib==1.0\n", "forms.py": "import vulnlib\n\nclass Contact:\n    field = vulnlib.configure()\n\n    def clean(self):\n        return self.field\n"},
    )
    (root / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert ("forms.py", "reachable-vulnerability", 4, "Contact.<body>") in rules(findings)


def test_functions_defined_at_module_level_keep_their_own_analysis(tmp_path: Path) -> None:
    root = project(tmp_path, {"run.py": "import os\n\ndef run(c):\n    os.system(c)\n\nrun(input())\n"})

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert rules(findings) == [("run.py", "command-injection", 6, "<module>")]
    assert findings[0].metadata["through"] == "run"


def test_a_module_level_lambda_is_analysed_as_a_function_of_the_module(tmp_path: Path) -> None:
    """A lambda bound at module level is collected and analysed. Calling it through its
    module-level name is not resolved: the body stores it as a global, which the call
    graph does not follow back to the lambda (a ceiling, not a regression)."""

    module = build_hir(SourceManager().add_source("run.py", "import os\n\nrun = lambda c: os.system(c)\n"))

    assert [f.name for f in analyzable_functions(module)] == ["<module>", "lambda_3_7"]


# --------------------------------------------------------------------------- the body runs as a script


def test_module_variables_are_the_body_s_locals_so_taint_connects(tmp_path: Path) -> None:
    """Found on the regression corpus: with module variables as globals, ``x = input()``
    did not reach ``os.system(x)`` and a module-level ``for`` had no supported target."""

    root = project(tmp_path, {"run.py": "import os\n\ncmd = input()\nos.system(cmd)\n\nfor name, value in os.environ.items():\n    os.system(value)\n"})

    analysis = engine.analyze_project(root, [PLUGINS])

    assert rules(analysis.findings) == [("run.py", "command-injection", 4, "<module>")]
    assert analysis.coverage.functions_analysed == analysis.coverage.functions == 1


def test_functions_still_read_module_variables_as_globals(tmp_path: Path) -> None:
    module = build_hir(SourceManager().add_source("run.py", "LIMIT = 3\n\ndef f():\n    return LIMIT\n"))
    from coretrace_python.ir.lowering import lower_module
    from coretrace_python.ir.model import Global, StoreLocal

    functions = {f.name: f for f in lower_module(module).functions}
    body = [i for b in functions["<module>"].blocks for i in b.instructions]
    reader = [i for b in functions["f"].blocks for i in b.instructions]

    assert any(isinstance(i, StoreLocal) and i.name == "LIMIT" for i in body)
    assert any(isinstance(i, Global) and i.name == "LIMIT" for i in reader)
