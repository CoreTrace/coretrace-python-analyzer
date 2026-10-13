"""The verdicts of #240, one concern at a time: what a constant package prefix proves, a
name the input controls entirely, and ``eval`` and ``exec`` left as they were.

A constant prefix that ends a package path (``"app.plugins." + name``) confines an import
to the modules of that package: a hotspot. A prefix that fixes no package, a relative
name, input before the constant, or a directory in front of a script path confines
nothing. ``eval`` and ``exec`` run the code they are given: no prefix proves anything
there.
"""

from __future__ import annotations

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.source import SourceManager

IMPORTS = "import importlib\nimport runpy\n\nPLUGINS = 'app.plugins.'\n\n\n"


def injection(body: str) -> Finding:
    text = f"{IMPORTS}def run(prefix):\n    {body}\n"
    findings = [
        f
        for f in engine.check(SourceManager().add_source("app.py", text), [engine.BUNDLED_PLUGINS])
        if f.rule_id == "code-injection"
    ]
    (finding,) = findings
    return finding


def verdict(finding: Finding) -> tuple[str, str, str]:
    return finding.metadata["verdict"], finding.confidence.value, finding.message.split(":", 1)[0]


@pytest.mark.parametrize(
    "body",
    [
        "importlib.import_module('app.plugins.' + input())",
        "importlib.import_module(f'app.plugins.{input()}')",
        "importlib.import_module('app.' + input())",
        "importlib.import_module(PLUGINS + input())",
        "__import__('app.plugins.' + input())",
        "runpy.run_module('app.jobs.' + input())",
    ],
)
def test_a_constant_package_prefix_makes_a_hotspot(body: str) -> None:
    finding = injection(body)

    assert verdict(finding) == ("hotspot", "medium", "Untrusted module import")
    assert "the package is fixed by" in finding.metadata["evidence"]


@pytest.mark.parametrize(
    ("body", "title"),
    [
        # No package fixed: ``"app" + name`` can be any module whose name starts so.
        ("importlib.import_module('app' + input())", "Untrusted module import"),
        # A relative name is resolved against the ``package`` argument, which the rule
        # does not read: the package it lands in is not established.
        ("importlib.import_module('.' + input(), package='app')", "Untrusted module import"),
        ("importlib.import_module('.plugins.' + input(), package='app')", "Untrusted module import"),
        ("importlib.import_module(input() + '.plugins')", "Untrusted module import"),
        ("importlib.import_module(prefix + input())", "Untrusted module import"),
        # ``../`` leaves any directory.
        ("runpy.run_path('/srv/scripts/' + input())", "Untrusted script execution"),
    ],
)
def test_a_prefix_that_confines_nothing_stays_a_vulnerability(body: str, title: str) -> None:
    assert verdict(injection(body)) == ("vulnerability", "high", title)


@pytest.mark.parametrize(
    ("body", "title"),
    [
        ("importlib.import_module(input())", "Untrusted module import"),
        ("importlib.import_module(name=input())", "Untrusted module import"),
        ("__import__(input())", "Untrusted module import"),
        ("importlib.__import__(input())", "Untrusted module import"),
        ("runpy.run_module(input())", "Untrusted module import"),
        ("runpy.run_module(mod_name=input())", "Untrusted module import"),
        ("runpy.run_path(input())", "Untrusted script execution"),
        ("runpy.run_path(path_name=input())", "Untrusted script execution"),
    ],
)
def test_a_name_the_input_controls_entirely_is_a_vulnerability(body: str, title: str) -> None:
    assert verdict(injection(body)) == ("vulnerability", "high", title)


@pytest.mark.parametrize(
    "body",
    [
        "eval(input())",
        "exec(input())",
        "eval('app.plugins.' + input())",
        "exec('import ' + input())",
    ],
)
def test_eval_and_exec_are_unchanged(body: str) -> None:
    assert verdict(injection(body)) == ("vulnerability", "high", "Code injection")
