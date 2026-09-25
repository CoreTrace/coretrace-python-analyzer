"""A project's own function, declared as a ``Validator``, proves what it validates.

healthchecks guards ``redirect(redirect_url)`` with ``_allow_redirect(redirect_url)``, a
function of the same module that accepts relative URLs resolving to a known route. A
``Validator`` model names such a function by its project symbol
(``python.<module>.<function>``, as ``project_symbol`` builds it), and the refutation then
recognises a call to it from its own module, as it does for an imported one. An
undeclared function remains a guard that proves nothing.
"""

from __future__ import annotations

from typing import ClassVar

from coretrace_python import engine
from coretrace_python.findings.refutation import RefutationAnalysis, Status
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import Model, SecurityModelRegistry, Sink, Source, TaintKind, Validator

VIEW = (
    "import os\n\n"
    "def run():\n"
    "    target = input()\n"
    "    if allowed(target):\n"
    "        os.system(target)\n\n"
    "def allowed(value):\n"
    "    return value in ('ls', 'pwd')\n"
)


def verdict(*models: Model, sink: TaintKind = TaintKind.COMMAND) -> Status:
    module = build_hir(SourceManager().add_source("views.py", VIEW))
    registry = SecurityModelRegistry()
    registry.register(Source(SymbolId("python.builtins.input"), "stdin"), Sink(SymbolId("python.os.system"), sink), *models)
    manager = engine.build_manager(module, registry)
    run = next(s for s in module.body if isinstance(s, nodes.Function) and s.name == "run")
    (found,) = manager.get(RefutationAnalysis, run).all()
    return found.status


def test_a_declared_project_validator_refutes_the_flow_it_guards() -> None:
    assert verdict(Validator(SymbolId("python.views.allowed"))) is Status.REFUTED


def test_a_validator_proves_only_the_kinds_it_declares() -> None:
    # A redirect validator says nothing of what a shell makes of the value.
    allowed = SymbolId("python.views.allowed")

    assert verdict(Validator(allowed, TaintKind.REDIRECT)) is Status.HOTSPOT
    assert verdict(Validator(allowed, TaintKind.COMMAND)) is Status.REFUTED
    assert verdict(Validator(allowed, TaintKind.COMMAND), sink=TaintKind.COMMAND | TaintKind.SQL) is Status.HOTSPOT
    assert verdict(Validator(allowed, TaintKind.COMMAND | TaintKind.SQL), sink=TaintKind.COMMAND | TaintKind.SQL) is (
        Status.REFUTED
    )


def test_an_undeclared_project_function_leaves_a_hotspot() -> None:
    assert verdict() is Status.HOTSPOT
    assert verdict(Validator(SymbolId("python.other.allowed"))) is Status.HOTSPOT


class _AllowRedirect(ModelPlugin):
    name: ClassVar[str] = "allow-redirect"
    models: ClassVar[tuple[Model, ...]] = (Validator(SymbolId("python.hc.views._allow_redirect")),)


def test_a_plugin_declares_the_validator_of_a_project(tmp_path) -> None:  # type: ignore[no-untyped-def]
    source = (
        "from django.http import HttpRequest\n"
        "from django.shortcuts import redirect\n\n"
        "def _allow_redirect(url):\n"
        "    return url.startswith('/') and not url.startswith('//')\n\n"
        "def login(request: HttpRequest):\n"
        "    target = request.GET['next']\n"
        "    if target and _allow_redirect(target):\n"
        "        return redirect(target)\n"
        "    return redirect('/')\n"
    )
    (tmp_path / "hc").mkdir()
    (tmp_path / "hc" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "hc" / "views.py").write_text(source, encoding="utf-8")

    declared = engine.analyze_project(tmp_path, [engine.BUNDLED_PLUGINS], plugins=[_AllowRedirect()]).findings
    undeclared = engine.analyze_project(tmp_path, [engine.BUNDLED_PLUGINS]).findings

    assert [f.rule_id for f in declared if f.rule_id == "open-redirect"] == []
    assert [(f.rule_id, f.metadata["verdict"]) for f in undeclared if f.rule_id == "open-redirect"] == [
        ("open-redirect", "hotspot")
    ]
