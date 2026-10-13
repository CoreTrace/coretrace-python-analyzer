"""Code injection: attacker-controlled input reaching a CODE sink, such as the code
``eval`` or ``exec`` runs, the module ``importlib.import_module``, ``__import__`` or
``runpy.run_module`` imports, or the file ``runpy.run_path`` runs. ``dangerous-eval``
reports every ``eval`` or ``exec``; this rule reports the calls attacker input reaches.

An import runs the top-level code of a module the input chooses among those that can be
found, and a script path runs the file the input chooses: execution is possible, and
how far it goes depends on what the input can reach. Their findings are titled for
that. A constant package prefix (``"app.plugins." + name``) confines an import to the
modules of that package: a hotspot."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.abstract.strings import ModuleStringsAnalysis, leading_text
from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Severity
from coretrace_python.findings.refutation import Status, Verdict
from coretrace_python.hir import nodes
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import Assessment, PluginContext, TaintDetector
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import TaintFlow, TaintKind

_IMPORTS = frozenset(
    SymbolId(f"python.{name}")
    for name in ("importlib.import_module", "builtins.__import__", "importlib.__import__", "runpy.run_module")
)
_RUN_PATH = SymbolId("python.runpy.run_path")


class CodeInjectionPlugin(TaintDetector):
    name: ClassVar[str] = "code-injection"
    rule_id: ClassVar[str] = "code-injection"
    kind: ClassVar[TaintKind] = TaintKind.CODE
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "Code injection"
    requires: ClassVar[frozenset[AnyAnalysis]] = TaintDetector.requires | {SSAAnalysis, ModuleStringsAnalysis}

    def assess(
        self, ctx: PluginContext, function: nodes.Function, flow: TaintFlow, verdict: Verdict
    ) -> Assessment:
        symbol = flow.sink.symbol
        if symbol == _RUN_PATH:
            return Assessment(verdict, self.severity, "Untrusted script execution")
        if symbol not in _IMPORTS:
            return Assessment(verdict, self.severity)
        if verdict.status is Status.VULNERABILITY and flow.through is None:
            ssa = ctx.get(SSAAnalysis, function)
            defs = {i.result: i for block in ssa.blocks for i in block.instructions if i.result is not None}
            prefix, whole = leading_text(flow.argument, defs, ctx.get(ModuleStringsAnalysis))
            package = prefix.rpartition(".")[0]
            if not whole and package and not prefix.startswith("."):
                verdict = Verdict(
                    flow, Status.HOTSPOT, f"the package is fixed by {prefix!r}, but the input chooses a module in it"
                )
        return Assessment(verdict, self.severity, "Untrusted module import")
