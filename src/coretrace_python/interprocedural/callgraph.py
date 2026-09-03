"""Intra-module call graph (architecture §20).

Every call site of every analysable function resolves, through the SSA form, to a
``KnownFunction`` defined at module level, an ``ExternalSymbol`` reached through imports
or builtins, or ``UnknownTarget`` (parameters, attributes, methods) until type inference
and framework models narrow it down.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext, AnyAnalysis
from coretrace_python.cfg import CFGError
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import LoweringError, analyzable_functions, qualified_name
from coretrace_python.ir.model import Call, FunctionIR, Global, Symbol, Value
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.semantic.scopes import BindingKind, ScopeAnalysis, ScopeTable
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceSpan


@dataclass(frozen=True)
class KnownFunction:
    name: str


@dataclass(frozen=True)
class ExternalSymbol:
    symbol: SymbolId


@dataclass(frozen=True)
class UnknownTarget:
    pass


Target = KnownFunction | ExternalSymbol | UnknownTarget


@dataclass(frozen=True)
class CallSite:
    caller: str
    location: SourceSpan
    target: Target
    arguments: int
    keywords: int


class CallGraph:
    def __init__(
        self,
        definitions: Mapping[str, nodes.Function],
        sites: Mapping[str, tuple[CallSite, ...]],
        unsupported: frozenset[str],
    ) -> None:
        self.definitions: Mapping[str, nodes.Function] = MappingProxyType(dict(definitions))
        self.functions = tuple(definitions)
        self.unsupported = unsupported
        self._sites = MappingProxyType(dict(sites))
        self._targets = {
            (site.caller, site.location): site.target for found in sites.values() for site in found
        }
        callers: dict[str, set[str]] = {name: set() for name in definitions}
        for found in sites.values():
            for site in found:
                if isinstance(site.target, KnownFunction):
                    callers[site.target.name].add(site.caller)
        self._callers = {name: frozenset(found) for name, found in callers.items()}

    def sites(self, caller: str) -> tuple[CallSite, ...]:
        return self._sites.get(caller, ())

    def target_at(self, caller: str, location: SourceSpan) -> Target:
        return self._targets.get((caller, location), UnknownTarget())

    def callees(self, caller: str) -> frozenset[str]:
        return frozenset(
            site.target.name for site in self.sites(caller) if isinstance(site.target, KnownFunction)
        )

    def callers(self, name: str) -> frozenset[str]:
        return self._callers.get(name, frozenset())


def resolve_targets(
    function: FunctionIR, scopes: ScopeTable, known: frozenset[str]
) -> dict[Value, Target]:
    """Map every callee value of ``function`` to its target."""

    module = scopes.module_scope
    targets: dict[Value, Target] = {}
    for block in function.blocks:
        for instruction in block.instructions:
            if isinstance(instruction, Symbol):
                targets[instruction.result] = ExternalSymbol(instruction.symbol_id)
            elif isinstance(instruction, Global):
                binding = module.bindings.get(instruction.name)
                if (
                    binding is not None
                    and binding.kind is BindingKind.FUNCTION
                    and instruction.name in known
                ):
                    targets[instruction.result] = KnownFunction(instruction.name)
    return targets


class CallGraphAnalysis(Analysis[CallGraph]):
    name: ClassVar[str] = "interprocedural.callgraph"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis, ScopeAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> CallGraph:
        scopes = ctx.get(ScopeAnalysis)
        definitions = {
            qualified_name(scopes, function): function
            for function in analyzable_functions(ctx.module)
        }
        known = frozenset(
            name for name, function in definitions.items() if function in ctx.module.body
        )
        sites: dict[str, tuple[CallSite, ...]] = {}
        unsupported: set[str] = set()
        for name, function in definitions.items():
            try:
                ssa = ctx.get(SSAAnalysis, function)
            except (LoweringError, CFGError):
                unsupported.add(name)
                sites[name] = ()
                continue
            targets = resolve_targets(ssa, scopes, known)
            found: list[CallSite] = []
            for block in ssa.blocks:
                for instruction in block.instructions:
                    if isinstance(instruction, Call):
                        found.append(
                            CallSite(
                                name,
                                instruction.location,
                                targets.get(instruction.callee, UnknownTarget()),
                                len(instruction.arguments),
                                len(instruction.keywords),
                            )
                        )
            sites[name] = tuple(found)
        return CallGraph(definitions, sites, frozenset(unsupported))
