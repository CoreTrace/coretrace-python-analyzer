"""Open redirect: attacker-controlled input reaching a open redirect sink.

The rule draws its verdict from what the target's constant text proves (``taint.urls``),
as a browser resolves it. A reference on the current site (``/profile/``, ``?page=``,
``profile/``) keeps the browser on the site, where any further redirect is the project's
own code, analysed on its own: refuted. A fixed absolute host sends the browser there,
but the input chooses the path, where that host may redirect again: a hotspot. Anything
unproven, ``"/" + next`` included, stays a vulnerability.
"""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.abstract.strings import ModuleStringsAnalysis
from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Severity
from coretrace_python.findings.refutation import Status, Verdict
from coretrace_python.hir import nodes
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import PluginContext, TaintDetector
from coretrace_python.taint import TaintFlow, TaintKind
from coretrace_python.taint.urls import flow_url


class OpenRedirectPlugin(TaintDetector):
    name: ClassVar[str] = "open-redirect"
    rule_id: ClassVar[str] = "open-redirect"
    kind: ClassVar[TaintKind] = TaintKind.REDIRECT
    severity: ClassVar[Severity] = Severity.MEDIUM
    title: ClassVar[str] = "Open redirect"
    requires: ClassVar[frozenset[AnyAnalysis]] = TaintDetector.requires | {SSAAnalysis, ModuleStringsAnalysis}

    def judge(self, ctx: PluginContext, function: nodes.Function, flow: TaintFlow, verdict: Verdict) -> Verdict:
        ssa = ctx.get(SSAAnalysis, function)
        defs = {i.result: i for block in ssa.blocks for i in block.instructions if i.result is not None}
        target = flow_url(flow, defs, ctx.get(ModuleStringsAnalysis))
        if target.relative:
            return Verdict(flow, Status.REFUTED, f"the browser stays on the site: the target starts with {target.text!r}")
        if target.origin is not None and verdict.status is Status.VULNERABILITY:
            return Verdict(
                flow,
                Status.HOTSPOT,
                f"the browser goes to the host fixed by {target.origin!r}, but the input chooses the path, "
                "where that host may redirect again",
            )
        return verdict
