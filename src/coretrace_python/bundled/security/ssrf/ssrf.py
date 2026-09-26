"""Server-side request forgery: attacker-controlled input reaching a SSRF sink.

The rule draws its verdict from what the URL's constant text proves (``taint.urls``).
A fixed host keeps the input from choosing it, but the input still chooses the path,
which may reach a sensitive resource of that host, and a redirect may lead elsewhere: a
hotspot. With the path fixed too, the input reaching the query or fragment only, and
redirects disabled in the call, the destination is fixed: refuted. Anything unproven,
a base of unknown value or a URL built in a helper function, stays a vulnerability.
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
from coretrace_python.taint.urls import flow_url, redirects_disabled


class SsrfPlugin(TaintDetector):
    name: ClassVar[str] = "ssrf"
    rule_id: ClassVar[str] = "ssrf"
    kind: ClassVar[TaintKind] = TaintKind.SSRF
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "Server-side request forgery"
    requires: ClassVar[frozenset[AnyAnalysis]] = TaintDetector.requires | {SSAAnalysis, ModuleStringsAnalysis}

    def judge(self, ctx: PluginContext, function: nodes.Function, flow: TaintFlow, verdict: Verdict) -> Verdict:
        ssa = ctx.get(SSAAnalysis, function)
        defs = {i.result: i for block in ssa.blocks for i in block.instructions if i.result is not None}
        url = flow_url(flow, defs, ctx.get(ModuleStringsAnalysis))
        if url.origin is None:
            return verdict
        no_redirects = redirects_disabled(flow.sink_arguments)
        if url.path_fixed:
            if no_redirects:
                return Verdict(flow, Status.REFUTED, f"the destination is fixed by {url.text!r} and redirects are disabled")
            left = "a redirect may lead elsewhere"
        else:
            left = "the input chooses the path" + ("" if no_redirects else ", and a redirect may lead elsewhere")
        if verdict.status is not Status.VULNERABILITY:
            return verdict
        return Verdict(flow, Status.HOTSPOT, f"the host is fixed by {url.origin!r}, but {left}")
