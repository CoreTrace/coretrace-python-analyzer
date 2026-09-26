"""Server-side request forgery: attacker-controlled input reaching a SSRF sink.

How the URL is built, with ``+`` and f-strings, can prove part of its destination. Constant
text fixing ``scheme://host`` and ending the authority with ``/``, ``?`` or ``#`` before
any input keeps the input from choosing the host; the input still chooses the path, which
may reach a sensitive resource of that host, and a redirect may lead elsewhere, so the
flow is a hotspot. With the path fixed too, the input reaching the query or fragment
only, and redirects disabled in the call, the destination is fixed and the flow is
refuted. Anything unproven, a base of unknown value or a URL built in a helper function,
stays a vulnerability.
"""

from __future__ import annotations

import re
from typing import ClassVar

from coretrace_python.abstract.strings import ModuleStringsAnalysis, leading_text
from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Severity
from coretrace_python.findings.refutation import Status, Verdict
from coretrace_python.hir import nodes
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import PluginContext, TaintDetector
from coretrace_python.taint import TaintFlow, TaintKind

# ``scheme://`` and an authority ended by ``/``, ``?`` or ``#``. A backslash, which some
# URL parsers take for a slash, does not end it here.
_FIXED_HOST = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/?#\\]+[/?#]")
# The same with the path fixed too: what follows is query or fragment.
_FIXED_PATH = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/?#\\]+(?:/[^?#]*)?[?#]")
# A client honours the one of these keywords it knows and rejects the other with a
# ``TypeError``: either way, the call follows no redirect.
_NO_REDIRECTS = ("allow_redirects", "follow_redirects")


class SsrfPlugin(TaintDetector):
    name: ClassVar[str] = "ssrf"
    rule_id: ClassVar[str] = "ssrf"
    kind: ClassVar[TaintKind] = TaintKind.SSRF
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "Server-side request forgery"
    requires: ClassVar[frozenset[AnyAnalysis]] = TaintDetector.requires | {SSAAnalysis, ModuleStringsAnalysis}

    def judge(self, ctx: PluginContext, function: nodes.Function, flow: TaintFlow, verdict: Verdict) -> Verdict:
        if flow.through is not None:
            return verdict  # the URL is built in the callee
        ssa = ctx.get(SSAAnalysis, function)
        defs = {i.result: i for block in ssa.blocks for i in block.instructions if i.result is not None}
        text, _ = leading_text(flow.argument, defs, ctx.get(ModuleStringsAnalysis))
        host = _FIXED_HOST.match(text)
        if host is None:
            return verdict
        arguments = flow.sink_arguments
        no_redirects = arguments is not None and any(arguments.given(name) == (True, "False") for name in _NO_REDIRECTS)
        if _FIXED_PATH.match(text) is not None:
            if no_redirects:
                return Verdict(flow, Status.REFUTED, f"the destination is fixed by {text!r} and redirects are disabled")
            left = "a redirect may lead elsewhere"
        else:
            left = "the input chooses the path" + ("" if no_redirects else ", and a redirect may lead elsewhere")
        if verdict.status is not Status.VULNERABILITY:
            return verdict
        return Verdict(flow, Status.HOTSPOT, f"the host is fixed by {host.group(0)!r}, but {left}")
