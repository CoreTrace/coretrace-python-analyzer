"""Disabled certificate verification: ``verify=False`` on an HTTP client call, or an
``ssl`` context built without verification, lets any peer impersonate the server."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Severity
from coretrace_python.interprocedural import CallGraphAnalysis
from coretrace_python.ir.model import Call, Constant, Instruction, Value
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import SymbolCallDetector
from coretrace_python.semantic.symbols import SymbolId

_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "request")
_CALLERS = ("requests", "requests.Session", "requests.api", "httpx", "httpx.Client", "httpx.AsyncClient")
HTTP_CALLS = frozenset(
    SymbolId(f"python.{caller}.{method}") for caller in _CALLERS for method in _METHODS
) | frozenset(SymbolId(f"python.{client}") for client in ("httpx.Client", "httpx.AsyncClient"))
UNVERIFIED = frozenset({SymbolId("python.ssl._create_unverified_context")})


class InsecureTlsPlugin(SymbolCallDetector):
    name: ClassVar[str] = "insecure-tls"
    rule_id: ClassVar[str] = "insecure-tls"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis, CallGraphAnalysis})
    symbols: ClassVar[frozenset[SymbolId]] = HTTP_CALLS | UNVERIFIED
    severity: ClassVar[Severity] = Severity.HIGH
    message_template: ClassVar[str] = "call to {symbol} disables certificate verification"

    def accepts(self, call: Call, symbol: SymbolId, defs: Mapping[Value, Instruction]) -> bool:
        if symbol in UNVERIFIED:
            return True
        for name, value in call.keywords:
            if name == "verify":
                defined = defs.get(value)
                return isinstance(defined, Constant) and defined.value is False
        return False
