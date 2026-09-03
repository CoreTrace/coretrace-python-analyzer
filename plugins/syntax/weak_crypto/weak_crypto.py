"""Report uses of broken hash algorithms."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.findings import Severity
from coretrace_python.plugins import SymbolCallDetector
from coretrace_python.semantic.symbols import SymbolId


class WeakCryptoPlugin(SymbolCallDetector):
    name: ClassVar[str] = "weak-crypto"
    rule_id: ClassVar[str] = "weak-crypto"
    symbols: ClassVar[frozenset[SymbolId]] = frozenset(
        {SymbolId("python.hashlib.md5"), SymbolId("python.hashlib.sha1")}
    )
    severity: ClassVar[Severity] = Severity.MEDIUM
    message_template: ClassVar[str] = "call to {symbol} uses a broken hash algorithm"
