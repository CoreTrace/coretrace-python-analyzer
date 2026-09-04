"""Plaintext credentials in database queries: a password-named parameter reaching a
database statement without passing through a hashing function, whether the statement
stores it or compares it, since comparing in clear implies storing in clear. A name is
a hint, so medium confidence."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.findings import Confidence, Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class PlaintextCredentialsPlugin(TaintDetector):
    name: ClassVar[str] = "plaintext-credentials"
    rule_id: ClassVar[str] = "plaintext-credential-storage"
    kind: ClassVar[TaintKind] = TaintKind.CREDENTIAL
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Plaintext credential in a database query"
