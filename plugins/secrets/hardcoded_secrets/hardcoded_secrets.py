"""Hardcoded secrets in Python literals: provider formats, credential-like names,
high-entropy tokens."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins.secrets import (
    DEFAULT_CREDENTIAL_NAMES,
    DEFAULT_PATTERNS,
    SecretDetector,
    SecretPattern,
)


class HardcodedSecrets(SecretDetector):
    name: ClassVar[str] = "hardcoded-secrets"
    patterns: ClassVar[tuple[SecretPattern, ...]] = DEFAULT_PATTERNS
    credential_names: ClassVar[tuple[str, ...]] = DEFAULT_CREDENTIAL_NAMES
