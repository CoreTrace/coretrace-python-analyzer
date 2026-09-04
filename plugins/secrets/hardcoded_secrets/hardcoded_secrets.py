"""Hardcoded secrets: provider formats, credential-like names, high-entropy tokens."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins.secrets import SecretDetector, SecretPattern


class HardcodedSecrets(SecretDetector):
    name: ClassVar[str] = "hardcoded-secrets"
    patterns: ClassVar[tuple[SecretPattern, ...]] = (
        SecretPattern("aws", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        SecretPattern("github", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        SecretPattern("github", r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b"),
        SecretPattern("slack", r"\bxox[abpr]-[0-9]{10,}-[0-9A-Za-z-]{10,}"),
        SecretPattern("stripe", r"\b[sr]k_(live|test)_[0-9A-Za-z]{24,}\b"),
        SecretPattern("google", r"\bAIza[0-9A-Za-z_-]{35}\b"),
        SecretPattern("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        SecretPattern("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        SecretPattern("sendgrid", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
        SecretPattern("twilio", r"\bSK[0-9a-fA-F]{32}\b"),
        SecretPattern(
            "url",
            r"://[^/\s:@'\"]+:[^/\s@'\"]+@"
            r"|[?&](?:password|passwd|pwd|token|api_key|apikey|secret|access_key)=[^&\s'\"]{3,}",
        ),
    )
    credential_names: ClassVar[tuple[str, ...]] = (
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "api-key",
        "private_key",
        "access_key",
        "credential",
    )
