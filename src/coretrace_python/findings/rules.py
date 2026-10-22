"""What each rule checks, for a report to explain its findings.

A title and a description per rule id, as a SARIF consumer shows them (``shortDescription``
and ``fullDescription``). The rules are those the usage guide documents; a rule a
third-party plugin reports has no description here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class RuleDescription:
    title: str
    description: str


RULES: Mapping[str, RuleDescription] = MappingProxyType(
    {
        # Taint flows
        "command-injection": RuleDescription(
            "Command injection",
            "Attacker-controlled data reaches a shell or process execution (os.system, "
            "subprocess, ...) where it can run or choose a command.",
        ),
        "code-injection": RuleDescription(
            "Code injection",
            "Attacker-controlled data chooses code that runs: the code eval or exec runs, the "
            "module an import loads, the script runpy runs, or the attribute getattr selects "
            "and the program calls.",
        ),
        "sql-injection": RuleDescription(
            "SQL injection",
            "Attacker-controlled data reaches a database statement (cursor.execute, SQLAlchemy "
            "text, Django raw, ...) rather than a query parameter.",
        ),
        "nosql-injection": RuleDescription(
            "NoSQL injection",
            "Attacker input that may hold a structure, such as a JSON body, reaches a NoSQL "
            'query, where an operator such as {"$ne": null} matches any value.',
        ),
        "path-traversal": RuleDescription(
            "Path traversal",
            "Attacker-controlled data reaches a file system path (open, send_file, os.remove, "
            "...).",
        ),
        "ssrf": RuleDescription(
            "Server-side request forgery",
            "Attacker-controlled data reaches the destination of an HTTP client request "
            "(Requests, httpx, urllib).",
        ),
        "xss": RuleDescription(
            "Cross-site scripting",
            "Attacker-controlled data reaches an HTTP response body built without escaping.",
        ),
        "insecure-deserialization": RuleDescription(
            "Insecure deserialization",
            "Attacker-controlled data reaches a deserializer that can build arbitrary objects "
            "or run code: pickle, marshal, dill, jsonpickle, shelve, or a YAML loader without "
            "a safe loader.",
        ),
        "open-redirect": RuleDescription(
            "Open redirect",
            "Attacker-controlled data chooses the target of an HTTP redirect, which can send "
            "the user to another site.",
        ),
        "plaintext-credential-storage": RuleDescription(
            "Plaintext credential storage",
            "A parameter named like a password is stored in a database without hashing.",
        ),
        "exploitable-vulnerability": RuleDescription(
            "Exploitable dependency vulnerability",
            "Attacker-controlled data reaches an API that an advisory of a vulnerable "
            "requirement affects.",
        ),
        # Dangerous API usage
        "dangerous-eval": RuleDescription(
            "Dynamic code execution",
            "A call to eval or exec, whatever name the file gives them.",
        ),
        "weak-crypto": RuleDescription(
            "Weak cryptographic algorithm",
            "A broken algorithm such as hashlib.md5 or hashlib.sha1.",
        ),
        "debug-enabled": RuleDescription(
            "Debug mode enabled",
            "A Flask application run with debug=True, which exposes an interactive debugger.",
        ),
        "missing-timeout": RuleDescription(
            "HTTP request without a timeout",
            "A Requests or httpx call without a timeout, which can wait forever.",
        ),
        "insecure-tls": RuleDescription(
            "TLS certificate verification disabled",
            "verify=False on a Requests or httpx call, or ssl._create_unverified_context(), "
            "which accept any certificate.",
        ),
        "unsafe-xml": RuleDescription(
            "Unsafe XML parser",
            "An XML parser of the standard library or of lxml, exposed to the entities a "
            "document declares; defusedxml is the safe replacement.",
        ),
        "unsafe-archive-extraction": RuleDescription(
            "Unsafe archive extraction",
            "A tarfile or zipfile extraction, or shutil.unpack_archive, without a member "
            "filter: a member can be written outside the destination.",
        ),
        "insecure-temp-file": RuleDescription(
            "Insecure temporary file",
            "tempfile.mktemp, which names a file without creating it, so that another process "
            "can create it first.",
        ),
        "weak-random": RuleDescription(
            "Weak random value for a credential",
            "A value of the random module used as a credential; random is not "
            "cryptographically secure.",
        ),
        # Secrets
        "hardcoded-secret": RuleDescription(
            "Hard-coded secret",
            "A secret in a provider-specific format (AWS, GitHub, Slack, Stripe, Google, a "
            "private key, a JWT, ...) written in a source or configuration file.",
        ),
        "hardcoded-credential": RuleDescription(
            "Hard-coded credential",
            "A credential-like name (password, token, api_key, ...) bound to a real value in a "
            "source or configuration file.",
        ),
        "high-entropy-string": RuleDescription(
            "High-entropy string",
            "An opaque high-entropy token that may be a secret.",
        ),
        # Dependencies
        "vulnerable-dependency": RuleDescription(
            "Vulnerable dependency",
            "A requirement allows a version that an advisory affects.",
        ),
        "reachable-vulnerability": RuleDescription(
            "Reachable dependency vulnerability",
            "The project calls an API that an advisory of a vulnerable requirement affects.",
        ),
        "denied-dependency": RuleDescription(
            "Denied dependency",
            "A requirement on a package the policy denies.",
        ),
        "unpinned-dependency": RuleDescription(
            "Unpinned dependency",
            "A requirement without an exact pin, when the policy requires pins.",
        ),
        # Analysis notes
        "unsupported-syntax": RuleDescription(
            "Unsupported syntax",
            "A function the analyzer could not analyze, because of syntax it does not support: "
            "its code is not checked.",
        ),
    }
)


def describe_rule(rule_id: str) -> RuleDescription | None:
    """The description of ``rule_id``; ``None`` for a rule this analyzer does not describe."""

    return RULES.get(rule_id)
