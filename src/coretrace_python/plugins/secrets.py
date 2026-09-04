"""Secret detection base (architecture §25 plugins/secrets).

Secrets are string literals of the PyHIR. ``literals`` walks every string literal with
the name it is bound to (assignment target, keyword argument, dictionary key) and the
enclosing function; ``SecretDetector`` reports at most one finding per literal: a
provider pattern first (``hardcoded-secret``), then a credential-like name with a real
value (``hardcoded-credential``), then a high-entropy token on its own
(``high-entropy-string``). Messages and metadata carry a redacted preview, never the
secret. Only Python sources are scanned; configuration files are not.
"""

from __future__ import annotations

import json
import math
import re
import tomllib
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.hir import nodes
from coretrace_python.hir.visitors import Node, children
from coretrace_python.interprocedural import discover_files
from coretrace_python.plugins.api import Plugin, PluginContext
from coretrace_python.source import SourceId, SourceSpan, decode_text

Literal = tuple[str, str | None, SourceSpan, str | None]

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_TOKEN = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_PLACEHOLDER = re.compile(r"^(<.*>|\$\{.*\}|\{\{.*\}\}|%.*%|\.{3,}|(.)\2*)$")
_PLACEHOLDER_WORDS = frozenset(
    {"", "changeme", "change_me", "password", "passwd", "secret", "token", "example", "xxx", "todo", "none", "null"}
)
_NOT_CREDENTIAL_SUFFIXES = ("_name", "_field", "_file", "_path", "_url", "_id", "_env", "_var", "_header", "_param")


def shannon_entropy(text: str) -> float:
    """Bits of information per character of ``text``."""

    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(count / length * math.log2(count / length) for count in counts.values())


def literals(module: nodes.Module) -> Iterator[Literal]:
    """Every string literal of the module as ``(value, bound name, span, function)``."""

    for statement in module.body:
        yield from _walk(statement, None, None)


def _walk(node: Node, name: str | None, function: str | None) -> Iterator[Literal]:
    if isinstance(node, nodes.Constant):
        if isinstance(node.value, str):
            yield node.value, name, node.span, function
        return
    if isinstance(node, nodes.Function):
        for child in children(node):
            yield from _walk(child, None, node.name)
        return
    if isinstance(node, nodes.Class):
        for child in children(node):
            yield from _walk(child, None, None)
        return
    if isinstance(node, nodes.Assign):
        yield from _walk(node.value, _bound_name(node.target), function)
        return
    if isinstance(node, nodes.Keyword):
        yield from _walk(node.value, node.name, function)
        return
    if isinstance(node, nodes.Parameter):
        if node.default is not None:
            yield from _walk(node.default, node.name, function)
        return
    if isinstance(node, nodes.Call) and _is_environment_lookup(node):
        # ``os.getenv("APP_TOKEN", "fallback")``: the fallback is bound to the variable name.
        variable, fallback = node.arguments[0], node.arguments[1]
        assert isinstance(variable, nodes.Constant) and isinstance(variable.value, str)
        yield from _walk(variable, None, function)
        yield from _walk(fallback, variable.value, function)
        for keyword in node.keywords:
            yield from _walk(keyword, None, function)
        return
    if isinstance(node, nodes.Dict):
        for key, value in node.items:
            # A constant key names the value; it is not a value itself.
            if isinstance(key, nodes.Constant):
                bound = key.value if isinstance(key.value, str) else None
            else:
                bound = None
                if key is not None:
                    yield from _walk(key, None, function)
            yield from _walk(value, bound, function)
        return
    for child in children(node):
        yield from _walk(child, None, function)


def _is_environment_lookup(call: nodes.Call) -> bool:
    callee = call.callee
    return (
        isinstance(callee, nodes.Attribute)
        and callee.name in ("getenv", "get")
        and len(call.arguments) >= 2
        and isinstance(call.arguments[0], nodes.Constant)
        and isinstance(call.arguments[0].value, str)
    )


def _bound_name(target: nodes.Target) -> str | None:
    """The name an assignment binds: ``name``, ``obj.attr`` or ``mapping['key']``."""

    if isinstance(target, nodes.Name):
        return target.identifier
    if isinstance(target, nodes.Attribute):
        return target.name
    if isinstance(target, nodes.Subscript) and isinstance(target.key, nodes.Constant):
        return target.key.value if isinstance(target.key.value, str) else None
    return None


@dataclass(frozen=True)
class SecretPattern:
    """A provider-specific secret format."""

    provider: str
    regex: str

    def matches(self, text: str) -> bool:
        return re.search(self.regex, text) is not None


DEFAULT_PATTERNS: tuple[SecretPattern, ...] = (
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

DEFAULT_CREDENTIAL_NAMES: tuple[str, ...] = (
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

CONFIG_SUFFIXES = frozenset({".env", ".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".properties", ".conf"})
_PAIR = re.compile(r"^\s*(?:-\s+)?([A-Za-z_][\w.-]*)\s*[:=]\s*(.*?)\s*$")
_MAX_CONFIG_BYTES = 8_000_000


def config_literals(root: Path) -> Iterator[Literal]:
    """Every string value of the configuration files under ``root`` with the key it is
    bound to: ``.env``, YAML, TOML, JSON, INI and properties files, decoded by their
    byte order mark. Python files are left to ``literals``."""

    for path in discover_files(root):
        if not (path.suffix in CONFIG_SUFFIXES or path.name.startswith(".env")):
            continue
        try:
            data = path.read_bytes()
            if len(data) > _MAX_CONFIG_BYTES:
                continue
            text = decode_text(data)
        except (OSError, UnicodeDecodeError):
            continue
        source = SourceId(str(path))
        if path.suffix == ".json":
            yield from _structured(source, text, _load_json(text))
        elif path.suffix == ".toml":
            yield from _structured(source, text, _load_toml(text))
        else:
            yield from _pairs(source, text)


def _load_json(text: str) -> object:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _load_toml(text: str) -> object:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None


def _structured(source: SourceId, text: str, data: object) -> Iterator[Literal]:
    lines = text.splitlines()

    def line_of(key: str) -> int:
        for number, line in enumerate(lines, start=1):
            if re.match(rf'^\s*"?{re.escape(key)}"?\s*[:=]', line) or f'"{key}"' in line:
                return number
        return 1

    def walk(node: object, key: str | None) -> Iterator[Literal]:
        if isinstance(node, dict):
            for name, value in node.items():
                yield from walk(value, str(name))
        elif isinstance(node, list):
            for item in node:
                yield from walk(item, key)
        elif isinstance(node, str) and key is not None:
            yield node, key, SourceSpan(source, line_of(key), 1), None

    yield from walk(data, None)


def _pairs(source: SourceId, text: str) -> Iterator[Literal]:
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped[0] in "#;[":
            continue
        match = _PAIR.match(line)
        if match is None:
            continue
        key, value = match.group(1), match.group(2)
        if value.startswith("#"):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if value:
            yield value, key, SourceSpan(source, number, 1), None


def redacted(value: str) -> str:
    preview = value[:4] if len(value) > 8 else value[:1]
    return f"{preview}… ({len(value)} characters)"


def is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return len(lowered) < 4 or lowered in _PLACEHOLDER_WORDS or _PLACEHOLDER.match(lowered) is not None


class SecretDetector(Plugin):
    """Report hardcoded secrets among the module's string literals."""

    patterns: ClassVar[tuple[SecretPattern, ...]] = ()
    credential_names: ClassVar[tuple[str, ...]] = ()
    entropy_threshold: ClassVar[float] = 4.5
    hex_entropy_threshold: ClassVar[float] = 3.5
    minimum_length: ClassVar[int] = 32

    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        findings: list[Finding] = []
        for value, name, span, function in literals(ctx.module):
            finding = self.judge(value, name, span, function)
            if finding is not None:
                findings.append(finding)
        return findings

    def judge(self, value: str, name: str | None, span: SourceSpan, function: str | None) -> Finding | None:
        where = f"in {name}" if name is not None else "in a string literal"
        for pattern in self.patterns:
            if pattern.matches(value):
                return Finding(
                    "hardcoded-secret",
                    f"Hardcoded {pattern.provider} secret {where}: {redacted(value)}",
                    Severity.HIGH,
                    Confidence.HIGH,
                    span,
                    function,
                    {"provider": pattern.provider, "name": name or "", "length": str(len(value))},
                )
        if name is not None and self.is_credential_name(name) and not is_placeholder(value):
            return Finding(
                "hardcoded-credential",
                f"Hardcoded credential {where}: {redacted(value)}",
                Severity.HIGH,
                Confidence.MEDIUM,
                span,
                function,
                {"name": name, "length": str(len(value))},
            )
        entropy = self.entropy_of(value)
        if entropy is not None:
            return Finding(
                "high-entropy-string",
                f"High-entropy string {where}: {redacted(value)}",
                Severity.MEDIUM,
                Confidence.LOW,
                span,
                function,
                {"name": name or "", "length": str(len(value)), "entropy": f"{entropy:.2f}"},
            )
        return None

    def is_credential_name(self, name: str) -> bool:
        lowered = name.lower()
        if lowered.endswith(_NOT_CREDENTIAL_SUFFIXES):
            return False
        return any(word in lowered for word in self.credential_names)

    def entropy_of(self, value: str) -> float | None:
        """The entropy of ``value`` when it looks like an opaque token, else ``None``."""

        if len(value) < self.minimum_length or _TOKEN.match(value) is None:
            return None
        entropy = shannon_entropy(value)
        threshold = self.hex_entropy_threshold if _HEX.match(value) else self.entropy_threshold
        return entropy if entropy >= threshold else None
