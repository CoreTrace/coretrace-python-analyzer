"""Secret detection base (architecture §25 plugins/secrets).

Secrets are string literals of the PyHIR. ``literals`` walks every string literal with
the name it is bound to (assignment target, keyword argument, dictionary key) and the
enclosing function; ``SecretDetector`` reports at most one finding per literal: a
provider pattern first (``hardcoded-secret``), then a credential-like name with a real
value (``hardcoded-credential``), then a high-entropy token on its own
(``high-entropy-string``). Messages and metadata carry a redacted preview, never the
secret. ``config_literals`` gives the string values of the project's configuration
files (``.env``, YAML, TOML, JSON, INI, properties) with the key each is bound to, and
the same detector judges them.
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
from coretrace_python.source import FileLocation, Location, SourceId, SourceSpan, decode_text
from coretrace_python.source.positions import JsonPositions, Pointer, TomlPositions, pointer_text

# A value, the name it is bound to, where it is, and its enclosing function. A value of
# a JSON or TOML file whose line cannot be established is at a file location.
Literal = tuple[str, str | None, Location, str | None]

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_TOKEN = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_PLACEHOLDER = re.compile(r"^(<.*>|\$\{.*\}|\{\{.*\}\}|%.*%|\.{3,}|(.)\2*)$")
_PLACEHOLDER_WORDS = frozenset(
    {"", "changeme", "change_me", "password", "passwd", "secret", "token", "example", "xxx", "todo", "none", "null"}
)
_NOT_CREDENTIAL_SUFFIXES = (
    "_name", "_field", "_file", "_path", "_url", "_id", "_env", "_var", "_header", "_param",
    # ``token_type = "bearer"``: the kind of a credential, not one.
    "_type", "_kind", "_scheme", "_format", "_algorithm", "_method", "_mode",
)
# MD5, SHA-1, SHA-256 and SHA-512 digests, as hex.
_DIGEST_LENGTHS = frozenset({32, 40, 64, 128})
_DIGEST_WORDS = ("hash", "digest", "sha", "md5", "checksum", "commit", "etag", "fingerprint", "revision", "version")
# Subresource integrity, as in lock files: ``sha512-<base64>``.
_INTEGRITY = re.compile(r"^(md5|sha1|sha256|sha384|sha512)-[A-Za-z0-9+/=]+$", re.IGNORECASE)
_ALPHABET_WORDS = ("alphabet", "charset", "characters", "letters", "digits")
# A password hash names its algorithm, then its parameters, salt and digest, each in a
# hash alphabet: modular crypt and PHC strings (``$6$salt$digest``, ``$argon2id$v=19$...``;
# bcrypt has a fixed shape), Werkzeug's ``method:parameters$salt$hex digest`` and
# Django's ``algorithm$...$digest``. An algorithm identifier alone is an incomplete hash.
_HASH_FIELD = r"[A-Za-z0-9./+=,-]"
_CRYPT_ALGORITHMS = r"1|5|6|7|y|apr1|argon2(?:i|d|id)|pbkdf2(?:-sha(?:1|256|512))?|scrypt"
_PASSWORD_HASHES = tuple(
    re.compile(regex)
    for regex in (
        r"^\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}$",
        rf"^\$(?:{_CRYPT_ALGORITHMS}|2[abxy])\$$",
        rf"^\$(?:{_CRYPT_ALGORITHMS})(?:\${_HASH_FIELD}+){{2,}}$",
        r"^(?:scrypt|pbkdf2):[a-z0-9:]+\$[^$\s]+\$[0-9a-f]+$",
        rf"^(?:pbkdf2_sha(?:1|256)|argon2|bcrypt(?:_sha256)?|scrypt|md5|sha1)(?:\${_HASH_FIELD}*){{2,}}$",
    )
)


def is_password_hash(value: str) -> bool:
    """A password hash of a known format, which an application stores instead of the
    password and which does not reveal it: the algorithm identifier followed by fields
    of that format's shape, or the identifier alone. An identifier followed by anything
    else (``$2y$Summer2024!``) is a plaintext password."""

    return any(pattern.match(value) is not None for pattern in _PASSWORD_HASHES)


def looks_like_digest(value: str, name: str | None) -> bool:
    """A hex value of digest length, a hex value whose name names a hash, or a
    subresource-integrity hash: a commit id, a checksum, a content hash, never a secret
    unless a credential name says so."""

    if _INTEGRITY.match(value) is not None or (name is not None and name.lower() == "integrity"):
        return True
    if _HEX.match(value) is None:
        return False
    if len(value) in _DIGEST_LENGTHS:
        return True
    return name is not None and any(word in name.lower() for word in _DIGEST_WORDS)


_TEST_DIRECTORIES = frozenset({"test", "tests", "testing", "fixtures", "__tests__"})
_TEST_FILE = re.compile(r"^(test_.*|.*_test|conftest)\.py$")
_EXAMPLE_SUFFIXES = (".example", ".sample", ".dist", ".tpl")


def credential_context(path: str) -> str | None:
    """``"test"`` for test code and fixtures, ``"example"`` for template configuration
    files (``.env.example``), ``None`` for anything else."""

    parts = Path(path).parts
    if any(part in _TEST_DIRECTORIES for part in parts[:-1]) or _TEST_FILE.match(parts[-1]):
        return "test"
    if parts[-1].endswith(_EXAMPLE_SUFFIXES):
        return "example"
    return None


def is_alphabet(value: str, name: str | None) -> bool:
    """A constant that spells out a character set is high-entropy by construction: its
    name says so, or every character in it is distinct, which no random token is."""

    if name is not None and any(word in name.lower() for word in _ALPHABET_WORDS):
        return True
    return len(value) >= 16 and len(set(value)) == len(value)


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
    """A provider-specific secret format. When the regex names a ``secret`` group, that
    group is the secret itself, and a match whose secret is a placeholder is not one;
    punctuation that ends a sentence around it (``(see ?token=...)``) is not part of it."""

    provider: str
    regex: str

    def matches(self, text: str) -> bool:
        for match in re.finditer(self.regex, text):
            secret = match.groupdict().get("secret")
            if secret is None or not is_placeholder(secret.rstrip(".,;:!?)")):
                return True
        return False


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
    # A password in the user information, up to the last ``@`` before the host, since a
    # password may hold one. An IP address or ``localhost`` and a port before the ``@``
    # are an address, as in proxy specifications (``udp://127.0.0.1:1234@0.0.0.0:0``);
    # a dotted name is not, since user names such as ``john.doe`` have dots.
    SecretPattern(
        "url",
        r"://(?!(?:\d{1,3}(?:\.\d{1,3}){3}|localhost):\d+@)"
        r"[^/\s:@'\"]+:(?P<secret>[^/\s'\"]+)@",
    ),
    # A secret in a query parameter, up to a character no URL holds unescaped (RFC 3986):
    # prose around it, such as Markdown quotes, is not part of it.
    SecretPattern(
        "url",
        r"[?&](?:password|passwd|pwd|token|api_key|apikey|secret|access_key)="
        r"(?P<secret>[^&\s'\"`<>{}|\\^]{3,})",
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
# In npm lock files, the keys of these maps are package or command names, and their
# values version ranges or paths: ``"js-tokens": "^4.0.0"`` binds no value to the name
# ``js-tokens``, nor ``"secretlint": "bin/secretlint.js"`` to ``secretlint``.
_NPM_LOCK_FILES = frozenset({"package-lock.json", "npm-shrinkwrap.json"})
_NPM_NAME_MAPS = frozenset(
    {"dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "requires", "bin"}
)


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
            maps = _NPM_NAME_MAPS if path.name in _NPM_LOCK_FILES else frozenset()
            yield from _structured(source, _load_json(text), JsonPositions(text), maps)
        elif path.suffix == ".toml":
            yield from _structured(source, _load_toml(text), TomlPositions(text))
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


def _structured(
    source: SourceId,
    data: object,
    positions: JsonPositions | TomlPositions,
    name_maps: frozenset[str] = frozenset(),
) -> Iterator[Literal]:
    """Every string value of ``data`` with its key, where ``positions`` places it from
    its structural path, except that a value directly under one of ``name_maps`` is
    bound to no name: its key names a package or a command."""

    def walk(node: object, path: Pointer, key: str | None, named: bool = True) -> Iterator[Literal]:
        if isinstance(node, dict):
            for name, value in node.items():
                yield from walk(value, (*path, str(name)), str(name), key not in name_maps)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                yield from walk(item, (*path, index), key, named)
        elif isinstance(node, str) and key is not None:
            place = positions.locate(path, node)
            location: Location = (
                SourceSpan(source, *place) if place is not None else FileLocation(source, pointer_text(path))
            )
            yield node, key if named else None, location, None

    yield from walk(data, (), None)


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

    def judge(self, value: str, name: str | None, span: Location, function: str | None) -> Finding | None:
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
        if (
            name is not None
            and self.is_credential_name(name)
            and not is_placeholder(value)
            and not is_password_hash(value)
        ):
            # A password in a test fixture or a template file is rarely a leak; a name
            # is a hint, so the finding stays, at low confidence.
            context = credential_context(str(span.source_id))
            metadata = {"name": name, "length": str(len(value))}
            if context is not None:
                metadata["context"] = context
            return Finding(
                "hardcoded-credential",
                f"Hardcoded credential {where}: {redacted(value)}",
                Severity.HIGH,
                Confidence.LOW if context is not None else Confidence.MEDIUM,
                span,
                function,
                metadata,
            )
        entropy = self.entropy_of(value)
        if entropy is not None and not looks_like_digest(value, name) and not is_alphabet(value, name):
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
