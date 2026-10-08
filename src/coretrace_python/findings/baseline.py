"""The baseline: findings accepted at a point in time, so only new ones fail a check.

A finding is recognised by its file relative to the root, its rule, its function and a
digest of the text of every line its span covers, never by its line number: code
inserted above it does not make it new, a change to its text does, on any of its lines,
as the body of a secret written over several lines (#223). A finding with a file
location, whose line is not established, is recognised by the JSON pointer of its value
and the value instead. An entry holds digests of them only, never the text, the value or
the pointer, whose keys may be secrets too, so the file, which is meant to be committed,
holds no accepted secret (#224). Entries are counted, so two identical findings on
identical lines need two entries.

Baselines are written in schema 3. Schema 1 and 2 files are still read, and never
rewritten; their entries hold the text of a finding's first line, which identifies a
finding on a single line exactly as it did, and no finding over several lines, whose
other lines it does not hold: such a finding is new. Schema 1 also recorded a finding
in a JSON, TOML or lock file with the text of its key's first line, its own only when
the key was not repeated: such an entry still identifies that finding, and no other.
Reading an old baseline, the check warns, with ``transition_notice``, that it may hold
secrets in plain text and is to be reviewed and recorded again.

A schema 3 digest lets anyone test candidate values offline. With a key (#225), from a
key file given explicitly, kept out of the analysed directory, or else from
``CORETRACE_BASELINE_KEY``, the baseline is recorded in schema 4: every digest is an
HMAC-SHA-256 under the key, and a check value tells the key apart without revealing it.
A schema 4 baseline needs its key: without it, or with another, it cannot be read; and
with a key, only a schema 4 baseline is read, so that an unkeyed one cannot stand in for
it. No baseline is ever rewritten on its own: moving to schema 4, or to another key, is
an explicit record, written only once the check succeeded, the previous file kept until
then. The key never leaves this module.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

from coretrace_python.findings.model import Finding
from coretrace_python.source import SourceSpan, decode_text, lines_of
from coretrace_python.source.positions import text_digest

BASELINE_SCHEMA = 3
KEYED_SCHEMA = 4
KEY_ENVIRONMENT = "CORETRACE_BASELINE_KEY"
_MINIMUM_KEY = 16
# Schemas whose entries hold the text of a finding's first line.
_LEGACY_SCHEMAS = (1, 2)

# File, rule, function, digest of the text of the span's lines (of the value, for a
# file location), digest of the pointer (empty for a span). In schemas 1 and 2, the text
# of the span's first line and the pointer itself.
Fingerprint = tuple[str, str, str, str, str]


class BaselineError(Exception):
    """The baseline file cannot be read, or its key cannot be used."""


class BaselineKey:
    """The secret key of a schema 4 baseline, which nothing shows."""

    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        self._secret = secret

    def __repr__(self) -> str:
        return "BaselineKey(<hidden>)"

    def digest(self, text: str) -> str:
        mac = hmac.new(self._secret, text.encode("utf-8", "surrogatepass"), hashlib.sha256)
        return "hmac-sha256:" + mac.hexdigest()[:32]

    @property
    def check(self) -> str:
        """A value that tells this key apart from another, without revealing it."""

        return self.digest("coretrace baseline key check")


def baseline_key(
    key_file: Path | None, environ: Mapping[str, str], root: Path, baseline: Path | None = None
) -> BaselineKey | None:
    """The key of the baseline: read from ``key_file`` when one is given, which must lie
    outside ``root`` and be another file than ``baseline``, or else from
    ``CORETRACE_BASELINE_KEY``; None when neither is. Trailing line breaks are not part
    of the key, from either source."""

    if key_file is not None:
        if _within(key_file, root):
            raise BaselineError(
                f"{key_file}: the baseline key file is inside the analysed directory; "
                "keep it out of the repository"
            )
        if baseline is not None and _same(key_file, baseline):
            raise BaselineError(f"{key_file}: the baseline key file is the baseline itself")
        try:
            secret = key_file.read_bytes()
        except OSError as error:
            raise BaselineError(f"{key_file}: cannot read the baseline key: {error.strerror}") from error
        source = str(key_file)
    elif KEY_ENVIRONMENT in environ:
        secret = environ[KEY_ENVIRONMENT].encode("utf-8", "surrogatepass")
        if not secret:
            raise BaselineError(f"{KEY_ENVIRONMENT} is set but empty")
        source = KEY_ENVIRONMENT
    else:
        return None
    secret = secret.rstrip(b"\r\n")
    if len(secret) < _MINIMUM_KEY:
        raise BaselineError(f"{source}: the baseline key is shorter than {_MINIMUM_KEY} bytes")
    return BaselineKey(secret)


def _same(path: Path, other: Path) -> bool:
    try:
        return path.samefile(other)
    except OSError:
        return False


def _within(path: Path, root: Path) -> bool:
    """Whether ``path`` lies in the directory ``root``, compared as files, not as
    spellings: letter case, symbolic links and firmlinks do not hide it."""

    resolved = path.resolve()
    return any(_same(candidate, root) for candidate in (resolved, *resolved.parents))


def ensure_recordable(path: Path, key: BaselineKey | None) -> None:
    """Refuse to record over a keyed baseline without a key: that would silently turn its
    digests back into ones anyone can test offline. Going back to an unkeyed baseline
    takes deleting it explicitly."""

    if key is not None or not path.is_file():
        return
    try:
        schema = json.loads(path.read_text(encoding="utf-8")).get("schema")
    except (OSError, ValueError, AttributeError):
        return
    if schema == KEYED_SCHEMA:
        raise BaselineError(
            f"{path}: recorded with a baseline key (schema 4); give it with --baseline-key-file or "
            f"{KEY_ENVIRONMENT} to record it again, or delete the file to record an unkeyed baseline"
        )


def fingerprint(finding: Finding, root: Path, key: BaselineKey | None = None) -> Fingerprint:
    """The fingerprint of ``finding`` in schema 3, or in schema 4 under ``key``."""

    path, head = _head(finding, root)
    span = finding.span
    if isinstance(span, SourceSpan):
        text = _span_text(path, span)
        return (*head, text_digest(text) if key is None else key.digest(text), "")
    # A key above the value may itself be a secret.
    if key is None:
        return (*head, span.digest, text_digest(span.pointer))
    return (*head, key.digest(span.digest), key.digest(span.pointer))


def legacy_fingerprint(finding: Finding, root: Path) -> Fingerprint | None:
    """The fingerprint of ``finding`` as schemas 1 and 2 recorded it, or None for a
    finding over several lines, which an entry of those schemas cannot identify."""

    path, head = _head(finding, root)
    span = finding.span
    if not isinstance(span, SourceSpan):
        return (*head, span.digest, span.pointer)
    if span.end_line not in (None, span.start_line):
        return None
    return (*head, _span_text(path, span), "")


def _head(finding: Finding, root: Path) -> tuple[Path, tuple[str, str, str]]:
    path = Path(str(finding.span.source_id))
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.as_posix()
    return path, (relative, finding.rule_id, finding.function or "")


def _span_text(path: Path, span: SourceSpan) -> str:
    """The text of the lines ``span`` covers, each stripped, lines counted as every line
    number of the engine counts them (``lines_of``); the line number when the file
    cannot be read or does not reach it."""

    try:
        lines = lines_of(decode_text(path.read_bytes()))
    except (OSError, UnicodeDecodeError):
        return str(span.start_line)
    if span.start_line > len(lines):
        return str(span.start_line)
    covered = lines[span.start_line - 1 : span.end_line or span.start_line]
    return "\n".join(line.strip() for line in covered)


@dataclass(frozen=True)
class Baseline:
    entries: Counter[Fingerprint] = field(default_factory=Counter)
    # The schema of the file read; its entries are compared by that schema's fingerprint.
    schema: int = BASELINE_SCHEMA
    # The key given to the check, whatever the schema.
    key: BaselineKey | None = field(default=None, repr=False, compare=False)

    @classmethod
    def of(cls, findings: Iterable[Finding], root: Path, key: BaselineKey | None = None) -> Baseline:
        entries = Counter(fingerprint(finding, root, key) for finding in findings)
        return cls(entries, BASELINE_SCHEMA if key is None else KEYED_SCHEMA, key)

    @classmethod
    def load(cls, path: Path, key: BaselineKey | None = None) -> Baseline:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            schema = document.get("schema")
            if schema not in (*_LEGACY_SCHEMAS, BASELINE_SCHEMA, KEYED_SCHEMA):
                raise BaselineError(f"{path}: unsupported baseline schema {schema!r}")
            if key is not None and schema != KEYED_SCHEMA:
                # Else whoever can edit the file could swap the keyed baseline for an
                # unkeyed one holding the digest of a new secret.
                raise BaselineError(
                    f"{path}: an unkeyed baseline (schema {schema}) while a baseline key is given; "
                    "review its findings, then record it in schema 4 with --record-baseline"
                )
            if schema == KEYED_SCHEMA:
                if key is None:
                    raise BaselineError(
                        f"{path}: recorded with a baseline key (schema 4); give it with "
                        f"--baseline-key-file or {KEY_ENVIRONMENT}"
                    )
                if not hmac.compare_digest(str(document["key_check"]), key.check):
                    raise BaselineError(
                        f"{path}: recorded with another baseline key; to rotate the key, review "
                        "the findings, then record the baseline again with --record-baseline"
                    )
            entries = Counter(
                {
                    (
                        str(e["path"]),
                        str(e["rule"]),
                        str(e["function"]),
                        str(e.get("line", "") if schema in _LEGACY_SCHEMAS else e["digest"]),
                        str(e.get("pointer", "")),
                    ): int(e["count"])
                    for e in document["findings"]
                }
            )
        except BaselineError:
            raise
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            raise BaselineError(f"{path}: {error}") from error
        return cls(entries, schema, key)

    def save(self, path: Path) -> None:
        """Write the baseline to ``path`` at once: the file there, if any, is replaced only
        when the new one is complete."""

        document: dict[str, object] = {"schema": self.schema}
        if self.schema == KEYED_SCHEMA:
            assert self.key is not None
            document["key_check"] = self.key.check
        document["findings"] = [
            {"path": p, "rule": r, "function": f, "digest": digest, "pointer": pointer, "count": count}
            for (p, r, f, digest, pointer), count in sorted(self.entries.items())
        ]
        # Through a symbolic link, to its target; with the mode of the file it replaces, or
        # the one a new file gets.
        target = Path(os.path.realpath(path))
        try:
            mode = stat.S_IMODE(target.stat().st_mode)
        except FileNotFoundError:
            umask = os.umask(0)
            os.umask(umask)
            mode = 0o666 & ~umask
        descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(document, indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def partition(
        self, findings: Iterable[Finding], root: Path
    ) -> tuple[tuple[Finding, ...], tuple[Finding, ...]]:
        """The findings not in the baseline, and those it accounts for."""

        key_of: Callable[[Finding, Path], Fingerprint | None] = (
            legacy_fingerprint
            if self.schema in _LEGACY_SCHEMAS
            else partial(fingerprint, key=self.key if self.schema == KEYED_SCHEMA else None)
        )
        remaining = Counter(self.entries)
        new: list[Finding] = []
        baselined: list[Finding] = []
        for finding in findings:
            fingerprinted = key_of(finding, root)
            if fingerprinted is not None and remaining[fingerprinted] > 0:
                remaining[fingerprinted] -= 1
                baselined.append(finding)
            else:
                new.append(finding)
        return tuple(new), tuple(baselined)

    def transition_notice(self) -> str | None:
        """What to tell when the baseline was read from schema 1 or 2, whose entries hold
        the text of lines and identify only findings on a single line: it is to be
        reviewed and recorded again; None otherwise."""

        if self.schema not in _LEGACY_SCHEMAS:
            return None
        return (
            f"schema {self.schema} baseline: this baseline may contain secrets in plain text. Its "
            "entries identify only findings on a single line, so a finding over several lines, or "
            "in a JSON, TOML or lock file, may be reported new only because no old entry can "
            "identify it with certainty. Review the baseline and the new findings, then migrate it "
            f"explicitly to schema {BASELINE_SCHEMA} with --record-baseline, which records digests "
            "only, or to schema 4 with a baseline key"
        )
