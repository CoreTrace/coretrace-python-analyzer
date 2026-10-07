"""Acceptance tests for issue #228: a secret built from several string literals.

A string expression whose parts are all constant (``+`` of strings, ``sep.join`` of a
list or tuple of strings with a constant separator, an f-string whose parts are all
constant) is one value, folded once at the outermost expression. It yields one finding,
the strongest of the whole value and of its pieces, at the span of the whole
expression, so the baseline digests every line of it; when the whole value is no
secret, its pieces are judged on their own, as before. An expression with a part that
is not constant is not folded as a whole; its literals are judged as before.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.source import SourceManager

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"
SECRET_RULES = ("hardcoded-secret", "hardcoded-credential", "high-entropy-string")
KEY = (
    'KEY = ("-----BEGIN RSA PRIVATE KEY-----\\n" +\n'
    '       "ZZZZowIBAAKCAQ\\n" +\n'
    '       "-----END RSA PRIVATE KEY-----")\n'
)


def secrets(text: str) -> list[tuple[str, int, int | None]]:
    findings = engine.check(SourceManager().add_source("app/keys.py", text), [PLUGINS])
    return sorted(
        (f.rule_id, f.span.start_line, f.span.end_line)
        for f in findings
        if f.rule_id in SECRET_RULES
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (KEY, [("hardcoded-secret", 1, 3)]),
        ('PASSWORD = "Zx81kQpL" + "w0RtY7vB" + "n3MsD9cF"\n', [("hardcoded-credential", 1, 1)]),
        ('TOKEN = "ghp_" + "a1B2a1B2a1B2a1B2a1B2a1B2a1B2a1B2a1B2"\n', [("hardcoded-secret", 1, 1)]),
        (
            (
                'KEY = "\\n".join([\n'
                '    "-----BEGIN RSA PRIVATE KEY-----",\n'
                '    "ZZZZowIBAAKCAQ",\n'
                '    "-----END RSA PRIVATE KEY-----",\n'
                "])\n"
            ),
            [("hardcoded-secret", 1, 5)],
        ),
        ('TOKEN = f"ghp_" "a1B2a1B2a1B2a1B2a1B2a1B2a1B2a1B2a1B2"\n', [("hardcoded-secret", 1, 1)]),
    ],
)
def test_a_secret_built_from_constant_pieces_is_judged_whole(
    text: str, expected: list[tuple[str, int, int | None]]
) -> None:
    assert secrets(text) == expected


def test_an_expression_with_a_part_that_is_not_constant_is_not_folded() -> None:
    text = (
        "import os\n\n"
        'TOKEN = "ghp_a1B2a1B2a1B2a1B2a1B2a1B2a1B2a1B2a1B2" + os.environ["SUFFIX"]\n'
        'PREFIX = "ghp_" + os.environ["REST"]\n'
    )

    assert secrets(text) == [("hardcoded-secret", 3, 3)]


def test_a_changed_body_of_a_folded_secret_is_new(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "keys.py").write_text(KEY, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    baseline = tmp_path / "baseline.json"
    assert main(["--check", "proj", "--baseline", str(baseline)]) == 0
    (root / "keys.py").write_text(KEY.replace("ZZZZ", "AAAA"), encoding="utf-8")
    capsys.readouterr()

    assert main(["--check", "proj", "--baseline", str(baseline)]) == 1
    assert capsys.readouterr().out.startswith("keys.py:1:8: high hardcoded-secret")


def test_a_piece_is_still_judged_when_the_whole_value_is_no_secret() -> None:
    """``"Token: " + token`` is no opaque token as a whole; its token piece still is."""

    text = 'X = "Token: " + "Zx81kQpLw0RtY7vBn3MsD9cF2hJ6gK4aQ"\n'

    assert secrets(text) == [("high-entropy-string", 1, 1)]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # The pieces touch, so the whole matches no provider pattern; a piece does.
        (
            'CREDS = "AKIAIOSFODNN7EXAMPLE" + "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n',
            [("hardcoded-secret", 1, 1)],
        ),
        (
            'api_token = "".join(["v1", "ghp_7Hq2Lm9XvB4nR8sT1kW6yZ3cF5gJ0dPaQeUi"])\n',
            [("hardcoded-secret", 1, 1)],
        ),
    ],
)
def test_the_strongest_finding_of_the_whole_or_a_piece_is_reported_at_the_whole(
    text: str, expected: list[tuple[str, int, int | None]]
) -> None:
    assert secrets(text) == expected


def test_a_part_of_a_chain_is_no_value_of_its_own() -> None:
    """``a + b + c`` folds once: ``a + b`` never exists, and is not judged."""

    text = 'commit_sha = "9f8e7d6c5b4a39281706" + "f5e4d3c2b1a09f8e7d6c5b" + "4a392817"\n'

    assert secrets(text) == []
