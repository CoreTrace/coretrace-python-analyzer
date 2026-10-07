"""Acceptance tests for #223 in configuration files: a value written over several lines.

A ``.env``, YAML, INI or properties value may continue past the line of its key: a quote
left open (``.env``, YAML), lines indented under the key (YAML, INI), a trailing
backslash (properties). Its span covers every line it continues on, so the baseline,
which digests the text of those lines, tells a changed body apart; the next key, at the
key's indentation or less, is not part of it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python.cli import main

BODY = "MIIEowIBAAKCAQEA9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i1h0g9f8e7d6"
BEGIN, END = "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return root


def changed_is_new(root: Path, name: str, before: str, after: str) -> bool:
    (root / name).write_text(before, encoding="utf-8")
    baseline = root.parent / "baseline.json"
    assert main(["--check", "proj", "--baseline", str(baseline)]) == 0
    (root / name).write_text(after, encoding="utf-8")
    return main(["--check", "proj", "--baseline", str(baseline)]) == 1


@pytest.mark.parametrize(
    ("name", "text"),
    [
        (".env", f'PRIVATE_KEY="{BEGIN}\n{BODY}\n{END}"\nOTHER=1\n'),
        ("config.yaml", f'private_key: "{BEGIN}\n  {BODY}\n  {END}"\nother: 1\n'),
        ("config.yaml", f"private_key: {BEGIN}\n  {BODY}\n  {END}\nother: 1\n"),
        ("app.ini", f"[db]\npassword = Zx81kQpLw0RtY7vB\n    {BODY}\nuser = app\n"),
        ("app.properties", f"db.password=Zx81kQpLw0RtY7vB\\\n    {BODY}\ndb.user=app\n"),
    ],
)
def test_a_changed_body_of_a_value_over_several_lines_is_new(
    root: Path, name: str, text: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert changed_is_new(root, name, text, text.replace(BODY, BODY[::-1]))


@pytest.mark.parametrize(
    ("name", "text", "after"),
    [
        (".env", f'PRIVATE_KEY="{BEGIN}"\nOTHER=1\n', "OTHER=2"),
        ("config.yaml", "db:\n  password: Zx81kQpLw0RtY7vB\n  user: app\n", "  user: web"),
        ("app.ini", "[db]\npassword = Zx81kQpLw0RtY7vB\nuser = app\n", "user = web"),
    ],
)
def test_the_next_key_is_not_part_of_the_value(
    root: Path, name: str, text: str, after: str, capsys: pytest.CaptureFixture[str]
) -> None:
    following = text.splitlines()[-1]
    assert not changed_is_new(root, name, text, text.replace(following, after))
