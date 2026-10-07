"""Acceptance tests for issues #223 and #224: what a baseline entry records.

An entry recognises a finding by a digest of the text of every line its span covers,
never by that text: a secret written over several lines, whose first line does not hold
it, is new once its body changes (#223), and the baseline file, which is meant to be
committed, holds no accepted secret in plain text (#224). Baselines are written in
schema 3. Schema 1 and 2 files are still read and never rewritten; their entries, which
hold the text of a finding's first line, identify only a finding on a single line, and
any other finding is new.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python.cli import main

TOKEN = "ghp_" + "a1B2" * 9
PASSWORD = "Zx81kQpLw0RtY7vBn3MsD9cF2hJ6gK4a"
BODY = "MIIEowIBAAKCAQEA1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4"
KEY = f'KEY = """\n-----BEGIN RSA PRIVATE KEY-----\n{BODY}\n-----END RSA PRIVATE KEY-----\n"""\n'
FILES = {
    "keys.py": KEY,
    "app.py": f"def run(code):\n    eval(code)\n\nTOKEN = '{TOKEN}'\n",
    ".env": f"DB_PASSWORD={PASSWORD}\n",
    "config.yaml": f"service:\n  api_token: {PASSWORD[::-1]}\n",
    "settings.json": f'{{\n  "db": {{"password": "{PASSWORD.upper()}"}}\n}}\n',
}
SECRETS = (BODY, TOKEN, PASSWORD, PASSWORD[::-1], PASSWORD.upper())
DONE = "no findings, 6 baselined\ncoverage: 2/2 files, 3/3 functions\n"


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    for name, text in FILES.items():
        (root / name).write_text(text, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return root


def check(root: Path, baseline: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    status = main(["--check", root.name, "--baseline", str(baseline)])
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def test_a_changed_secret_in_a_multi_line_string_is_new(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = tmp_path / "baseline.json"
    check(root, baseline, capsys)
    (root / "keys.py").write_text(KEY.replace(BODY, BODY[::-1]), encoding="utf-8")

    status, out, _ = check(root, baseline, capsys)

    assert status == 1
    assert out.startswith("keys.py:1:7: high hardcoded-secret")
    assert "1 finding, 5 baselined\n" in out


def test_an_unchanged_multi_line_secret_stays_baselined_when_code_moves(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = tmp_path / "baseline.json"
    check(root, baseline, capsys)
    (root / "keys.py").write_text("import os\n\n\n" + KEY, encoding="utf-8")

    assert check(root, baseline, capsys)[:2] == (0, DONE)


def test_the_baseline_holds_no_accepted_secret_and_is_not_reported_itself(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The baseline is recorded inside the project, as when it is committed with it."""

    baseline = root / "baseline.json"
    check(root, baseline, capsys)
    text = baseline.read_text(encoding="utf-8")
    document = json.loads(text)

    assert document["schema"] == 3
    assert not [secret for secret in SECRETS if secret in text or secret[:12] in text]
    assert {"path", "rule", "function", "digest", "pointer", "count"} == set(
        document["findings"][0]
    )
    assert check(root, baseline, capsys)[:2] == (0, DONE)


def legacy(path: Path, schema: int, *entries: tuple[str, str, str, str]) -> Path:
    findings = [
        {"path": file, "rule": rule, "function": function, "line": line, "pointer": "", "count": 1}
        for file, rule, function, line in entries
    ]
    path.write_text(json.dumps({"schema": schema, "findings": findings}), encoding="utf-8")
    return path


@pytest.mark.parametrize("schema", [1, 2])
def test_an_old_entry_never_accounts_for_a_finding_over_several_lines(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], schema: int
) -> None:
    """The old entry of the key holds the text of its first line, which a changed key
    keeps: it cannot identify the finding, which is new; entries of findings on a single
    line still match exactly, and the file is left as it was."""

    for name in (".env", "config.yaml", "settings.json"):
        (root / name).unlink()
    (root / "keys.py").write_text(KEY.replace(BODY, BODY[::-1]), encoding="utf-8")
    baseline = legacy(
        tmp_path / "baseline.json",
        schema,
        ("keys.py", "hardcoded-secret", "", 'KEY = """'),
        ("app.py", "dangerous-eval", "run", "eval(code)"),
        ("app.py", "hardcoded-secret", "", f"TOKEN = '{TOKEN}'"),
    )
    before = baseline.read_bytes()

    status, out, err = check(root, baseline, capsys)

    assert status == 1
    assert out.startswith("keys.py:1:7: high hardcoded-secret")
    assert "1 finding, 2 baselined\n" in out
    assert (
        err.count(f"schema {schema} baseline: this baseline may contain secrets in plain text") == 1
    )
    assert baseline.read_bytes() == before


def test_a_secret_written_as_a_key_is_not_kept_in_the_pointer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A value at a file location is recognised by its pointer, which names the keys
    above it; a key may itself be a secret, so the entry holds a digest of the pointer."""

    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    (root / "settings.toml").write_text(
        f'[tokens]\n"{TOKEN}" = {{ owner = "ci", password = "{PASSWORD}" }}\n', encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    baseline = root / "baseline.json"
    check(root, baseline, capsys)
    text = baseline.read_text(encoding="utf-8")

    assert TOKEN not in text and PASSWORD not in text
    assert check(root, baseline, capsys)[:2] == (
        0,
        "no findings, 1 baselined\ncoverage: 1/1 files, 1/1 functions\n",
    )
