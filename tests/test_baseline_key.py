"""Acceptance tests for issue #225: baselines keyed with HMAC-SHA-256.

A schema 3 baseline holds no text, but its digests let anyone test candidate values
offline. With a key, from a key file given with ``--baseline-key-file`` (kept out of the
analysed directory) or else from ``CORETRACE_BASELINE_KEY``, the baseline is recorded in
schema 4: every digest is an HMAC-SHA-256 under the key, with a check value that tells
the key apart, never the key itself. A schema 4 baseline needs its key: without it, or
with another, the check stops with an explicit error and records nothing; and with a key,
an unkeyed baseline is refused, so that it cannot stand in for the keyed one. Without a
key, schemas 1 to 3 are still read, never rewritten. Rotating the key, or moving to schema 4, is an explicit
``--record-baseline``, which replaces the file only once the check succeeded. The key
never appears in a report, a message or the baseline.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from coretrace_python.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main
from coretrace_python.source.positions import text_digest

KEY = "k3y-0f-the-team-" * 2
OTHER = "an0ther-k3y-2026" * 2
TOKEN = "ghp_" + "a1B2" * 9
LINE = f"TOKEN = '{TOKEN}'"
ENVIRONMENT = "CORETRACE_BASELINE_KEY"


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").write_text(f"def run(code):\n    eval(code)\n\n{LINE}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(ENVIRONMENT, raising=False)
    return root


def check(capsys: pytest.CaptureFixture[str], *options: str) -> tuple[int, str, str]:
    status = main(["--check", "proj", *options])
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def keyed(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    key: str = KEY,
) -> Path:
    baseline = project.parent / "baseline.json"
    monkeypatch.setenv(ENVIRONMENT, key)
    assert check(capsys, "--baseline", str(baseline))[0] == EXIT_CLEAN
    return baseline


def test_a_key_records_schema_4_with_hmac_digests_and_never_the_key(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = keyed(project, monkeypatch, capsys)
    text = baseline.read_text(encoding="utf-8")
    document = json.loads(text)

    assert document["schema"] == 4
    assert document["key_check"].startswith("hmac-sha256:")
    assert all(entry["digest"].startswith("hmac-sha256:") for entry in document["findings"])
    assert KEY not in text and TOKEN not in text
    # A candidate value hashed without the key matches no entry.
    assert text_digest(LINE) not in text
    status, out, err = check(capsys, "--baseline", str(baseline), "--format", "json")
    assert status == EXIT_CLEAN
    assert KEY not in out and KEY not in err


def test_a_schema_4_baseline_without_its_key_is_an_error_and_records_nothing(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = keyed(project, monkeypatch, capsys)
    before = baseline.read_bytes()
    monkeypatch.delenv(ENVIRONMENT)

    status, _, err = check(capsys, "--baseline", str(baseline))

    assert status == EXIT_ERROR
    assert "recorded with a baseline key" in err and ENVIRONMENT in err
    assert baseline.read_bytes() == before


def test_a_schema_4_baseline_with_another_key_is_an_error_and_records_nothing(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = keyed(project, monkeypatch, capsys)
    before = baseline.read_bytes()
    monkeypatch.setenv(ENVIRONMENT, OTHER)

    status, _, err = check(capsys, "--baseline", str(baseline))

    assert status == EXIT_ERROR
    assert "another baseline key" in err and "--record-baseline" in err
    assert OTHER not in err and KEY not in err
    assert baseline.read_bytes() == before


def test_the_key_file_given_explicitly_comes_before_the_environment(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "secrets" / "baseline.key"
    key_file.parent.mkdir()
    key_file.write_text(KEY + "\n", encoding="utf-8")
    baseline = project.parent / "baseline.json"
    monkeypatch.setenv(ENVIRONMENT, OTHER)
    assert (
        check(capsys, "--baseline", str(baseline), "--baseline-key-file", str(key_file))[0]
        == EXIT_CLEAN
    )

    monkeypatch.setenv(ENVIRONMENT, KEY)
    assert check(capsys, "--baseline", str(baseline))[0] == EXIT_CLEAN
    monkeypatch.setenv(ENVIRONMENT, OTHER)
    assert check(capsys, "--baseline", str(baseline))[0] == EXIT_ERROR


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ("inside", "inside the analysed directory"),
        ("short", "shorter than 16 bytes"),
        ("empty", "is set but empty"),
        ("missing", "cannot read the baseline key"),
    ],
)
def test_an_unusable_key_is_an_error_and_records_nothing(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    setup: str,
    message: str,
) -> None:
    baseline = project.parent / "baseline.json"
    options = ["--baseline", str(baseline)]
    if setup == "inside":
        (project / "baseline.key").write_text(KEY, encoding="utf-8")
        options += ["--baseline-key-file", str(project / "baseline.key")]
    elif setup == "short":
        monkeypatch.setenv(ENVIRONMENT, "short")
    elif setup == "empty":
        monkeypatch.setenv(ENVIRONMENT, "")
    else:
        options += ["--baseline-key-file", str(tmp_path / "absent.key")]

    status, _, err = check(capsys, *options)

    assert status == EXIT_ERROR
    assert message in err and KEY not in err
    assert not baseline.exists()


def test_rotating_the_key_is_an_explicit_record_that_replaces_the_baseline(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = keyed(project, monkeypatch, capsys)
    monkeypatch.setenv(ENVIRONMENT, OTHER)
    assert check(capsys, "--baseline", str(baseline))[0] == EXIT_ERROR

    assert check(capsys, "--baseline", str(baseline), "--record-baseline")[0] == EXIT_CLEAN

    assert check(capsys, "--baseline", str(baseline))[0] == EXIT_CLEAN
    monkeypatch.setenv(ENVIRONMENT, KEY)
    assert check(capsys, "--baseline", str(baseline))[0] == EXIT_ERROR
    assert [path.name for path in baseline.parent.iterdir() if path.name.startswith(".")] == []


def test_a_failed_record_keeps_the_previous_baseline(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = keyed(project, monkeypatch, capsys)
    before = baseline.read_bytes()
    monkeypatch.setenv(ENVIRONMENT, "short")

    assert check(capsys, "--baseline", str(baseline), "--record-baseline")[0] == EXIT_ERROR
    assert baseline.read_bytes() == before


def legacy(path: Path, schema: int) -> Path:
    if schema == 3:
        entries = [
            {
                "path": "app.py",
                "rule": "dangerous-eval",
                "function": "run",
                "digest": text_digest("eval(code)"),
                "pointer": "",
                "count": 1,
            },
            {
                "path": "app.py",
                "rule": "hardcoded-secret",
                "function": "",
                "digest": text_digest(LINE),
                "pointer": "",
                "count": 1,
            },
        ]
    else:
        entries = [
            {
                "path": "app.py",
                "rule": "dangerous-eval",
                "function": "run",
                "line": "eval(code)",
                "pointer": "",
                "count": 1,
            },
            {
                "path": "app.py",
                "rule": "hardcoded-secret",
                "function": "",
                "line": LINE,
                "pointer": "",
                "count": 1,
            },
        ]
    path.write_text(json.dumps({"schema": schema, "findings": entries}), encoding="utf-8")
    return path


@pytest.mark.parametrize("schema", [1, 2, 3])
def test_an_unkeyed_baseline_is_refused_while_a_key_is_given(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], schema: int
) -> None:
    """Else whoever can edit the baseline could swap the keyed one for an unkeyed one
    holding the digest of a new secret."""

    baseline = legacy(project.parent / "baseline.json", schema)
    before = baseline.read_bytes()
    monkeypatch.setenv(ENVIRONMENT, KEY)

    status, _, err = check(capsys, "--baseline", str(baseline))

    assert status == EXIT_ERROR
    assert f"unkeyed baseline (schema {schema})" in err and "--record-baseline" in err
    assert baseline.read_bytes() == before


@pytest.mark.parametrize("schema", [1, 2, 3])
def test_an_unkeyed_baseline_moves_to_schema_4_by_an_explicit_record(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], schema: int
) -> None:
    baseline = legacy(project.parent / "baseline.json", schema)
    monkeypatch.setenv(ENVIRONMENT, KEY)

    assert check(capsys, "--baseline", str(baseline), "--record-baseline")[0] == EXIT_CLEAN

    assert json.loads(baseline.read_text(encoding="utf-8"))["schema"] == 4
    assert check(capsys, "--baseline", str(baseline))[0] == EXIT_CLEAN


@pytest.mark.parametrize("schema", [1, 2])
def test_an_old_baseline_without_a_key_is_read_as_before(
    project: Path, capsys: pytest.CaptureFixture[str], schema: int
) -> None:
    baseline = legacy(project.parent / "baseline.json", schema)
    before = baseline.read_bytes()

    status, out, err = check(capsys, "--baseline", str(baseline))

    assert status == EXIT_CLEAN
    assert out.startswith("no findings, 2 baselined\n")
    assert f"schema {schema} baseline" in err and "--record-baseline" in err
    assert baseline.read_bytes() == before


def test_a_schema_3_baseline_without_a_key_keeps_its_behaviour(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = legacy(project.parent / "baseline.json", 3)

    status, out, err = check(capsys, "--baseline", str(baseline))

    assert (status, out.startswith("no findings, 2 baselined\n"), err) == (EXIT_CLEAN, True, "")


def test_a_new_finding_is_still_new_under_a_key(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = keyed(project, monkeypatch, capsys)
    (project / "app.py").write_text(
        f"def run(code):\n    eval(code)\n\n{LINE.replace('a1B2', 'Z9y8')}\n", encoding="utf-8"
    )

    status, out, _ = check(capsys, "--baseline", str(baseline))

    assert status == EXIT_FINDINGS
    assert out.startswith("app.py:4:9: high hardcoded-secret")


def test_recording_without_the_key_never_drops_it(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A CI job whose secret is missing must not turn a keyed baseline into an unkeyed one."""

    baseline = keyed(project, monkeypatch, capsys)
    before = baseline.read_bytes()
    monkeypatch.delenv(ENVIRONMENT)

    status, _, err = check(capsys, "--baseline", str(baseline), "--record-baseline")

    assert status == EXIT_ERROR
    assert "recorded with a baseline key" in err
    assert baseline.read_bytes() == before


def test_the_key_file_cannot_be_the_baseline(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = keyed(project, monkeypatch, capsys)
    before = baseline.read_bytes()

    status, _, err = check(
        capsys,
        "--baseline",
        str(baseline),
        "--baseline-key-file",
        str(baseline),
        "--record-baseline",
    )

    assert status == EXIT_ERROR and "the baseline itself" in err
    assert baseline.read_bytes() == before


def test_a_key_file_inside_is_refused_however_its_path_is_spelled(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    (project / "baseline.key").write_text(KEY, encoding="utf-8")
    spelled = tmp_path / project.name.upper() / "baseline.key"
    if not spelled.exists():
        pytest.skip("the file system tells letter cases apart")

    status, _, err = check(
        capsys, "--baseline", str(project.parent / "b.json"), "--baseline-key-file", str(spelled)
    )

    assert status == EXIT_ERROR and "inside the analysed directory" in err


def test_the_same_key_reads_the_same_from_the_file_and_the_environment(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "baseline.key"
    key_file.write_text(KEY + "\r\n", encoding="utf-8")
    baseline = project.parent / "baseline.json"
    assert (
        check(capsys, "--baseline", str(baseline), "--baseline-key-file", str(key_file))[0]
        == EXIT_CLEAN
    )

    monkeypatch.setenv(ENVIRONMENT, KEY + "\n")
    assert check(capsys, "--baseline", str(baseline))[0] == EXIT_CLEAN


def test_the_baseline_is_replaced_only_once_the_report_is_rendered(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = keyed(project, monkeypatch, capsys)
    before = baseline.read_bytes()
    monkeypatch.setenv(ENVIRONMENT, OTHER)

    def failing(*args: object) -> str:
        raise OSError("the report cannot be written")

    monkeypatch.setattr("coretrace_python.cli.render", failing)

    assert check(capsys, "--baseline", str(baseline), "--record-baseline")[0] == EXIT_ERROR
    assert baseline.read_bytes() == before


def test_a_recorded_baseline_keeps_the_permissions_of_the_file_it_replaces(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    fresh = project.parent / "fresh.json"
    assert check(capsys, "--baseline", str(fresh))[0] == EXIT_CLEAN
    umask = os.umask(0)
    os.umask(umask)
    assert stat.S_IMODE(fresh.stat().st_mode) == 0o666 & ~umask

    fresh.chmod(0o640)
    assert check(capsys, "--baseline", str(fresh), "--record-baseline")[0] == EXIT_CLEAN
    assert stat.S_IMODE(fresh.stat().st_mode) == 0o640

    link = project.parent / "link.json"
    link.symlink_to(fresh)
    assert check(capsys, "--baseline", str(link), "--record-baseline")[0] == EXIT_CLEAN
    assert link.is_symlink()
