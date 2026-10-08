"""Acceptance tests for issue #205: the concurrency contract of the command line.

``ctrace`` deprecated ``--async`` for ``-j``/``--jobs`` (CoreTrace/coretrace#158): the
analyzer follows it rather than adding an ``--async`` mode. ``-j N`` is ``--jobs N``;
``0`` analyses in one process per available core, as ``runtime.jobs`` of ``ctrace``;
the default stays one process. The command always waits for the complete report, which
is the same whatever the number of processes.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import EXIT_ERROR, main

PROJECT = {
    "app/__init__.py": "",
    "app/a.py": "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n",
    "app/b.py": "def handle(code):\n    eval(code)\n",
    "app/c.py": "import hashlib\n\n\ndef digest(data):\n    return hashlib.md5(data)\n",
}


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    for name, text in PROJECT.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


def report(capsys: pytest.CaptureFixture[str], *options: str) -> tuple[int, str]:
    status = main(["--check", *options, "--format", "json"])
    out = capsys.readouterr().out
    return status, out


def test_j_is_jobs_and_the_report_does_not_depend_on_it(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sequential = report(capsys, str(project))

    assert report(capsys, str(project), "-j", "2") == sequential
    assert report(capsys, str(project), "--jobs", "2") == sequential


def test_zero_jobs_is_one_process_per_available_core(
    project: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sequential = report(capsys, str(project))
    used: list[int] = []
    analyze = engine.analyze_project

    def recording(*args: object, jobs: int = 1, **kwargs: object) -> engine.ProjectAnalysis:
        used.append(jobs)
        return analyze(*args, jobs=jobs, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(engine, "analyze_project", recording)
    cores = getattr(os, "process_cpu_count", os.cpu_count)() or 1

    assert report(capsys, str(project), "-j", "0") == sequential
    assert used == [cores]


def test_the_default_stays_one_process(
    project: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    used: list[int] = []
    analyze = engine.analyze_project

    def recording(*args: object, jobs: int = 1, **kwargs: object) -> engine.ProjectAnalysis:
        used.append(jobs)
        return analyze(*args, jobs=jobs, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(engine, "analyze_project", recording)
    report(capsys, str(project))

    assert used == [1]


@pytest.mark.parametrize("value", ["-1", "-8"])
def test_a_negative_number_of_jobs_is_an_error(
    project: Path, capsys: pytest.CaptureFixture[str], value: str
) -> None:
    assert main(["--check", str(project), "-j", value]) == EXIT_ERROR
    assert "--jobs" in capsys.readouterr().err


def test_there_is_no_async_option(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit:
        main(["--check", str(project), "--async"])

    assert exit.value.code == EXIT_ERROR
    assert "--async" in capsys.readouterr().err


def test_help_names_j_and_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--help"])
    text = " ".join(capsys.readouterr().out.split())

    # Python 3.13 prints "-j, --jobs N", earlier versions "-j N, --jobs N".
    assert re.search(r"-j( N)?, --jobs N", text) and "0 for one per available core" in text
