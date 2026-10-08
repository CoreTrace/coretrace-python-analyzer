"""Acceptance tests for issue #205: the concurrency contract of the command line.

``ctrace`` deprecated ``--async`` for ``-j``/``--jobs`` (CoreTrace/coretrace#158): the
analyzer follows it rather than adding an ``--async`` mode. ``-j N`` is ``--jobs N``;
``0`` analyses in one process per core the process may run on, as ``runtime.jobs`` of
``ctrace`` (its affinity where Python can tell it); the default stays one process. The
pool never holds more processes than the platform allows (61 on Windows). The command always waits for the complete report, which
is the same whatever the number of processes.
"""

from __future__ import annotations

import concurrent.futures
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


def recorded_jobs(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    used: list[int] = []
    analyze = engine.analyze_project

    def recording(*args: object, jobs: int = 1, **kwargs: object) -> engine.ProjectAnalysis:
        used.append(jobs)
        return analyze(*args, jobs=jobs, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(engine, "analyze_project", recording)
    return used


def test_zero_jobs_is_one_process_per_available_core(
    project: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sequential = report(capsys, str(project))
    used = recorded_jobs(monkeypatch)
    monkeypatch.setattr(os, "process_cpu_count", lambda: 3, raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: 64)

    assert report(capsys, str(project), "-j", "0") == sequential
    assert used == [3]


def test_zero_jobs_counts_the_cores_the_process_may_run_on_before_python_3_13(
    project: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without ``os.process_cpu_count``, the affinity of the process, not every core of
    the machine: 2 of 64 here."""

    used = recorded_jobs(monkeypatch)
    monkeypatch.delattr(os, "process_cpu_count", raising=False)
    monkeypatch.setattr(os, "sched_getaffinity", lambda pid: {0, 5}, raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: 64)

    report(capsys, str(project), "-j", "0")
    assert used == [2]


@pytest.mark.parametrize(("cores", "expected"), [(5, 5), (None, 1)])
def test_zero_jobs_falls_back_to_the_cores_of_the_machine(
    project: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    cores: int | None,
    expected: int,
) -> None:
    used = recorded_jobs(monkeypatch)
    monkeypatch.delattr(os, "process_cpu_count", raising=False)
    monkeypatch.delattr(os, "sched_getaffinity", raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: cores)

    report(capsys, str(project), "-j", "0")
    assert used == [expected]


@pytest.mark.parametrize(
    ("jobs", "platform", "size"),
    [(64, "win32", 61), (61, "win32", 61), (64, "linux", 64), (2, "win32", 2)],
)
def test_the_pool_holds_no_more_processes_than_the_platform_allows(
    jobs: int, platform: str, size: int
) -> None:
    """``ProcessPoolExecutor`` refuses more than 61 workers on Windows."""

    assert engine.process_pool_size(jobs, platform) == size


def test_the_analysis_starts_the_pool_at_its_capped_size(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sizes: list[int] = []
    pool = concurrent.futures.ProcessPoolExecutor

    def recording(max_workers: int, **kwargs: object) -> concurrent.futures.ProcessPoolExecutor:
        sizes.append(max_workers)
        return pool(max_workers=2, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(engine, "process_pool_size", lambda jobs, platform=None: 7)
    monkeypatch.setattr(concurrent.futures, "ProcessPoolExecutor", recording)

    engine.analyze_project(project, [engine.BUNDLED_PLUGINS], jobs=64)
    assert sizes == [7]


def test_the_default_stays_one_process(
    project: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    used = recorded_jobs(monkeypatch)
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
