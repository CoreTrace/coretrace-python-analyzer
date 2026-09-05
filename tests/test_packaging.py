"""Acceptance tests for the installable product (product track, first point).

The shipped plugins travel inside the wheel, under ``coretrace_python/bundled``, and are
loaded by default: ``coretrace-python-analyzer --check app.py`` works right after
``pip install``. ``--plugins DIR`` adds directories on top of the bundle and
``--no-bundled-plugins`` drops it. The wheel carries the manifests, and the version has
one source of truth.

Expected to remain red until ``engine.BUNDLED_PLUGINS`` and the CLI defaults exist.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from importlib import metadata
from pathlib import Path

import pytest

import coretrace_python
from coretrace_python import engine
from coretrace_python.cli import main

MISSING: Exception | None = None
if not hasattr(engine, "BUNDLED_PLUGINS"):
    MISSING = AttributeError("engine has no BUNDLED_PLUGINS")


@pytest.fixture(autouse=True)
def require_packaging() -> None:
    if MISSING is not None:
        pytest.fail(f"packaging is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
EVAL = "def run(code):\n    eval(code)\n"


def write_plugin(directory: Path) -> Path:
    directory.mkdir(parents=True)
    (directory / "plugin.toml").write_text(
        'name = "extra-hello"\nversion = "1.0.0"\nplugin_api = ">=1,<2"\nrequires = []\n'
        'provides = ["extra.hello"]\n\n[entrypoint]\nmodule = "hello"\nclass = "Hello"\n',
        encoding="utf-8",
    )
    (directory / "hello.py").write_text(
        "from coretrace_python.findings import Confidence, Finding, Severity\n"
        "from coretrace_python.plugins import Plugin\n"
        "from coretrace_python.source import SourceSpan\n\n"
        "class Hello(Plugin):\n    name = 'extra-hello'\n\n"
        "    def analyze(self, ctx):\n"
        "        span = SourceSpan(ctx.module.span.source_id, 1, 1)\n"
        "        return [Finding('hello', 'hello', Severity.INFO, Confidence.HIGH, span)]\n",
        encoding="utf-8",
    )
    return directory


def test_bundled_plugins_live_inside_the_package() -> None:
    bundled = engine.BUNDLED_PLUGINS

    assert bundled == Path(coretrace_python.__file__).resolve().parent / "bundled"
    assert bundled.is_dir()
    manifests = sorted(p.relative_to(bundled).as_posix() for p in bundled.rglob("plugin.toml"))
    assert len(manifests) == 26
    assert "syntax/dangerous_eval/plugin.toml" in manifests
    assert not (REPO / "plugins").exists()


def test_checks_use_the_bundle_by_default(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "app.py"
    source.write_text(EVAL, encoding="utf-8")

    assert main(["--check", str(source)]) == 1
    assert "dangerous-eval" in capsys.readouterr().out
    assert main(["--check", str(source), "--no-bundled-plugins"]) == 0
    assert capsys.readouterr().out == "no findings\ncoverage: 1/1 files, 1/1 functions\n"


def test_extra_plugin_directories_add_to_the_bundle(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "app.py"
    source.write_text(EVAL, encoding="utf-8")
    extra = write_plugin(tmp_path / "extra")

    assert main(["--check", str(source), "--plugins", str(extra)]) == 1
    output = capsys.readouterr().out
    assert "dangerous-eval" in output and "hello" in output
    assert main(["--check", str(source), "--plugins", str(extra), "--no-bundled-plugins", "--format", "json"]) == 1
    assert '"rule_id": "hello"' in capsys.readouterr().out
    assert "dangerous-eval" not in capsys.readouterr().out


def test_the_version_has_one_source_of_truth() -> None:
    assert metadata.version("coretrace-python-analyzer") == coretrace_python.__version__


def test_the_wheel_carries_the_bundled_plugins(tmp_path: Path) -> None:
    pytest.importorskip("build")
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(tmp_path), str(REPO)],
        check=True,
        capture_output=True,
    )
    (wheel,) = tmp_path.glob("*.whl")
    names = zipfile.ZipFile(wheel).namelist()

    assert "coretrace_python/bundled/syntax/dangerous_eval/plugin.toml" in names
    assert "coretrace_python/bundled/syntax/dangerous_eval/dangerous_eval.py" in names
    assert sum(1 for n in names if n.endswith("/plugin.toml")) == 26
    assert not any(n.startswith("tests/") or "tests-project" in n for n in names)


def test_the_license_ships_with_the_repository_and_the_wheel(tmp_path: Path) -> None:
    pytest.importorskip("build")
    assert "Apache License" in (REPO / "LICENSE").read_text(encoding="utf-8")
    assert "Copyright" in (REPO / "NOTICE").read_text(encoding="utf-8")
    assert "Apache" in (REPO / "README.md").read_text(encoding="utf-8")
    assert metadata.metadata("coretrace-python-analyzer")["License-Expression"] == "Apache-2.0"
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(tmp_path), str(REPO)],
        check=True,
        capture_output=True,
    )
    (wheel,) = tmp_path.glob("*.whl")
    names = zipfile.ZipFile(wheel).namelist()
    assert any(name.endswith(".dist-info/licenses/LICENSE") for name in names)
    assert any(name.endswith(".dist-info/licenses/NOTICE") for name in names)
