"""What makes a fix reach a cached project (#258, review of PR #259).

A change to the analysis that keeps the cache format and the plugins, as the summaries
dropping unreachable blocks does, keeps every key between commits of one version: a
cache built before it would still serve the old results. What delivers it is the
version of the engine, part of every key: once it changes, nothing cached is reused and
every module is analysed again with the engine that reads it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cache import ProjectCache

APP = "import os\n\n\ndef helper(cmd):\n    if False:\n        os.system(cmd)\n\n\ndef caller():\n    helper(input())\n"


def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "app").mkdir(parents=True)
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app" / "main.py").write_text(APP, encoding="utf-8")
    return root


def test_a_new_engine_version_reuses_nothing_cached(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = project(tmp_path)
    cache = ProjectCache(tmp_path / "cache")
    built = engine.analyze_project(root, [engine.BUNDLED_PLUGINS], cache=cache)
    same_version = engine.analyze_project(root, [engine.BUNDLED_PLUGINS], cache=cache)

    monkeypatch.setattr(engine, "__version__", "0.0.0+next")
    next_version = engine.analyze_project(root, [engine.BUNDLED_PLUGINS], cache=cache)

    assert set(same_version.reused) == set(built.keys) == {"app", "app.main"}
    assert next_version.reused == ()
    assert set(next_version.keys.values()).isdisjoint(built.keys.values())
    assert [f for f in next_version.findings if f.rule_id == "command-injection"] == []
