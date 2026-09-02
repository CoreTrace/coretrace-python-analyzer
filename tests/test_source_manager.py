from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python.source import SourceId, SourceManager, SourceSpan


def test_add_source_returns_the_same_object_for_identical_input() -> None:
    manager = SourceManager()
    first = manager.add_source("memory.py", "value = 1\n")
    second = manager.add_source("memory.py", "value = 1\n")

    assert first is second
    assert len(manager) == 1


def test_add_source_rejects_conflicting_text() -> None:
    manager = SourceManager()
    manager.add_source("memory.py", "value = 1\n")

    with pytest.raises(ValueError, match="already exists with different text"):
        manager.add_source("memory.py", "value = 2\n")


def test_load_file_uses_a_resolved_path_as_its_stable_id(tmp_path: Path) -> None:
    path = tmp_path / "module.py"
    path.write_text("value = 1\n", encoding="utf-8")

    source = SourceManager().load_file(path)

    assert source.source_id == SourceId(str(path.resolve()))
    assert source.path == path.resolve()


def test_load_file_accepts_a_utf8_bom(tmp_path: Path) -> None:
    path = tmp_path / "module.py"
    path.write_text("\ufeffvalue = 1\n", encoding="utf-8")

    source = SourceManager().load_file(path)

    assert source.text == "value = 1\n"


def test_source_span_uses_one_based_positions() -> None:
    with pytest.raises(ValueError, match="one-based"):
        SourceSpan(SourceId("module.py"), start_line=0, start_column=1)


def test_source_span_formats_its_start_location() -> None:
    span = SourceSpan(SourceId("module.py"), start_line=3, start_column=7)
    assert span.display() == "module.py:3:7"

