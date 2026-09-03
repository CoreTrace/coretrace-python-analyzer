"""Reporters render normalized findings and never run an analysis (architecture §28)."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType

from coretrace_python.reporters.json_format import render_json
from coretrace_python.reporters.report import Report
from coretrace_python.reporters.sarif import render_sarif
from coretrace_python.reporters.text import render_text

FORMATS: Mapping[str, Callable[[Report], str]] = MappingProxyType(
    {"text": render_text, "json": render_json, "sarif": render_sarif}
)


def render(format_name: str, report: Report) -> str:
    return FORMATS[format_name](report)


__all__ = ["FORMATS", "Report", "render", "render_json", "render_sarif", "render_text"]
