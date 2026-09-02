from __future__ import annotations

import ast
from pathlib import Path

from coretrace_python.source import SourceFile, SourceManager


class ParseError(Exception):
    """A source-located Python parsing failure."""


def parse_source(source: str, filename: str = "<unknown>") -> ast.Module:
    try:
        return ast.parse(source, filename=filename)
    except SyntaxError as error:
        line = error.lineno or 0
        column = error.offset or 0
        message = error.msg or "invalid syntax"
        raise ParseError(f"{filename}:{line}:{column}: {message}") from error


def parse_file(path: str | Path) -> ast.Module:
    source = SourceManager().load_file(path)
    return parse_source_file(source)


def parse_source_file(source: SourceFile) -> ast.Module:
    return parse_source(source.text, filename=str(source.source_id))
