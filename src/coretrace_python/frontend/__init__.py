"""Parsing and adaptation of Python source into parser-independent PyHIR.

Parser-specific objects never leave this package: callers receive a PyHIR module.
"""

from coretrace_python.frontend.ast_adapter import HIRBuildError, build_module
from coretrace_python.frontend.parser import ParseError, parse_source_file
from coretrace_python.hir import nodes
from coretrace_python.source import SourceFile


def build_hir(source: SourceFile) -> nodes.Module:
    """Parse ``source`` and return its PyHIR module."""

    return build_module(source, parse_source_file(source))


__all__ = ["HIRBuildError", "ParseError", "build_hir"]
