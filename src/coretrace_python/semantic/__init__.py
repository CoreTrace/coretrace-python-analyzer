"""Semantic analyses computed from PyHIR: scopes, imports and symbols."""

from coretrace_python.semantic.imports import ImportAnalysis
from coretrace_python.semantic.scopes import ScopeAnalysis
from coretrace_python.semantic.symbols import SymbolAnalysis

SEMANTIC_ANALYSES = (ScopeAnalysis, ImportAnalysis, SymbolAnalysis)

__all__ = ["SEMANTIC_ANALYSES", "ImportAnalysis", "ScopeAnalysis", "SymbolAnalysis"]
