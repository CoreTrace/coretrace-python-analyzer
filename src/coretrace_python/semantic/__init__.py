"""Semantic analyses computed from PyHIR: scopes, imports and symbols."""

from coretrace_python.semantic.imports import ImportAnalysis
from coretrace_python.semantic.scopes import ScopeAnalysis
from coretrace_python.semantic.symbols import MembersAnalysis, SymbolAnalysis

SEMANTIC_ANALYSES = (ScopeAnalysis, ImportAnalysis, MembersAnalysis, SymbolAnalysis)

__all__ = ["SEMANTIC_ANALYSES", "ImportAnalysis", "MembersAnalysis", "ScopeAnalysis", "SymbolAnalysis"]
