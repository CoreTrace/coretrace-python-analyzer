"""Parser-independent high-level representation of Python source."""

from coretrace_python.hir.builder import HIRBuildError, build_module
from coretrace_python.hir.nodes import Module

__all__ = ["HIRBuildError", "Module", "build_module"]

