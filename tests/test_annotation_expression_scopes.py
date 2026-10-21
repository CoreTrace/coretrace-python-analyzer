"""Regression coverage for lexical scopes created inside parameter annotations."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from coretrace_python.frontend import build_hir
from coretrace_python.semantic.scopes import ResolutionKind, ScopeKind, analyze_scopes
from coretrace_python.source import SourceManager


class AnnotationExpressionScopes(unittest.TestCase):
    def _check_directory(self, contents: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            project.mkdir()
            (project / "app.py").write_text(contents, encoding="utf-8")
            env = os.environ.copy()
            result = subprocess.run(
                [sys.executable, "-m", "coretrace_python", "--check", str(project)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr[-1000:])
            self.assertNotIn("KeyError", result.stderr)

    def test_keyword_only_parameter_lambda_annotation_does_not_crash_project(self):
        self._check_directory("def f(*, status: (lambda value: value) = None):\n    return status\n")

    def test_positional_parameter_lambda_annotation_does_not_crash_project(self):
        self._check_directory("def f(status: (lambda value: value) = None):\n    return status\n")

    def test_parameter_comprehension_annotation_does_not_crash_project(self):
        self._check_directory("entries = (1, 2)\ndef f(status: [v for v in entries]):\n    return status\n")

    def test_annotation_scopes_belong_to_the_enclosing_module(self):
        source = SourceManager().add_source(
            "annotation_scopes.py",
            "entries = (1, 2)\ndef f(first: (lambda x: x), second: [v for v in entries]):\n    pass\n",
        )
        hir = build_hir(source)
        scopes = analyze_scopes(hir)
        function = hir.body[1]
        first, second = function.parameters
        lambda_scope = scopes.scope_for(first.annotation)
        comprehension_scope = scopes.scope_for(second.annotation)
        self.assertEqual(lambda_scope.kind, ScopeKind.FUNCTION)
        self.assertEqual(comprehension_scope.kind, ScopeKind.COMPREHENSION)
        self.assertEqual(lambda_scope.parent, scopes.module_scope.id)
        self.assertEqual(comprehension_scope.parent, scopes.module_scope.id)

    def test_varargs_annotations_create_scopes_in_the_enclosing_module(self):
        source = SourceManager().add_source(
            "varargs_scopes.py",
            "def f(*args: (lambda x: x), **kwargs: [v for v in (1, 2)]):\n    pass\n",
        )
        hir = build_hir(source)
        scopes = analyze_scopes(hir)
        first, second = hir.body[0].parameters
        self.assertEqual(scopes.scope_for(first.annotation).parent, scopes.module_scope.id)
        self.assertEqual(scopes.scope_for(second.annotation).parent, scopes.module_scope.id)

    def test_nested_parameter_annotation_resolves_enclosing_local(self):
        source = SourceManager().add_source(
            "nested_annotations.py",
            "def outer():\n"
            "    secret = 1\n"
            "    def inner(value: (lambda: secret)):\n"
            "        return value\n"
            "    return inner\n",
        )
        hir = build_hir(source)
        scopes = analyze_scopes(hir)
        outer = hir.body[0]
        inner = outer.body[1]
        annotation_scope = scopes.scope_for(inner.parameters[0].annotation)
        outer_scope = scopes.scope_for(outer)
        self.assertEqual(annotation_scope.parent, outer_scope.id)
        resolution = scopes.resolve(annotation_scope.id, "secret")
        self.assertEqual(resolution.kind, ResolutionKind.FREE)
        self.assertEqual(resolution.scope, outer_scope.id)


if __name__ == "__main__":
    unittest.main()
