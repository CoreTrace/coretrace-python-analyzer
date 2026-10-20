"""Regression for issue #261: an external-call cycle must reach a fixpoint.

The child-process timeout makes the old nontermination observable without
leaving a hanging pytest process on CI. The source is a fixed, local fixture.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

SOURCE = textwrap.dedent("""\
    def a(x):
        b(x)
        print(x)

    def b(x):
        c(x)
        print(x)

    def c(x):
        a(x)
""")


class ExternalCallOrderTests(unittest.TestCase):
    def test_old_order_dependent_summary_cache_is_invalidated(self):
        from coretrace_python.cache import CACHE_FORMAT, decode

        self.assertGreater(CACHE_FORMAT, 16)
        with self.assertRaisesRegex(ValueError, "unsupported cache format"):
            decode({"format": 16})

    def test_three_function_cycle_converges_with_external_calls(self):
        program = (
            "from coretrace_python import engine\n"
            "from coretrace_python.frontend import build_hir\n"
            "from coretrace_python.source import SourceManager\n"
            "from coretrace_python.interprocedural import SummaryAnalysis\n"
            f"source = {SOURCE!r}\n"
            "table = engine.build_manager(build_hir(SourceManager().add_source('cycle.py', source))).get(SummaryAnalysis)\n"
            "for name in ('a', 'b', 'c'):\n"
            "    calls = table.summary(name).external_calls\n"
            "    assert any(str(c.symbol) == 'python.builtins.print' for c in calls), name\n"
            "print('converged')\n"
        )
        try:
            proc = subprocess.run(
                [sys.executable, "-c", program], capture_output=True,
                text=True, timeout=20, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            self.fail(f"summary fixpoint did not terminate within 20 seconds: {exc}")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "converged")

    def test_external_call_order_is_independent_of_insertion_order(self):
        from coretrace_python.interprocedural.summaries import (
            ExternalCall,
            _canonical_external_calls,
        )
        from coretrace_python.semantic.symbols import SymbolId
        from coretrace_python.source import SourceId, SourceSpan

        span = SourceSpan(SourceId("cycle.py"), 3, 5)
        earlier = ExternalCall(SymbolId("python.builtins.print"), (), (), span, None)
        later = ExternalCall(
            SymbolId("python.builtins.len"), (), (),
            SourceSpan(SourceId("cycle.py"), 6, 5), span,
        )
        self.assertEqual(
            _canonical_external_calls([earlier, later]),
            _canonical_external_calls([later, earlier]),
        )
        self.assertEqual(_canonical_external_calls([later, earlier]), (earlier, later))

    def test_public_check_command_finishes_for_recursive_external_calls(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "cycle.py"
            path.write_text(SOURCE, encoding="utf-8")
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "coretrace_python", "--check", str(path)],
                    capture_output=True, text=True, timeout=20, check=False,
                )
            except subprocess.TimeoutExpired as exc:
                self.fail(f"CLI --check stalled on 3-function call cycle: {exc}")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_order_is_stable_across_call_site_and_symbol_ties(self):
        from coretrace_python.interprocedural.summaries import (
            ExternalCall,
            _canonical_external_calls,
        )
        from coretrace_python.semantic.symbols import SymbolId
        from coretrace_python.source import SourceId, SourceSpan

        location = SourceSpan(SourceId("cycle.py"), 3, 5)
        caller = SourceSpan(SourceId("cycle.py"), 6, 5)
        first = ExternalCall(SymbolId("python.builtins.len"), (), (), location, None)
        second = ExternalCall(SymbolId("python.builtins.print"), (), (), location, None)
        third = ExternalCall(SymbolId("python.builtins.len"), (), (), location, caller)
        self.assertEqual(
            _canonical_external_calls((third, second, first)),
            (first, second, third),
        )


if __name__ == "__main__":
    unittest.main()
