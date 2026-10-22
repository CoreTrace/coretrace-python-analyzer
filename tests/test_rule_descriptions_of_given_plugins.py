"""Acceptance tests for the review of #274: a plugin given to ``analyze_project`` as an
instance, rather than loaded from a plugin root, describes its rules in the report as a
loaded plugin does.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import ClassVar

from coretrace_python import engine
from coretrace_python.findings import Finding, RuleDescription
from coretrace_python.plugins import Plugin, PluginContext

QUIET = RuleDescription("Quiet rule", "A rule of a plugin given as an instance.")


class Quiet(Plugin):
    name: ClassVar[str] = "quiet"
    rules: ClassVar[Mapping[str, RuleDescription]] = {
        "quiet-rule": QUIET,
    }

    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        return ()


def analysed(tmp_path: Path) -> engine.ProjectAnalysis:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    return engine.analyze_project(tmp_path, [engine.BUNDLED_PLUGINS], plugins=[Quiet()])


def test_a_plugin_given_as_an_instance_describes_its_rules(tmp_path: Path) -> None:
    assert analysed(tmp_path).rules["quiet-rule"] == QUIET
