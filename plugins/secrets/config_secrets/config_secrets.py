"""Hardcoded secrets in configuration files: ``.env``, YAML, TOML, JSON, INI, properties.

Judged with the same rules as the Python literal detector, once per project.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

from coretrace_python.findings import Finding
from coretrace_python.plugins import PluginContext, ProjectContext, ProjectPlugin
from coretrace_python.plugins.secrets import (
    DEFAULT_CREDENTIAL_NAMES,
    DEFAULT_PATTERNS,
    SecretDetector,
    SecretPattern,
    config_literals,
)


class ConfigSecrets(SecretDetector, ProjectPlugin):
    name: ClassVar[str] = "config-secrets"
    patterns: ClassVar[tuple[SecretPattern, ...]] = DEFAULT_PATTERNS
    credential_names: ClassVar[tuple[str, ...]] = DEFAULT_CREDENTIAL_NAMES

    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        return ()

    def analyze_project(self, ctx: ProjectContext) -> Sequence[Finding]:
        if ctx.root is None:
            return ()
        findings: list[Finding] = []
        for value, name, span, function in config_literals(ctx.root):
            finding = self.judge(value, name, span, function)
            if finding is not None:
                findings.append(finding)
        return findings
