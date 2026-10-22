"""What a rule checks, for a report to explain its findings.

A title and a description, as a SARIF consumer shows them (``shortDescription`` and
``fullDescription``). Whoever defines a rule describes it: a plugin those it reports
(``Plugin.rules``), the engine its own (``engine.ENGINE_RULES``).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleDescription:
    title: str
    description: str
