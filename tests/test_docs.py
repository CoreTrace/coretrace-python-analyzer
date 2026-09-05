"""Acceptance tests for the usage documentation.

``docs/usage.md`` documents the command line: every option of the parser, every rule the
shipped plugins can report, the report formats and the exit codes. ``docs/plugins.md``
documents how to write a plugin: the manifest, every base class and every model kind the
plugin API exports. The README points at both, and every command the guides show uses
options that exist.

Expected to remain red until ``docs/usage.md`` and ``docs/plugins.md`` exist.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from coretrace_python import cli, engine, plugins, taint

REPO = Path(__file__).resolve().parent.parent
USAGE = REPO / "docs" / "usage.md"
PLUGINS = REPO / "docs" / "plugins.md"
README = REPO / "README.md"


@pytest.fixture(autouse=True)
def require_docs() -> None:
    missing = [path.name for path in (USAGE, PLUGINS) if not path.is_file()]
    if missing:
        pytest.fail(f"usage documentation is not written yet: {missing}")


def options() -> set[str]:
    parser = cli.build_parser()
    return {
        option
        for action in parser._actions
        for option in action.option_strings
        if option.startswith("--")
    }


def shipped_rules() -> set[str]:
    rules: set[str] = set()
    for path in (REPO / "src" / "coretrace_python").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        rules.update(re.findall(r'rule_id(?:: ClassVar\[str\])?\s*=\s*"([a-z-]+)"', text))
        rules.update(re.findall(r'Finding\(\s*"([a-z]+-[a-z-]+)"', text))
        rules.update(re.findall(r'_note\("([a-z-]+)"', text))
    return rules - {"message"}


def test_usage_documents_every_option_rule_format_and_exit_code() -> None:
    text = USAGE.read_text(encoding="utf-8")
    assert all(option in text for option in options()), options() - {o for o in options() if o in text}
    assert shipped_rules() <= set(re.findall(r"`([a-z-]+)`", text)), shipped_rules() - set(
        re.findall(r"`([a-z-]+)`", text)
    )
    assert len(shipped_rules()) >= 20
    assert all(f"`{fmt}`" in text for fmt in ("text", "json", "sarif"))
    assert "exit status" in text.lower()


def test_usage_commands_only_use_existing_options() -> None:
    text = USAGE.read_text(encoding="utf-8")
    commands = re.findall(r"^\s*coretrace-python-analyzer (.*)$", text, re.MULTILINE)
    assert len(commands) >= 5
    for command in commands:
        used = set(re.findall(r"(--[a-z-]+)", command))
        assert used <= options(), command


def test_plugin_guide_documents_the_manifest_base_classes_and_models() -> None:
    text = PLUGINS.read_text(encoding="utf-8")
    for field in ("name", "version", "plugin_api", "requires", "provides", "entrypoint"):
        assert f"`{field}`" in text
    for base in ("Plugin", "ModelPlugin", "ProjectPlugin", "SymbolCallDetector", "TaintDetector", "SecretDetector"):
        assert base in plugins.__all__ and f"`{base}`" in text
    for model in ("Source", "Sink", "Sanitizer", "EntryPoint", "TypedParameter", "NamedParameter",
                  "RouteRegistrar", "SuffixSink", "Validator", "AuthorizationGuard"):
        assert hasattr(taint, model) and re.search(rf"`{model}\b", text), model
    assert all(kind.name in text for kind in taint.TaintKind if kind.name not in {"NONE", "ALL"})
    assert "--plugins" in text and "plugin.toml" in text


def test_every_bundled_plugin_is_named_in_the_guides() -> None:
    text = USAGE.read_text(encoding="utf-8") + PLUGINS.read_text(encoding="utf-8")
    names = [
        re.search(r'^name = "([a-z-]+)"', manifest.read_text(encoding="utf-8"), re.MULTILINE).group(1)  # type: ignore[union-attr]
        for manifest in engine.BUNDLED_PLUGINS.rglob("plugin.toml")
    ]
    assert len(names) == 26
    assert all(f"`{name}`" in text for name in names), [n for n in names if f"`{n}`" not in text]


def test_readme_links_to_both_guides() -> None:
    text = README.read_text(encoding="utf-8")
    assert "docs/usage.md" in text and "docs/plugins.md" in text
