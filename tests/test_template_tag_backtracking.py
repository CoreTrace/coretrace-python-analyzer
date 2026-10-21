"""Acceptance tests for issue #263: the escaping inspection of a template ends, whatever
the file under a ``templates`` directory holds.

``_START_TAG`` could split a run of attribute-name characters, or of an unquoted value,
between consecutive attributes in exponentially many ways, and tried them all when no
``>`` followed: a few dozen characters, in a text template or a binary file decoded with
replacement characters, stopped the analysis. Each inspection runs here in a subprocess
with a timeout, so that one that does not end fails instead of hanging the suite. The
inspection still refuses to establish escaping where a variable stands in a dangerous
attribute, however long what comes before it.

Start tags are read as the HTML tokenizer reads them. A tag a template leaves open at its
end runs, once the template is included, into the markup that follows: its attributes
are checked like any other's.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

# A run long enough that no exponential inspection would ever end; a linear one takes
# milliseconds.
RUN = 5000
TIMEOUT = 60

ESCAPED_TEMPLATES = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "from coretrace_python.taint.templates import escaped_templates\n"
    "print(json.dumps(sorted(escaped_templates(Path(sys.argv[1])))))\n"
)


def escaped(tmp_path: Path, files: dict[str, str | bytes]) -> list[str]:
    """The names of the templates ``escaped_templates`` establishes for a project of
    ``files``, computed in a subprocess with a timeout."""

    root = tmp_path / "project"
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    try:
        completed = subprocess.run(
            [sys.executable, "-c", ESCAPED_TEMPLATES, str(root)],
            capture_output=True,
            text=True,
            check=True,
            timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"the inspection did not end within {TIMEOUT} s")
    names: list[str] = json.loads(completed.stdout)
    return names


@pytest.mark.parametrize(
    "template",
    [
        "<p><a " + "b" * RUN + "</p>",
        "<a " + "b" * RUN + '"',
        "<a " + "b" * RUN,
        "<a b=" + "c" * RUN + '"',
    ],
    ids=["name-run-in-text", "name-run-then-quote", "name-run-at-the-end", "unquoted-value-run-then-quote"],
)
def test_a_tag_that_never_closes_is_inspected_to_the_end(tmp_path: Path, template: str) -> None:
    # No variable is printed, so the template escapes.
    assert escaped(tmp_path, {"app/templates/page.html": template}) == ["page.html"]


def test_a_binary_file_under_templates_does_not_stop_the_inspection(tmp_path: Path) -> None:
    # Invalid UTF-8 decodes to replacement characters, which may form attribute names.
    image = b"\x89PNG\r\n\x1a\n" + b"<a " + b"\xb5" * RUN + b'"'
    files: dict[str, str | bytes] = {
        "app/templates/images/thumbnail.png": image,
        "app/templates/page.html": "<p>{{ name }}</p>",
    }

    assert "page.html" in escaped(tmp_path, files)


@pytest.mark.parametrize(
    "template",
    [
        "<a " + "b" * RUN + " onclick=\"go('{{ name }}')\">x</a>",
        "<div " + "b" * RUN + " title={{ name }}>x</div>",
        "<a b=" + "c" * RUN + ' href="{{ url }}">x</a>',
        "<a title=\"x\"onclick=\"go('{{ name }}')\">x</a>",
        "<div " + "b" * RUN + " {{ attributes }}>x</div>",
    ],
    ids=["event-handler", "unquoted-value", "url-attribute", "handler-right-after-a-quoted-value", "attribute-name"],
)
def test_a_variable_in_a_dangerous_attribute_after_a_long_run_is_still_refused(tmp_path: Path, template: str) -> None:
    assert escaped(tmp_path, {"app/templates/page.html": template}) == []


def test_a_variable_in_a_quoted_attribute_after_a_long_run_is_still_escaped(tmp_path: Path) -> None:
    template = "<a " + "b" * RUN + ' title="{{ name }}">x</a>'

    assert escaped(tmp_path, {"app/templates/page.html": template}) == ["page.html"]


@pytest.mark.parametrize(
    ("template", "names"),
    [
        ("<p>Hello</p><a onclick=\"go('{{ name }}')\"", []),
        ("<p>Hello</p><a title={{ name }}", []),
        ("<p>Hello</p><a {{ name }}", []),
        ('<p>Hello</p><a title="{{ name }}"', ["page.html"]),
    ],
    ids=["event-handler", "unquoted-value", "attribute-name", "quoted-title"],
)
def test_a_tag_left_open_at_the_end_has_its_attributes_checked(tmp_path: Path, template: str, names: list[str]) -> None:
    assert escaped(tmp_path, {"app/templates/page.html": template}) == names


@pytest.mark.parametrize(
    ("template", "names"),
    [
        # After a stray ``/``, the variable starts an attribute name.
        ("<a/{{ name }}>x</a>", []),
        # An attribute name may begin with ``=``: here ``="`` and the variable.
        ('<div ="{{ name }}">x</div>', []),
        # ``=`` is an attribute of its own, and ``title`` a quoted one after it.
        ('<div = title="{{ name }}">x</div>', ["page.html"]),
    ],
    ids=["after-a-slash", "name-beginning-with-equals", "equals-then-quoted-title"],
)
def test_attributes_are_read_as_a_browser_reads_them(tmp_path: Path, template: str, names: list[str]) -> None:
    assert escaped(tmp_path, {"app/templates/page.html": template}) == names
