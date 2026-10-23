"""Acceptance tests for issue #278: every continuation of a comment holding template tags.

Rendered, such a comment may end at any of its tags, an include closing it or a condition
leaving out its opener, or run to its close when its tags render nothing. The reading
resumed after its first tag (#272) is kept. At every other point where a reading may
resume, right after each later tag of the comment and right after its close, that reading
must be in HTML data, where every other continuation reads what it reads; elsewhere, the
template is refused. Each inspection and analysis runs in a subprocess with a timeout, so
that one that does not end fails instead of hanging the suite.
"""

from __future__ import annotations

import itertools
import json
import random
import subprocess
import sys
from functools import cache
from pathlib import Path

import pytest

TIMEOUT = 60
# Far beyond what a quadratic reading reads within the timeout; a linear one takes about a
# second.
SIZE = 3_000_000

ESCAPED_TEMPLATES = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "from coretrace_python.taint.templates import escaped_templates\n"
    "print(json.dumps(sorted(escaped_templates(Path(sys.argv[1])))))\n"
)

VIEW = (
    "from django.http import HttpRequest, HttpResponse\n"
    "from django.template.loader import render_to_string\n\n"
    "def page(request: HttpRequest):\n"
    "    return HttpResponse(render_to_string('page.html', {'name': request.GET['name']}))\n"
)


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{command[1:3]} did not end within {TIMEOUT} s")


def project(tmp_path: Path, templates: dict[str, str]) -> Path:
    """A project rendering ``page.html`` with the request's ``name``; a template given by
    its name lies under ``app/templates``, one given by a path under that path."""

    root = tmp_path / "project"
    (root / "app" / "templates").mkdir(parents=True, exist_ok=True)
    (root / "app" / "views.py").write_text(VIEW, encoding="utf-8")
    for name, content in templates.items():
        path = root / name if "/templates/" in name else root / "app" / "templates" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def escaped(tmp_path: Path, templates: dict[str, str]) -> list[str]:
    completed = run([sys.executable, "-c", ESCAPED_TEMPLATES, str(project(tmp_path, templates))])
    assert completed.returncode == 0, completed.stderr
    names: list[str] = json.loads(completed.stdout)
    return names


def xss(tmp_path: Path, templates: dict[str, str]) -> list[tuple[str, int]]:
    root = project(tmp_path, templates)
    completed = run([sys.executable, "-m", "coretrace_python", "--check", str(root), "--format", "json"])
    findings = json.loads(completed.stdout)["findings"]
    return [(f["location"]["path"], f["location"]["line"]) for f in findings if f["rule_id"] == "xss"]


# The reproduction of #278, rendered with Django 5.1.15 and run in Chrome 155: the comment
# runs to the "-->" in the title, and the variable after it names a tag.
def test_a_comment_closed_inside_an_attribute_after_its_tags_is_cross_site_scripting(tmp_path: Path) -> None:
    templates = {"page.html": '<!--{% if debug %}{% endif %}<a title="--><{{ name }}">x</a>\n'}

    assert xss(tmp_path, templates) == [("app/views.py", 5)]


@pytest.mark.parametrize(
    "template",
    [
        '<!--{% if debug %}{% endif %}<a title="--><{{ name }}">x</a>\n',
        '<!-- {% if a %}x <a title="y {% endif %} z">{{ name }} -->\n',
    ],
    ids=["close-inside-a-title", "later-tag-inside-a-title"],
)
def test_a_comment_resuming_elsewhere_than_in_html_data_is_not_established(tmp_path: Path, template: str) -> None:
    assert escaped(tmp_path, {"page.html": template}) == []


@pytest.mark.parametrize(
    "template",
    [
        "<!-- {% if a %} note {% endif %} -->\n",
        "<!-- {% if a %} note {% endif %} --><p>{{ name }}</p>\n",
        '<!-- <div class="{% if a %}x{% endif %}"> -->\n',
        '<p>hello</p><!-- {{ name }} <a onclick="{{ name }}"> -->\n',
    ],
    ids=["tags-around-text", "variable-after-the-comment", "tags-in-a-class", "no-tag"],
)
def test_a_comment_resuming_in_html_data_everywhere_stays_established(tmp_path: Path, template: str) -> None:
    assert escaped(tmp_path, {"page.html": template}) == ["page.html"]


def test_an_include_of_a_name_two_files_have_anywhere_in_a_comment_is_refused(tmp_path: Path) -> None:
    # The tag before it may render nothing: the include then stands inside the comment.
    templates = {
        "part.html": "x\n",
        "other/templates/part.html": "y\n",
        "page.html": "<!-- {% if a %} {% include 'part.html' %} -->\n",
    }

    assert escaped(tmp_path, templates) == ["part.html"]


def test_a_comment_holding_tags_left_open_does_not_end_in_html_data(tmp_path: Path) -> None:
    # Its tags may render nothing: the comment then hides what follows the include.
    templates = {
        "part.html": "x\n",
        "other/templates/part.html": "y <!-- {% if a %}{% endif %}",
        "page.html": "<div>{% include 'part.html' %}</div>\n",
    }

    assert escaped(tmp_path, templates) == ["part.html"]


@pytest.mark.parametrize(
    "shape",
    [
        "tags-in-one-open-comment",
        "tags-in-one-closed-comment",
        "tag-then-open-start-tag",
        "tag-then-open-script",
        "comments-with-tags-in-titles",
    ],
)
def test_the_points_of_resumption_keep_the_reading_linear(tmp_path: Path, shape: str) -> None:
    template = {
        "tags-in-one-open-comment": "<!--" + "{% if x %}" * (SIZE // 10),
        "tags-in-one-closed-comment": "<!--" + "{% if x %}x" * (SIZE // 11) + "-->",
        "tag-then-open-start-tag": "<!--{% if x %}<a " * (SIZE // 17),
        "tag-then-open-script": "<!--{% if x %}<script>" * (SIZE // 22),
        "comments-with-tags-in-titles": '<!--{% if x %}<a title="{% if y %}">-->' * (SIZE // 38),
    }[shape]

    escaped(tmp_path, {"page.html": template})


# Pieces of a template's markup as the reader sees it: markup, a variable, a template tag
# and an inserted markup (#273).
OUTPUT, TAG, INSERTED = "\x00", "\x01", "\x02"
PIECES = ["<!--", "-->", "<!-->", "--!>", TAG, OUTPUT, '<a title="', '<a onclick="', '"', ">", "<script>", "</script>", "x", " ", "<", "</a", INSERTED]


def every_continuation_accepted(html: str) -> bool:
    """The reading of ``html`` that follows every continuation of each comment holding
    template tags: from each of its tags, and from its close. Its cost is not linear;
    it is the reference the reading of the engine must never be more lenient than."""

    from coretrace_python.taint import templates

    @cache
    def from_position(position: int) -> bool:
        while (start := html.find("<", position)) != -1:
            if html.startswith("<!--", start):
                close = templates._COMMENT_END.search(html, start + 2)
                hidden_to = len(html) if close is None else close.start()
                if INSERTED in html[start + 4 : hidden_to]:
                    return False
                tags = [index for index in range(start + 4, hidden_to) if html[index] == TAG]
                if not all(from_position(tag + 1) for tag in tags):
                    return False
                if close is None:
                    return True
                position = close.end()
            elif raw := templates._RAW_TEXT.match(html, start):
                if OUTPUT in raw.group(2) or INSERTED in raw.group(0) or not templates._attributes_escape(html[start : raw.start(2)]):
                    return False
                position = raw.end()
            elif tag := templates._START_TAG.match(html, start):
                if OUTPUT in tag.group(1) or INSERTED in tag.group(0) or not templates._attributes_escape(tag.group(2)):
                    return False
                position = tag.end()
            elif end := templates._END_TAG.match(html, start):
                if OUTPUT in end.group(0) or INSERTED in end.group(0):
                    return False
                position = end.end()
            elif templates._NAMED_BY_OUTPUT.match(html, start) or templates._OPENED_BY_INSERTION.match(html, start):
                return False
            else:
                position = start + 1
        return True

    return from_position(0)


def test_the_reading_accepts_no_text_a_reading_of_every_continuation_refuses() -> None:
    """Checked on every text of up to four pieces, and on random longer ones."""

    from coretrace_python.taint import templates

    rng = random.Random(278)
    texts = [
        *("".join(pieces) for length in range(5) for pieces in itertools.product(PIECES, repeat=length)),
        *("".join(rng.choice(PIECES) for _ in range(rng.randint(5, 14))) for _ in range(30_000)),
    ]
    refused_by_the_reference = 0
    for text in texts:
        accepted = templates._read_markup(text).escapes
        reference = every_continuation_accepted(text)
        refused_by_the_reference += not reference
        assert reference or not accepted, text
    assert refused_by_the_reference
