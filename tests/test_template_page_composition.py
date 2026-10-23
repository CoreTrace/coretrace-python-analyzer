"""Acceptance tests for issue #273: a page is read as Django puts it together.

A ``{% block %}`` takes the definition the rendered page gives it, which may stand in the
parent's ``<script>``; an ``{% include %}`` puts the included template's markup where it
stands, which may be inside an attribute value and end it. Each template file read on
its own sees neither, so each page is also put together, its blocks and includes in
place, and read once. Each inspection and analysis runs in a subprocess with a timeout,
so that one that does not end fails instead of hanging the suite.
"""

from __future__ import annotations

import itertools
import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

TIMEOUT = 60

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


BASE_WITH_SCRIPT_BLOCK = "<html><head><script>{% block js %}{% endblock %}</script></head><body>{% block body %}{% endblock %}</body></html>\n"


# The reproductions of #273, rendered with Django 5.1.15: the variable runs as script in
# F, as an event handler in H, and in H's variant when other/templates comes first.
@pytest.mark.parametrize(
    "templates",
    [
        {
            "base.html": "<html><head><script>{% block js %}{% endblock %}</script></head><body></body></html>\n",
            "page.html": "{% extends 'base.html' %}{% block js %}var name = {{ name }};{% endblock %}\n",
        },
        {"page.html": '<a title="{% include "q.html" %}{{ name }}">x</a>\n', "q.html": '" onclick="\n'},
        {
            "page.html": '<a title="{% include "q.html" %}{{ name }}">x</a>\n',
            "q.html": "quote: \n",
            "other/templates/q.html": '" onclick="\n',
        },
    ],
    ids=["F-block-inside-parent-script", "H-include-inside-attribute-value", "H-include-of-a-name-two-files-have"],
)
def test_markup_a_block_or_an_include_puts_inside_a_construct_is_read_there(
    tmp_path: Path, templates: dict[str, str]
) -> None:
    assert xss(tmp_path, templates) == [("app/views.py", 5)]


def test_only_the_page_printing_inside_the_parent_script_is_refused(tmp_path: Path) -> None:
    templates = {
        "base.html": BASE_WITH_SCRIPT_BLOCK,
        "page.html": "{% extends 'base.html' %}{% block body %}<p>{{ name }}</p>{% endblock %}\n",
        "inert.html": "{% extends 'base.html' %}{% block js %}var count = 1;{% endblock %}\n",
        "script.html": "{% extends 'base.html' %}{% block js %}var name = {{ name }};{% endblock %}\n",
    }

    assert escaped(tmp_path, templates) == ["base.html", "inert.html", "page.html"]


@pytest.mark.parametrize(
    "templates",
    [
        {
            "base.html": '<body class="{% block bodyclass %}{% endblock %}">{% block content %}{% endblock %}</body>\n',
            "page.html": "{% extends 'base.html' %}{% block bodyclass %}{{ name }} change-form{% endblock %}\n",
        },
        {
            "base.html": "<script>{% block js %}var count = 1;{% endblock %}</script>\n",
            "page.html": "{% extends 'base.html' %}{% block js %}{{ block.super }} var total = 2;{% endblock %}\n",
        },
        {"page.html": '<a title="{% include "q.html" %}{{ name }}">x</a>\n', "q.html": "prefix \n"},
        {
            "base.html": "<p>{% block body %}{% endblock %}</p>\n",
            "middle.html": "{% extends 'base.html' %}{% block body %}<b>{% block inner %}{% endblock %}</b>{% endblock %}\n",
            "page.html": "{% extends 'middle.html' %}{% block inner %}{{ name }}{% endblock %}\n",
        },
    ],
    ids=["variable-in-a-quoted-class", "block-super-in-a-script", "include-without-a-quote-in-a-title", "nested-blocks"],
)
def test_a_page_whose_parts_stay_escaped_once_put_together_is_established(
    tmp_path: Path, templates: dict[str, str]
) -> None:
    assert escaped(tmp_path, templates) == sorted(templates)


@pytest.mark.parametrize(
    "templates",
    [
        {
            "page.html": "{% include 'self.html' %}",
            "self.html": '<a title="{% if more %}{% include \'self.html\' %}{% endif %}{{ name }}">x</a>',
        },
        {
            "page.html": "{% include 'a.html' %}",
            "a.html": "<script>{% if more %}{% include 'b.html' %}{% endif %}</script>",
            "b.html": "{{ name }}{% include 'a.html' %}",
        },
    ],
    ids=["itself-inside-an-attribute", "through-another-inside-a-script"],
)
def test_a_template_including_itself_inside_a_construct_is_not_established(
    tmp_path: Path, templates: dict[str, str]
) -> None:
    # Rendered twice, self.html puts an <a title="…"> inside the title it is in, whose quote
    # ends that title before the variable; b.html's variable lands inside a.html's script.
    assert escaped(tmp_path, templates) == []


def test_a_page_beyond_eight_mebibytes_is_not_established(tmp_path: Path) -> None:
    # level{n}.html holds 2 ** n characters once put together: level23.html is 8 MiB,
    # level24.html beyond, and the page including it is put together no further.
    templates = {"level0.html": "x"}
    for level in range(1, 25):
        templates[f"level{level}.html"] = f"{{% include 'level{level - 1}.html' %}}" * 2
    templates["page.html"] = "{% include 'level24.html' %}"

    assert escaped(tmp_path, templates) == sorted(f"level{level}.html" for level in range(24))


# Two files give part.html. Django renders the first its loaders find, which the analyzer
# does not know: the include stands for each of them.
def test_an_include_of_a_name_two_files_have_is_established_in_html_data(tmp_path: Path) -> None:
    templates = {
        "part.html": "<p>{{ name }}</p>\n",
        "other/templates/part.html": "<span>x</span>\n",
        "page.html": "<div>{% include 'part.html' %}</div>\n",
    }

    assert escaped(tmp_path, templates) == ["page.html", "part.html"]


@pytest.mark.parametrize(
    "page",
    [
        '<a title="{% include "part.html" %}">x</a>',
        "<a {% include 'part.html' %}>x</a>",
        "<{% include 'part.html' %}>",
        "</{% include 'part.html' %}>",
        "<script>{% include 'part.html' %}</script>",
        "<style>{% include 'part.html' %}</style>",
        "<!-- {% include 'part.html' %} -->",
        "<!{% include 'part.html' %}",
        "<!-{% include 'part.html' %}",
    ],
    ids=["attribute-value", "attribute", "tag-name", "end-tag", "script", "style", "comment", "after-bang", "after-bang-dash"],
)
def test_an_include_of_a_name_two_files_have_is_refused_outside_html_data(tmp_path: Path, page: str) -> None:
    # Both files are harmless here: what matters is that either could end the construct.
    templates = {"part.html": "x\n", "other/templates/part.html": "y\n", "page.html": page}

    assert escaped(tmp_path, templates) == ["part.html"]


@pytest.mark.parametrize(
    "other",
    ["<script>\n", "<!-- note", "x <", "<!-", "</"],
    ids=["construct", "comment", "less-than", "comment-opener", "end-tag-opener"],
)
def test_an_include_of_a_name_two_files_have_needs_each_to_end_in_html_data(tmp_path: Path, other: str) -> None:
    templates = {"part.html": "x\n", "other/templates/part.html": other, "page.html": "<div>{% include 'part.html' %}</div>\n"}

    assert escaped(tmp_path, templates) == ["part.html"]



# Two files give base.html: the page is put together with each.
@pytest.mark.parametrize(
    ("other", "expected"),
    [
        ("<div>{% block body %}{% endblock %}</div>\n", ["base.html", "page.html"]),
        ("<script>{% block body %}{% endblock %}</script>\n", ["base.html"]),
    ],
    ids=["each-escapes", "one-runs-the-block-as-script"],
)
def test_a_page_extending_a_name_two_files_have_must_escape_with_each(
    tmp_path: Path, other: str, expected: list[str]
) -> None:
    templates = {
        "base.html": "<p>{% block body %}{% endblock %}</p>\n",
        "other/templates/base.html": other,
        "page.html": "{% extends 'base.html' %}{% block body %}{{ name }}{% endblock %}\n",
    }

    assert escaped(tmp_path, templates) == expected


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        ("<div>{% include 'widget.html' %}</div>\n", ["base.html", "page.html", "widget.html"]),
        ('<a title="{% include \'widget.html\' %}">x</a>\n', ["base.html", "widget.html"]),
    ],
    ids=["in-html-data", "in-an-attribute"],
)
def test_an_include_of_a_template_with_several_pages_stands_for_each(
    tmp_path: Path, page: str, expected: list[str]
) -> None:
    templates = {
        "base.html": "<p>{% block body %}{% endblock %}</p>\n",
        "other/templates/base.html": "<div>{% block body %}{% endblock %}</div>\n",
        "widget.html": "{% extends 'base.html' %}{% block body %}x{% endblock %}",
        "page.html": page,
    }

    assert escaped(tmp_path, templates) == expected


def chain_of_names_two_files_have(levels: int, root: str = "x") -> dict[str, str]:
    # level{n}.html, given by two files, extends level{n - 1}.html: each file of level n
    # renders 2 ** n pages, one for each file each level below it may be.
    templates: dict[str, str] = {}
    for directory in ("app", "other"):
        templates[f"{directory}/templates/level0.html"] = f"{root}{{% block body %}}{{% endblock %}}"
        for level in range(1, levels + 1):
            templates[f"{directory}/templates/level{level}.html"] = (
                f"{{% extends 'level{level - 1}.html' %}}{{% block body %}}{{{{ name }}}}{{% endblock %}}"
            )
    return templates


def test_a_template_rendering_more_than_64_pages_is_not_established(tmp_path: Path) -> None:
    assert escaped(tmp_path, chain_of_names_two_files_have(7)) == [f"level{level}.html" for level in range(7)]


def test_pages_of_a_template_beyond_sixteen_mebibytes_together_are_not_established(tmp_path: Path) -> None:
    # Each of the 64 pages of level6.html holds 300,000 characters: 19.2 million together.
    templates = chain_of_names_two_files_have(6, root="x" * 300_000)

    assert escaped(tmp_path, templates) == [f"level{level}.html" for level in range(6)]



def test_a_template_including_itself_in_html_data_is_established(tmp_path: Path) -> None:
    templates = {
        "page.html": "{% include 'tree.html' %}",
        "tree.html": "<li>{{ name }}<ul>{% if more %}{% include 'tree.html' %}{% endif %}</ul></li>",
    }

    assert escaped(tmp_path, templates) == ["page.html", "tree.html"]


def test_a_template_including_itself_must_end_in_html_data(tmp_path: Path) -> None:
    # Rendered twice, the comment it leaves open runs to the "-->" in the next title, and
    # the variable after it names a tag.
    templates = {"self.html": '{% if more %}{% include \'self.html\' %}{% endif %}<a title="--><{{ name }}"><!--'}

    assert escaped(tmp_path, templates) == []

# Markup, a variable and a template tag, as the reader sees a page.
PIECES = ["x", " ", "<p>", "</p>", "<script>", "</script>", '<a title="', '<a onclick="', '"', ">", "<!--", "-->", "<", "</", "<!", "<!-", "-"]


def test_text_accepted_in_place_of_the_marker_keeps_the_page_accepted() -> None:
    """The marker stands for a text the reader accepts and that ends in HTML data. Where
    the reader accepts the marker, any such text in its place keeps the page accepted,
    and ending in HTML data: a page made of such texts, nested to any depth, is accepted
    whatever the texts, which is why one marker may stand for several files. Checked on
    every text of up to two pieces around the marker, and on random longer ones."""

    from coretrace_python.taint import templates

    pieces = [*PIECES, templates._OUTPUT, templates._TAG]
    rng = random.Random(273)

    def text(low: int, high: int) -> str:
        return "".join(rng.choice(pieces) for _ in range(rng.randint(low, high)))

    def accepted(candidate: str) -> bool:
        reading = templates._read_markup(candidate)
        return reading.escapes and reading.settled

    short = ["", *pieces, *("".join(pair) for pair in itertools.product(pieces, repeat=2))]
    contents = [candidate for candidate in short + [text(3, 6) for _ in range(2_000)] if accepted(candidate)]
    around = [*itertools.product(short, repeat=2), *((text(2, 8), text(2, 8)) for _ in range(20_000))]
    for prefix, suffix in around:
        marked = templates._read_markup(prefix + templates._INSERTED + suffix)
        if not marked.escapes:
            continue
        for content in rng.sample(contents, 8):
            spliced = templates._read_markup(prefix + content + suffix)
            assert spliced.escapes, (prefix, content, suffix)
            assert spliced.settled or not marked.settled, (prefix, content, suffix)


def test_a_text_inserting_itself_is_accepted_only_if_its_unfoldings_are() -> None:
    """A text holding the marker where it inserts itself, accepted and ending in HTML
    data, stays accepted unfolded: the marker replaced by the text's own unfolding, level
    after level, down to the text without it. Checked on every text of up to two pieces
    around the marker."""

    from coretrace_python.taint import templates

    pieces = [*PIECES, templates._OUTPUT, templates._TAG]
    short = ["", *pieces, *("".join(pair) for pair in itertools.product(pieces, repeat=2))]
    for before, after in itertools.product(short, repeat=2):
        reading = templates._read_markup(before + templates._INSERTED + after)
        if not (reading.escapes and reading.settled):
            continue
        unfolded = before + after
        for _ in range(3):
            assert templates._read_markup(unfolded).escapes, (before, after)
            unfolded = before + unfolded + after


# Template pieces around a self-include: unfolded, the include gives way to the template's
# own text, level after level, until the condition around it, if any, no longer holds.
TEMPLATE_PIECES = ["x", " ", "{{ name }}", "<", "<!--", "-->", '<a title="', '"', ">", "</a>", "<script>", "</script>", "{% if c %}", "{% endif %}"]


def test_a_template_including_itself_is_established_only_if_its_unfoldings_are(tmp_path: Path) -> None:
    """For generated templates including themselves, established means every unfolding
    of the recursion, written out as templates including each other down to one that
    includes nothing, is established too."""

    from coretrace_python.taint.templates import escaped_templates

    rng = random.Random(273)
    root = tmp_path / "project"
    directory = root / "app" / "templates"
    directory.mkdir(parents=True)
    count, depth = 3_000, 4
    for index in range(count):
        before = "".join(rng.choice(TEMPLATE_PIECES) for _ in range(rng.randint(0, 3)))
        after = "".join(rng.choice(TEMPLATE_PIECES) for _ in range(rng.randint(0, 3)))
        # Half of them include themselves under a condition, the others without one: a
        # tag after the include would end a comment its markup leaves open.
        opening, closing = ("{% if more %}", "{% endif %}") if index % 2 else ("", "")
        written = {
            f"t{index}.html": f"{{% include 't{index}.html' %}}",
            f"t{index}-0.html": "",
            **{f"t{index}-{level}.html": f"{{% include 't{index}-{level - 1}.html' %}}" for level in range(1, depth)},
        }
        for name, included in written.items():
            (directory / name).write_text(f"{before}{opening}{included}{closing}{after}", encoding="utf-8")
    established = escaped_templates(root)
    recursive = [index for index in range(count) if f"t{index}.html" in established]
    assert recursive
    for index in recursive:
        assert all(f"t{index}-{level}.html" in established for level in range(depth)), index
