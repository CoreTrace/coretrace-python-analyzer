"""Acceptance tests for issue #279: the filters a template's render reaches are collected
once for each template and set of blocks the templates extending it override.

They are the same as before, in the same order: which filters, where they stand, the
template applying each, and the names of the render reaching its value and argument. The
results are kept for one analysis only, so that projects analysed one after the other do
not share them. A result cut short by a cycle of includes is not reused, nor one that
went through a template already on the way, where the walk would be cut.
"""

from __future__ import annotations

import itertools
import json
import random
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from coretrace_python.interprocedural import TemplateFilter, discover_files
from coretrace_python.source import SourceId
from coretrace_python.taint import templates
from coretrace_python.taint.templates import project_templates

TIMEOUT = 60
FILTERS = "python.django.template.defaultfilters"


def write(root: Path, templates: dict[str, str]) -> Path:
    for name, text in templates.items():
        path = root / "app" / "templates" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def described(root: Path) -> dict[str, list[tuple[str, str, int, int, str, tuple[str, ...], tuple[str, ...]]]]:
    """Each template's filters, in order: the function, the file and the line and column it
    is applied at, the template applying it, and the names reaching its value and argument."""

    return {
        name: [
            (
                str(f.symbol),
                Path(str(f.location.source_id)).name,
                f.location.start_line,
                f.location.start_column,
                f.template,
                f.value,
                f.argument,
            )
            for f in found
        ]
        for name, found in project_templates(root).filters.items()
    }


FIRST = {"page.html": "{{ bio|striptags }}\n{% include 'part.html' with note=bio %}\n", "part.html": "<p>{{ note|upper }}</p>\n"}
FIRST_FILTERS = {
    "page.html": [
        (f"{FILTERS}.striptags", "page.html", 1, 8, "page.html", ("bio",), ()),
        (f"{FILTERS}.upper", "part.html", 1, 12, "part.html", ("bio",), ()),
    ],
    "part.html": [(f"{FILTERS}.upper", "part.html", 1, 12, "part.html", ("note",), ())],
}
# The same names, other templates.
SECOND = {"page.html": "{% include 'part.html' %}\n{{ title|lower }}\n", "part.html": "{{ other|title }}\n"}
SECOND_FILTERS = {
    "page.html": [
        (f"{FILTERS}.lower", "page.html", 2, 10, "page.html", ("title",), ()),
        (f"{FILTERS}.title", "part.html", 1, 10, "part.html", ("other",), ()),
    ],
    "part.html": [(f"{FILTERS}.title", "part.html", 1, 10, "part.html", ("other",), ())],
}


def test_projects_analysed_one_after_the_other_each_get_their_own_filters(tmp_path: Path) -> None:
    first, second, again = (write(tmp_path / key, files) for key, files in (("first", FIRST), ("second", SECOND), ("again", FIRST)))

    assert described(first) == FIRST_FILTERS
    assert described(second) == SECOND_FILTERS
    assert described(again) == FIRST_FILTERS
    assert described(second) == SECOND_FILTERS


def test_a_template_reached_directly_and_through_a_child_overriding_its_block(tmp_path: Path) -> None:
    # child.html renders base.html with its own body: base.html's upper is not reached
    # through it, though it is through the direct include.
    root = write(
        tmp_path,
        {
            "base.html": "{% block body %}{{ a|upper }}{% endblock %}{{ b|lower }}\n",
            "child.html": "{% extends 'base.html' %}{% block body %}{{ c|title }}{% endblock %}\n",
            "page.html": "{% include 'base.html' %}{% include 'child.html' %}\n",
        },
    )

    assert described(root) == {
        "base.html": [
            (f"{FILTERS}.upper", "base.html", 1, 22, "base.html", ("a",), ()),
            (f"{FILTERS}.lower", "base.html", 1, 49, "base.html", ("b",), ()),
        ],
        "child.html": [
            (f"{FILTERS}.title", "child.html", 1, 47, "child.html", ("c",), ()),
            (f"{FILTERS}.lower", "base.html", 1, 49, "base.html", ("b",), ()),
        ],
        "page.html": [
            (f"{FILTERS}.upper", "base.html", 1, 22, "base.html", ("a",), ()),
            (f"{FILTERS}.lower", "base.html", 1, 49, "base.html", ("b",), ()),
            (f"{FILTERS}.title", "child.html", 1, 47, "child.html", ("c",), ()),
        ],
    }


def test_a_template_reached_inside_a_cycle_and_from_outside_it(tmp_path: Path) -> None:
    # a.html is walked first: inside it, b.html's walk stops at a.html and misses its
    # upper. c.html reaches b.html from outside the cycle, and gets a.html's upper.
    root = write(
        tmp_path,
        {
            "a.html": "{{ x|upper }}{% include 'b.html' %}\n",
            "b.html": "{{ y|lower }}{% include 'a.html' %}\n",
            "c.html": "{% include 'b.html' %}\n",
        },
    )

    assert described(root) == {
        "a.html": [(f"{FILTERS}.upper", "a.html", 1, 6, "a.html", ("x",), ()), (f"{FILTERS}.lower", "b.html", 1, 6, "b.html", ("y",), ())],
        "b.html": [(f"{FILTERS}.lower", "b.html", 1, 6, "b.html", ("y",), ()), (f"{FILTERS}.upper", "a.html", 1, 6, "a.html", ("x",), ())],
        "c.html": [(f"{FILTERS}.lower", "b.html", 1, 6, "b.html", ("y",), ()), (f"{FILTERS}.upper", "a.html", 1, 6, "a.html", ("x",), ())],
    }


COUNT_FILTERS = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "from coretrace_python.taint.templates import project_templates\n"
    "print(json.dumps({name: len(found) for name, found in project_templates(Path(sys.argv[1])).filters.items()}))\n"
)


def test_includes_doubled_at_every_level_are_walked_in_linear_time(tmp_path: Path) -> None:
    # Followed path by path, level30.html leads to level0.html 2 ** 30 times.
    templates = {"level0.html": "{{ name|upper }}"}
    for level in range(1, 31):
        templates[f"level{level}.html"] = f"{{% include 'level{level - 1}.html' %}}" * 2
    root = write(tmp_path, templates)
    try:
        completed = subprocess.run(
            [sys.executable, "-c", COUNT_FILTERS, str(root)], capture_output=True, text=True, check=False, timeout=TIMEOUT
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"the walk did not end within {TIMEOUT} s")

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {name: 1 for name in templates}


# A child extending a parent that includes it back, inside the block the child overrides.
# The walk of the parent includes the child, whose extends leads back to the parent: a
# cycle, cut there. Whichever of the two is walked first, each gets the filters of main.
def cycle_through_an_overridden_block(child: str, parent: str) -> dict[str, str]:
    return {
        child: "{% extends '" + parent + "' %}\n{% block body %}{{ v|upper }}{% endblock %}\n",
        parent: "{{ v|striptags }}\n{% block body %}{% include '" + child + "' with v=other %}{% endblock %}\n",
    }


@pytest.mark.parametrize(
    ("child", "parent"), [("a.html", "b.html"), ("b.html", "a.html")], ids=["child-walked-first", "parent-walked-first"]
)
def test_a_child_its_parent_includes_back_gets_the_same_filters_whichever_is_walked_first(
    tmp_path: Path, child: str, parent: str
) -> None:
    root = write(tmp_path, cycle_through_an_overridden_block(child, parent))

    assert described(root) == {
        child: [
            (f"{FILTERS}.upper", child, 2, 22, child, ("v",), ()),
            (f"{FILTERS}.striptags", parent, 1, 6, parent, ("v",), ()),
        ],
        parent: [
            (f"{FILTERS}.striptags", parent, 1, 6, parent, ("v",), ()),
            (f"{FILTERS}.upper", child, 2, 22, child, ("other",), ()),
        ],
    }


def path_by_path(
    name: str,
    files: dict[str, list[Path]],
    read: dict[Path, Any],
    visiting: frozenset[str],
    overridden: frozenset[str] = frozenset(),
) -> Iterator[tuple[Any, ...]]:
    """The walk of main, every path through includes and extends followed, a cycle cut at
    a template already on the way: the reference the walk of the engine must equal."""

    paths = files.get(name, [])
    if len(paths) != 1 or paths[0] not in read or name in visiting:
        return
    template = read[paths[0]]
    for application in template.applications:
        if template.rendered(application.blocks, overridden):
            yield application.symbol, application.span, name, application.value, application.argument
    for reference in template.references:
        if reference.name is None:
            continue
        if reference.extends:
            found = path_by_path(reference.name, files, read, visiting | {name}, overridden | template.replaced)
        elif template.rendered(reference.blocks, overridden):
            found = path_by_path(reference.name, files, read, visiting | {name})
        else:
            continue
        for symbol, span, where, value, argument in found:
            yield symbol, span, where, reference.maps(value), reference.maps(argument)


def reference_filters(root: Path) -> dict[str, list[TemplateFilter]]:
    """The filters of each template, as project_templates gives them, from the walk of main."""

    found = {path: tuple(templates._names(path.relative_to(root).parts)) for path in discover_files(root)}
    libraries = templates._libraries(found)
    paths = sorted(path for path, names in found.items() if names)
    files: dict[str, list[Path]] = {}
    for path in paths:
        for name in found[path]:
            files.setdefault(name, []).append(path)
    read = {path: templates._read_scopes(text, SourceId(str(path)), libraries) for path in paths if (text := templates._text(path))}
    return {
        name: list(
            dict.fromkeys(
                TemplateFilter(symbol, span, where, tuple(sorted(value)), tuple(sorted(argument)))
                for symbol, span, where, value, argument in path_by_path(name, files, read, frozenset())
            )
        )
        for name in files
    }


NAMES = [f"t{index}.html" for index in range(4)]


def generated(rng: random.Random, fresh: Iterator[str], depth: int = 0) -> str:
    """Markup applying filters, including other templates, inside blocks of two names and
    outside them. An include binds the variable to a name of its own, so that what reaches
    a filter tells the paths apart."""

    pieces: list[Callable[[], str]] = [
        lambda: "{{ v|upper }}",
        lambda: "{{ v|striptags }}",
        lambda: "{% include '" + rng.choice(NAMES) + "' %}",
        lambda: "{% include '" + rng.choice(NAMES) + "' with v=" + next(fresh) + " %}",
    ]
    if depth < 2:
        block = rng.choice(["body", "side"])
        pieces.append(lambda: "{% block " + block + " %}" + generated(rng, fresh, depth + 1) + "{% endblock %}")
    return "".join(rng.choice(pieces)() for _ in range(rng.randint(1, 3)))


def test_the_walk_gives_the_filters_of_main_on_inheritance_overridden_blocks_and_cycles(tmp_path: Path) -> None:
    """Generated projects of four templates extending and including one another, cycles
    among them, each walked by the engine and by the walk of main, path by path."""

    rng = random.Random(279)
    for index in range(1_500):
        fresh = (f"n{number}" for number in itertools.count())
        texts = {}
        for name in NAMES:
            extends = "{% extends '" + rng.choice(NAMES) + "' %}" if rng.random() < 0.5 else ""
            texts[name] = extends + generated(rng, fresh) + "\n"
        root = write(tmp_path / str(index), texts)
        filters = project_templates(root).filters

        assert {name: list(found) for name, found in filters.items()} == reference_filters(root), texts
