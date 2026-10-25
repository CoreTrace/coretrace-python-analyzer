"""Acceptance tests for issues #279 and #284: the filters a template's render reaches are
collected for each template and set of blocks the templates extending it override, in
time linear in the references, and a cycle of includes is not cut (#284).

Where no cycle is reached, they are the same as before, in the same order: which filters,
where they stand, the template applying each, and the names of the render reaching its
value and argument. Through a cycle, a template reached again contributes what it
reaches, as Django renders it when the project's conditions let the cycle turn. The
results are kept for one analysis only, so that projects analysed one after the other do
not share them.
"""

from __future__ import annotations

import itertools
import json
import random
import re
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
# Django renders the parent through the child with that block overridden, which renders
# the child's block instead of the include: the parent's striptags receives other.
# Whichever of the two is walked first, each gets the filters Django applies.
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
            (f"{FILTERS}.striptags", parent, 1, 6, parent, ("other",), ()),
        ],
    }


# The walk path by path lets each cycle turn 2, then 3 times, within this many steps.
REPEATS = (2, 3)
BUDGET = 20_000
# Projects the walk does not settle within its budget: 10 with this seed.
UNVERIFIED = 15


class Unverified(Exception):
    """The walk path by path exceeded its budget: it verifies nothing of the project."""


def unrolled(
    name: str,
    files: dict[str, list[Path]],
    read: dict[Path, Any],
    repeats: int,
    budget: list[int],
    visiting: tuple[tuple[str, frozenset[str]], ...] = (),
    overridden: frozenset[str] = frozenset(),
) -> Iterator[tuple[Any, ...]]:
    """Every path through includes and extends, where each template, with the blocks
    overridden, may come back ``repeats`` times on the way: what Django renders when the
    project's conditions let each cycle turn that many times."""

    paths = files.get(name, [])
    here = (name, overridden)
    if len(paths) != 1 or paths[0] not in read or visiting.count(here) >= repeats:
        return
    budget[0] -= 1
    if budget[0] < 0:
        raise Unverified
    template = read[paths[0]]
    for application in template.applications:
        if template.rendered(application.blocks, overridden):
            yield application.symbol, application.span, name, application.value, application.argument
    for reference in template.references:
        if reference.name is None:
            continue
        if reference.extends:
            found = unrolled(reference.name, files, read, repeats, budget, (*visiting, here), overridden | template.replaced)
        elif template.rendered(reference.blocks, overridden):
            found = unrolled(reference.name, files, read, repeats, budget, (*visiting, here))
        else:
            continue
        for symbol, span, where, value, argument in found:
            yield symbol, span, where, reference.maps(value), reference.maps(argument)


def unrolled_filters(root: Path, repeats: int) -> dict[str, list[TemplateFilter]]:
    """The filters of each template, as project_templates gives them, from the walk path by
    path letting each cycle turn ``repeats`` times."""

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
                for symbol, span, where, value, argument in unrolled(name, files, read, repeats, [BUDGET])
            )
        )
        for name in files
    }


def reaches_a_cycle(name: str, texts: dict[str, str]) -> bool:
    """Whether a template ``name`` includes or extends, or ``name`` itself, reaches itself."""

    edges = {template: set(re.findall(r"\{% (?:include|extends) '([^']+)'", text)) for template, text in texts.items()}

    def reached(start: str) -> set[str]:
        found: set[str] = set()
        pending = list(edges.get(start, ()))
        while pending:
            current = pending.pop()
            if current not in found:
                found.add(current)
                pending.extend(edges.get(current, ()))
        return found

    return any(template in reached(template) for template in reached(name) | {name})


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


def joined(found: list[TemplateFilter]) -> dict[tuple[Any, ...], tuple[set[str], set[str]]]:
    """The names reaching the value and the argument of each filter application, joined
    over the paths that bring them: what the analysis reads of a template's filters."""

    names: dict[tuple[Any, ...], tuple[set[str], set[str]]] = {}
    for found_filter in found:
        values, arguments = names.setdefault((found_filter.symbol, found_filter.location, found_filter.template), (set(), set()))
        values.update(found_filter.value)
        arguments.update(found_filter.argument)
    return names


def test_the_filters_are_those_of_every_path_with_each_cycle_turned_until_it_settles(tmp_path: Path) -> None:
    """Generated projects of four templates extending and including one another, cycles
    among them, each walked by the engine and path by path, each cycle turned 2, then 3
    times. Where both give the same names at each filter application, the walk has
    settled: the engine must give those names, and the same lists, order included, for
    the templates no cycle reaches. A project the walk does not settle within its budget
    is not verified, and counted."""

    rng = random.Random(279)
    unverified = 0
    for index in range(1_500):
        fresh = (f"n{number}" for number in itertools.count())
        texts = {}
        for name in NAMES:
            extends = "{% extends '" + rng.choice(NAMES) + "' %}" if rng.random() < 0.5 else ""
            texts[name] = extends + generated(rng, fresh) + "\n"
        root = write(tmp_path / str(index), texts)
        filters = {name: list(found) for name, found in project_templates(root).filters.items()}
        try:
            fewer, more = (unrolled_filters(root, repeats) for repeats in REPEATS)
        except Unverified:
            unverified += 1
            continue
        if {name: joined(found) for name, found in fewer.items()} != {name: joined(found) for name, found in more.items()}:
            unverified += 1
            continue

        assert {name: joined(found) for name, found in filters.items()} == {name: joined(found) for name, found in more.items()}, texts
        for name, found in filters.items():
            if not reaches_a_cycle(name, texts):
                assert found == more[name], texts
    assert unverified <= UNVERIFIED
