"""Where the code of a finding lives, by its path in the project (#244): test code, which
a project runs to check itself and does not ship. The context is a fact about the file,
shown in the finding's metadata; what it changes, if anything, is the rule's decision, or
a refiner plugin's."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

TEST = "test"

_TEST_DIRECTORIES = frozenset({"test", "tests", "testing", "fixtures", "__tests__"})
_TEST_FILE = re.compile(r"^(test_.*|.*_test|conftest)\.py$")


def is_test_code(path: str) -> bool:
    """Whether ``path`` is test code or a fixture: under a test directory, or named like
    a test module."""

    parts = PurePosixPath(path).parts
    return bool(parts) and (
        any(part in _TEST_DIRECTORIES for part in parts[:-1]) or _TEST_FILE.match(parts[-1]) is not None
    )


def code_context(path: str) -> str | None:
    """The context a finding at ``path`` carries: ``"test"`` for test code, ``None`` for
    anything else. ``path`` is relative to the project root, so where the project sits
    does not count."""

    return TEST if is_test_code(path) else None
