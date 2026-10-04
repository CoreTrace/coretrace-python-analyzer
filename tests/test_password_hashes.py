"""Acceptance tests for issue #211: password hashes are not hardcoded passwords.

A value in a password-hash format (a PHC string such as ``$argon2id$...`` or a modular
crypt string such as ``$2b$...`` or ``$6$...``) is what an application stores instead of
the password; it does not reveal the password, so a credential-like name bound to it is
not a hardcoded credential. The algorithm identifier is what tells a hash: an incomplete
hash such as ``$argon2id$`` reveals nothing either. A plaintext value bound to the same
name is still reported, dollar signs included.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.source import SourceManager

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("app/settings.py", text), [PLUGINS])


@pytest.mark.parametrize(
    "value",
    [
        "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$ieVgG5ysTJFx4k/KvmC9aQ",
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2d$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$Hl6uH5u2Bx9QA6LiWdqzkzCZD0dw6Y9V6nhuB1z0zgs",
        "$argon2id$",
        "$2b$12$KIXQJ1rKqvYV8m1b2u3Ewe0eY8c9Jx5mQ6v1Zp7S3y2Lh4Qn0aBcW",
        "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
        "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
        "$5$rounds=5000$saltsalt$Gbbw8bXq5ckEEnEJfRZFm6S6ki13QdkqoZ0gYJx0rU/",
        "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/",
        "$pbkdf2-sha256$29000$N2YMIWQsBWBMae09x1jrPQ$1t8iyB2A.WF/Z5JZv.lfCIhXXN33N23OSgQYThBYRfk",
        "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E",
    ],
)
def test_a_password_hash_is_not_a_hardcoded_credential(value: str) -> None:
    assert check(f'web_password = "{value}"\n') == ()


@pytest.mark.parametrize("value", ["hunter2-not-a-placeholder", "pa$$w0rd-really", "$ecret$value"])
def test_a_plaintext_password_is_still_reported(value: str) -> None:
    (finding,) = check(f'web_password = "{value}"\n')

    assert finding.rule_id == "hardcoded-credential"
