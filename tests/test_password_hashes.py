"""Acceptance tests for issue #211: password hashes are not hardcoded passwords.

A value in a password-hash format is what an application stores instead of the
password; it does not reveal the password, so a credential-like name bound to it is not
a hardcoded credential. The formats are PHC and modular crypt strings (``$argon2id$...``,
``$2b$...``, ``$6$...``), and the encodings of Werkzeug (``scrypt:32768:8:1$...``) and
Django (``pbkdf2_sha256$...``). A hash has the shape of its format: an algorithm
identifier followed by text that is not a hash (``$2y$Summer2024!``) is a plaintext
password, while the identifier alone (``$argon2id$``, an incomplete hash) reveals
nothing. A plaintext value bound to the same name is still reported.
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
        "$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/",
        "$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.",
        "$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c7o.9agCG9G317fhZg9SqC.5i5rd.RhAtQ7",
        "scrypt:32768:8:1$KbI3sQ1x9cBnGz7a$d624ca2ead7454931117ad5ab4342ed9d93ae0407f730264d97f655506d36fb308d1ddb7f4c5f9046884ba4516df4b6e492ba26a31786ff43bec1f2d8999bc47",
        "pbkdf2:sha256:600000$KbI3sQ1x9cBnGz7a$57fab0cc5de31d8fb5518804d402a6dd807e483ba7c6e3968a10cd466d28c46e",
        "pbkdf2_sha256$870000$Qx7mR2vT9kLp4sWz$q8bVU34ZbIqSroAvvFgZhHZ6jNeCNMPqYZOg52ta260=",
        "argon2$argon2id$v=19$m=102400,t=2,p=8$c29tZXNhbHQ$ieVgG5ysTJFx4k/KvmC9aQ",
        "bcrypt_sha256$$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
        "scrypt$16384$c29tZXNhbHQ$8$1$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E=",
    ],
)
def test_a_password_hash_is_not_a_hardcoded_credential(value: str) -> None:
    assert check(f'web_password = "{value}"\n') == ()


@pytest.mark.parametrize(
    "value",
    [
        "hunter2-not-a-placeholder",
        "pa$$w0rd-really",
        "$ecret$value",
        "$2y$Summer2024!",
        "$scrypt$MyRealPassw0rd",
        "$5$hunter2-plain",
    ],
)
def test_a_plaintext_password_is_still_reported(value: str) -> None:
    (finding,) = check(f'web_password = "{value}"\n')

    assert finding.rule_id == "hardcoded-credential"
