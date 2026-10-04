"""Acceptance tests for issue #209: credentials in URLs, not their placeholders.

The ``url`` provider pattern finds a password in the user information of a URL and a
secret in a query parameter. The secret it matches goes through the placeholder check
that credentials already get: ``?token=...``, ``?token=<token>`` or ``?token={token}`` in
help text are not secrets. A ``host:port@`` pair is an address, as in proxy mode
specifications (``reverse:udp://127.0.0.1:1234@127.0.0.1:0``), not a user and a password.
Real credentials in URLs are still reported.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.source import SourceManager

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"


def url_secrets(value: str) -> list[Finding]:
    findings = engine.check(
        SourceManager().add_source("app/cli.py", f"TEXT = {value!r}\n"), [PLUGINS]
    )
    return [f for f in findings if f.rule_id == "hardcoded-secret"]


@pytest.mark.parametrize(
    "value",
    [
        "--upload needs --token (the ?token=... mitmweb prints at startup)",
        "The token is the `?token=...` in the URL mitmweb prints on startup.",
        "open http://127.0.0.1:8081/?token=<token> in a browser",
        "open http://127.0.0.1:8081/?token={token} in a browser",
        "https://host.example/api?password=password",
        "https://user:<password>@db.example/app",
        "reverse:udp://127.0.0.1:1234@127.0.0.1:0",
        "reverse:tcp://example.com:8080@0.0.0.0:80",
    ],
)
def test_placeholders_and_addresses_are_not_url_secrets(value: str) -> None:
    assert url_secrets(value) == []


@pytest.mark.parametrize(
    "value",
    [
        "https://alice:s3cr3tP4ss@example.com/",
        "postgres://admin:hunter2@db.example/app",
        "https://admin:1234@example.com/",
        "https://host.example/api?token=a1b2c3d4e5f6",
        "see ?token=... then https://host.example/api?api_key=a1b2c3d4e5f6",
        "call `https://host.example/api?token=a1b2c3d4e5f6` to sync",
    ],
)
def test_real_credentials_in_urls_are_still_reported(value: str) -> None:
    (finding,) = url_secrets(value)

    assert finding.metadata["provider"] == "url"
