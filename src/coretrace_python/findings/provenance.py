"""What a result was produced with, besides the engine and the analysed sources.

Advisories decide the dependency findings and the VEX statements, and they come from
plugins and advisory files that change on their own schedule. A report names each of
them with the digest of its content, so a result can be traced to its data and
reproduced.
"""

from __future__ import annotations

from dataclasses import dataclass

PLUGIN = "plugin"
ADVISORIES = "advisories"


@dataclass(frozen=True)
class Component:
    """A loaded plugin, by its manifest ``name`` and ``version``, or an advisory file, by
    its path as ``name``. ``digest`` is ``sha256:`` and the hex digest of its content:
    the plugin directory as the cache fingerprints it, or the file's bytes."""

    kind: str
    name: str
    digest: str
    version: str | None = None
