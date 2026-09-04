"""Source storage and location primitives."""

from coretrace_python.source.manager import SourceManager, decode_text
from coretrace_python.source.model import SourceFile, SourceId, SourceSpan

__all__ = [
    "SourceFile",
    "SourceId",
    "SourceManager",
    "SourceSpan",
    "decode_text",
]

