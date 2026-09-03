from __future__ import annotations

import argparse
import sys
from pathlib import Path

from coretrace_python.frontend import HIRBuildError, ParseError, build_hir
from coretrace_python.ir.lowering import LoweringError, lower_module
from coretrace_python.ir.printer import format_module
from coretrace_python.semantic.imports import ImportResolutionError
from coretrace_python.source import SourceManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="coretrace-python-analyzer",
        description="Analyze Python source with CoreTrace.",
    )
    parser.add_argument("path", type=Path, help="Python source file to analyze")
    parser.add_argument(
        "--emit-ir",
        action="store_true",
        help="print the lowered Python intermediate representation",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.emit_ir:
        print("error: no action selected; pass --emit-ir", file=sys.stderr)
        return 2

    try:
        source = SourceManager().load_file(args.path)
        module = lower_module(build_hir(source))
    except (
        OSError,
        UnicodeError,
        ParseError,
        HIRBuildError,
        ImportResolutionError,
        LoweringError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(format_module(module))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
