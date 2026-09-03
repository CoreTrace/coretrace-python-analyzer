from __future__ import annotations

import argparse
import sys
from pathlib import Path

from coretrace_python import engine
from coretrace_python.analysis import AnalysisError
from coretrace_python.cfg import CFGError
from coretrace_python.frontend import HIRBuildError, ParseError, build_hir
from coretrace_python.ir.lowering import LoweringError, lower_module
from coretrace_python.ir.printer import format_module
from coretrace_python.plugins import IncompatiblePluginError, ManifestError
from coretrace_python.reporters import FORMATS, render
from coretrace_python.semantic.imports import ImportResolutionError
from coretrace_python.semantic.scopes import ScopeError
from coretrace_python.source import SourceManager

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_ANALYSIS_ERRORS = (
    OSError,
    UnicodeError,
    ParseError,
    HIRBuildError,
    ImportResolutionError,
    ScopeError,
    CFGError,
    LoweringError,
    AnalysisError,
    ManifestError,
    IncompatiblePluginError,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=engine.TOOL_NAME,
        description="Analyze Python source with CoreTrace.",
    )
    parser.add_argument("path", type=Path, help="Python source file, or a directory for --check")
    parser.add_argument(
        "--emit-ir",
        action="store_true",
        help="print the lowered Python intermediate representation",
    )
    parser.add_argument(
        "--ssa",
        action="store_true",
        help="with --emit-ir, print the static single assignment form",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="run the loaded plugins and report their findings",
    )
    parser.add_argument(
        "--plugins",
        action="append",
        type=Path,
        default=[],
        metavar="DIR",
        help="with --check, a directory searched recursively for plugin.toml (repeatable)",
    )
    parser.add_argument(
        "--format",
        choices=sorted(FORMATS),
        default=None,
        help="with --check, the report format (default: text)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not (args.emit_ir or args.check):
        print("error: no action selected; pass --emit-ir or --check", file=sys.stderr)
        return EXIT_ERROR
    if args.format is not None and not args.check:
        print("error: --format only applies to --check", file=sys.stderr)
        return EXIT_ERROR

    if args.path.is_dir() and args.emit_ir:
        print(f"error: {args.path} is a directory; --emit-ir needs a file", file=sys.stderr)
        return EXIT_ERROR

    try:
        if args.emit_ir:
            source = SourceManager().load_file(args.path)
            print(format_module(lower_module(build_hir(source), ssa=args.ssa)))
        if args.check:
            if args.path.is_dir():
                findings = engine.analyze_project(args.path, args.plugins).findings
            else:
                findings = engine.check(SourceManager().load_file(args.path), args.plugins)
            print(render(args.format or "text", engine.report(findings)), end="")
            return EXIT_FINDINGS if findings else EXIT_CLEAN
    except _ANALYSIS_ERRORS as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
