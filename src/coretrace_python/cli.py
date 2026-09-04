from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

from coretrace_python import __version__, engine
from coretrace_python.analysis import AnalysisError
from coretrace_python.cache import ProjectCache
from coretrace_python.cfg import CFGError
from coretrace_python.dependency import dump_advisories, import_osv, read_osv, render_sbom
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
    parser.add_argument(
        "path", type=Path, nargs="?", help="Python source file, or a directory for --check"
    )
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
        help="with --check, a directory searched recursively for plugin.toml, loaded on "
        "top of the bundled plugins (repeatable)",
    )
    parser.add_argument(
        "--no-bundled-plugins",
        action="store_true",
        help="with --check, do not load the plugins shipped with the package",
    )
    parser.add_argument(
        "--format",
        choices=sorted(FORMATS),
        default=None,
        help="with --check, the report format (default: text)",
    )
    parser.add_argument(
        "--cache",
        type=Path,
        default=None,
        metavar="DIR",
        help="with --check on a directory, keep per-module results under DIR and reuse "
        "them for modules unchanged since the previous run",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=None,
        metavar="N",
        help="with --check on a directory, analyse independent modules in N processes",
    )
    parser.add_argument(
        "--sbom",
        type=Path,
        default=None,
        metavar="PATH",
        help="with --check on a directory, write a CycloneDX bill of materials to PATH",
    )
    parser.add_argument(
        "--advisories",
        action="append",
        type=Path,
        default=[],
        metavar="FILE",
        help="with --check on a directory, a local advisory file to read in addition to "
        "advisories.json at the root (repeatable)",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        metavar="FILE",
        help="with --check on a directory, the dependency policy to apply instead of "
        "coretrace-policy.toml at the root",
    )
    parser.add_argument(
        "--import-advisories",
        nargs=2,
        type=Path,
        default=None,
        metavar=("SRC", "OUT"),
        help="convert an OSV dump (a JSON file, a directory of them or a zip archive) "
        "into the local advisory file OUT, then exit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.import_advisories is not None:
        source, out = args.import_advisories
        try:
            out.write_text(dump_advisories(import_osv(read_osv(source))), encoding="utf-8")
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            print(f"error: {error}", file=sys.stderr)
            return EXIT_ERROR
        return EXIT_CLEAN
    if not (args.emit_ir or args.check):
        print("error: no action selected; pass --emit-ir or --check", file=sys.stderr)
        return EXIT_ERROR
    if args.path is None:
        print("error: a path is required", file=sys.stderr)
        return EXIT_ERROR
    if args.format is not None and not args.check:
        print("error: --format only applies to --check", file=sys.stderr)
        return EXIT_ERROR
    if args.cache is not None and not (args.check and args.path.is_dir()):
        print("error: --cache only applies to --check on a directory", file=sys.stderr)
        return EXIT_ERROR
    if args.jobs is not None and not (args.check and args.path.is_dir()):
        print("error: --jobs only applies to --check on a directory", file=sys.stderr)
        return EXIT_ERROR
    if args.jobs is not None and args.jobs < 1:
        print("error: --jobs must be at least 1", file=sys.stderr)
        return EXIT_ERROR
    if args.sbom is not None and not (args.check and args.path.is_dir()):
        print("error: --sbom only applies to --check on a directory", file=sys.stderr)
        return EXIT_ERROR
    if args.advisories and not (args.check and args.path.is_dir()):
        print("error: --advisories only applies to --check on a directory", file=sys.stderr)
        return EXIT_ERROR
    if args.policy is not None and not (args.check and args.path.is_dir()):
        print("error: --policy only applies to --check on a directory", file=sys.stderr)
        return EXIT_ERROR

    if args.no_bundled_plugins and not args.check:
        print("error: --no-bundled-plugins only applies to --check", file=sys.stderr)
        return EXIT_ERROR
    plugin_roots = ([] if args.no_bundled_plugins else [engine.BUNDLED_PLUGINS]) + list(args.plugins)

    if args.path.is_dir() and args.emit_ir:
        print(f"error: {args.path} is a directory; --emit-ir needs a file", file=sys.stderr)
        return EXIT_ERROR

    try:
        if args.emit_ir:
            source = SourceManager().load_file(args.path)
            print(format_module(lower_module(build_hir(source), ssa=args.ssa)))
        if args.check:
            if args.path.is_dir():
                cache = None if args.cache is None else ProjectCache(args.cache)
                analysis = engine.analyze_project(
                    args.path,
                    plugin_roots,
                    cache=cache,
                    jobs=args.jobs or 1,
                    advisory_files=args.advisories,
                    policy_file=args.policy,
                )
                findings = analysis.findings
                coverage = analysis.coverage
                if args.sbom is not None:
                    args.sbom.write_text(
                        render_sbom(analysis.dependencies, analysis.advisories, engine.TOOL_NAME, __version__),
                        encoding="utf-8",
                    )
            else:
                file_analysis = engine.analyze_file(SourceManager().load_file(args.path), plugin_roots)
                findings, coverage = file_analysis.findings, file_analysis.coverage
            print(render(args.format or "text", engine.report(findings, coverage)), end="")
            return EXIT_FINDINGS if findings else EXIT_CLEAN
    except _ANALYSIS_ERRORS as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
