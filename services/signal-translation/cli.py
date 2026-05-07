"""CLI for the detection compiler.

Two ways to run it:

  python services/signal-translation/cli.py compile
  python services/signal-translation/cli.py validate
  python services/signal-translation/cli.py coverage

The script self-bootstraps the hyphenated directory as the importable
``signal_translation`` package, so it works without installing the service.
"""

from __future__ import annotations
import argparse
import importlib.util
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _register(alias: str, pkg_path: Path) -> None:
    if alias in sys.modules:
        return
    spec = importlib.util.spec_from_file_location(
        alias,
        pkg_path / "__init__.py",
        submodule_search_locations=[str(pkg_path)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot register {alias}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)


_register("signal_translation", _HERE)

from signal_translation.compiler import (  # noqa: E402
    compile_all,
    coverage_report,
    discover_yaml_files,
    load_yaml,
)
from signal_translation.config import get_config  # noqa: E402
from signal_translation.validator import ValidationError, validate  # noqa: E402


def _add_path_args(p: argparse.ArgumentParser) -> None:
    cfg = get_config()
    p.add_argument("--yaml", type=Path, default=cfg.yaml_path, help="YAML detections directory")
    p.add_argument("--out", type=Path, default=cfg.compiled_path, help="Compiled output directory")


def cmd_compile(args: argparse.Namespace) -> int:
    try:
        report = compile_all(args.yaml, args.out)
    except ValidationError as e:
        for r in e.results:
            for err in r.errors:
                print(f"FAIL  {r.detection_id}: {err}", file=sys.stderr)
        return 1
    for c in report.compiled:
        print(f"OK    {c.detection_id} → {c.splunk_path.name}, {c.sentinel_path.name}, {c.elastic_path.name}")
    print(f"compiled {len(report.compiled)} detections; manifest at {args.out}/manifest.json")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    files = discover_yaml_files(args.yaml)
    failures = 0
    for path in files:
        try:
            doc = load_yaml(path)
        except Exception as e:
            print(f"FAIL  {path.name}: YAML parse error: {e}", file=sys.stderr)
            failures += 1
            continue
        if not isinstance(doc, dict):
            print(f"FAIL  {path.name}: top-level YAML must be a mapping", file=sys.stderr)
            failures += 1
            continue
        result = validate(doc)
        if not result.ok:
            for err in result.errors:
                print(f"FAIL  {result.detection_id}: {err}", file=sys.stderr)
            failures += 1
        else:
            print(f"OK    {result.detection_id}")
    return 1 if failures else 0


def cmd_coverage(args: argparse.Namespace) -> int:
    print(json.dumps(coverage_report(args.yaml), indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="signal-translation")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("compile", help="Compile YAML → SPL/KQL/EQL artifacts")
    _add_path_args(p)
    p.set_defaults(func=cmd_compile)

    p = sub.add_parser("validate", help="Validate YAML detections")
    _add_path_args(p)
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("coverage", help="ATT&CK coverage report")
    _add_path_args(p)
    p.set_defaults(func=cmd_coverage)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
