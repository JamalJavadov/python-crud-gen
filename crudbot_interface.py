#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CrudBot unified interface.

Run one interface to:
- generate CRUD
- generate tests
- analyze project
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from crudbot import AnalyzerBotConfig, CrudBotConfig, CrudBotHub, TestBotConfig


def _split_entities(value: str) -> List[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _default_generator(root: Path) -> Path:
    return root / "java-project-crud.py"


def _log(line: str) -> None:
    print(line)


def _resolve_root(raw: str) -> Path:
    root = Path(raw).expanduser().resolve()
    if not root.exists():
        raise SystemExit(f"Project root not found: {root}")
    return root


def run_crud(args: argparse.Namespace, hub: CrudBotHub) -> int:
    root = _resolve_root(args.root)
    generator = Path(args.generator).expanduser() if args.generator else _default_generator(root)
    if not generator.exists():
        raise SystemExit(f"CRUD generator not found: {generator}")

    entities = _split_entities(args.entities)
    config = CrudBotConfig(
        project_root=root,
        generator_path=generator,
        entities=entities,
        api_prefix=args.api_prefix or "",
        backup_mode=args.backup_mode,
        overwrite_policy=args.overwrite_policy,
        patch_all=args.patch_all,
        dry_run=args.dry_run,
        no_build=args.no_build,
        no_config=args.no_config,
        no_docker=args.no_docker,
        no_openapi=args.no_openapi,
        no_compile=args.no_compile,
    )
    return hub.run_crud(config, on_line=_log)


def run_tests(args: argparse.Namespace, hub: CrudBotHub) -> int:
    root = _resolve_root(args.root)
    entities = _split_entities(args.entities)
    config = TestBotConfig(project_root=root, entities=entities)
    return hub.run_tests(config, on_line=_log)


def run_analyze(args: argparse.Namespace, hub: CrudBotHub) -> int:
    root = _resolve_root(args.root)
    report = Path(args.report).expanduser() if args.report else root / "project_report.md"
    context = Path(args.context).expanduser() if args.context else root / "ai_context.txt"
    exclude_dirs = [item.strip() for item in (args.exclude_dirs or "").split(",") if item.strip()]

    config = AnalyzerBotConfig(
        project_root=root,
        report_path=report,
        context_path=context,
        max_file_kb=args.max_file_kb,
        include_all_text=args.include_all_text,
        exclude_dirs_extra=exclude_dirs,
    )
    hub.run_analyzer(config)
    _log(f"[DONE] Report: {report}")
    _log(f"[DONE] Context: {context}")
    return 0


def run_all(args: argparse.Namespace, hub: CrudBotHub) -> int:
    rc = run_crud(args, hub)
    if rc != 0:
        return rc

    if args.generate_tests:
        rc = run_tests(args, hub)
        if rc != 0:
            return rc

    if args.run_build_tests:
        root = _resolve_root(args.root)
        rc = hub.run_build_tests(root, on_line=_log)
        if rc != 0:
            return rc

    if args.run_analyzer:
        rc = run_analyze(args, hub)
        if rc != 0:
            return rc

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CrudBot unified interface")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common_targets(p: argparse.ArgumentParser) -> None:
        p.add_argument("--root", required=True, help="Spring Boot project root")
        p.add_argument("--entities", default="", help="Comma-separated entity names (default: all)")

    crud = sub.add_parser("crud", help="Generate CRUD")
    add_common_targets(crud)
    crud.add_argument("--generator", help="Path to java-project-crud.py (default: root/java-project-crud.py)")
    crud.add_argument("--api-prefix", default="", help="Optional API prefix override")
    crud.add_argument("--backup-mode", default="managed", choices=["none", "managed", "all"])
    crud.add_argument("--overwrite-policy", default="marked", choices=["marked", "force", "never"])
    crud.add_argument("--patch-all", action="store_true")
    crud.add_argument("--dry-run", action="store_true")
    crud.add_argument("--no-build", action="store_true")
    crud.add_argument("--no-config", action="store_true")
    crud.add_argument("--no-docker", action="store_true")
    crud.add_argument("--no-openapi", action="store_true")
    crud.add_argument("--no-compile", action="store_true")

    tests = sub.add_parser("tests", help="Generate integration tests")
    add_common_targets(tests)

    analyze = sub.add_parser("analyze", help="Analyze project and export report/context")
    analyze.add_argument("--root", required=True, help="Spring Boot project root")
    analyze.add_argument("--report", help="Report output path (.md)")
    analyze.add_argument("--context", help="Context output path (.txt)")
    analyze.add_argument("--max-file-kb", type=int, default=512)
    analyze.add_argument("--include-all-text", action="store_true")
    analyze.add_argument("--exclude-dirs", default="", help="Comma-separated directories to exclude")

    all_cmd = sub.add_parser("all", help="Run CRUD + tests + analyzer in one flow")
    add_common_targets(all_cmd)
    all_cmd.add_argument("--generator", help="Path to java-project-crud.py (default: root/java-project-crud.py)")
    all_cmd.add_argument("--api-prefix", default="", help="Optional API prefix override")
    all_cmd.add_argument("--backup-mode", default="managed", choices=["none", "managed", "all"])
    all_cmd.add_argument("--overwrite-policy", default="marked", choices=["marked", "force", "never"])
    all_cmd.add_argument("--patch-all", action="store_true")
    all_cmd.add_argument("--dry-run", action="store_true")
    all_cmd.add_argument("--no-build", action="store_true")
    all_cmd.add_argument("--no-config", action="store_true")
    all_cmd.add_argument("--no-docker", action="store_true")
    all_cmd.add_argument("--no-openapi", action="store_true")
    all_cmd.add_argument("--no-compile", action="store_true")
    all_cmd.add_argument("--generate-tests", action="store_true", help="Run test generator after CRUD")
    all_cmd.add_argument("--run-build-tests", action="store_true", help="Run mvn/gradle tests")
    all_cmd.add_argument("--run-analyzer", action="store_true", help="Run project analyzer")
    all_cmd.add_argument("--report", help="Report output path (.md)")
    all_cmd.add_argument("--context", help="Context output path (.txt)")
    all_cmd.add_argument("--max-file-kb", type=int, default=512)
    all_cmd.add_argument("--include-all-text", action="store_true")
    all_cmd.add_argument("--exclude-dirs", default="", help="Comma-separated directories to exclude")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    hub = CrudBotHub()

    if args.command == "crud":
        return run_crud(args, hub)
    if args.command == "tests":
        return run_tests(args, hub)
    if args.command == "analyze":
        return run_analyze(args, hub)
    if args.command == "all":
        return run_all(args, hub)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
