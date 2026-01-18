from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, TYPE_CHECKING

import sys

import crudbot_analyzer


LogFn = Callable[[str], None]


@dataclass
class BotResult:
    return_code: int
    message: str


class CommandRunner:
    def run_stream(self, cmd: List[str], cwd: Optional[Path], on_line: Optional[LogFn]) -> int:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            if on_line:
                on_line(line.rstrip("\n"))
        proc.wait()
        return int(proc.returncode or 0)


if TYPE_CHECKING:  # pragma: no cover - typing only
    from .hub import AnalyzerBotConfig, CrudBotConfig, TestBotConfig


class CrudGeneratorBot:
    def __init__(self, runner: CommandRunner, python_executable: str) -> None:
        self.runner = runner
        self.python_executable = python_executable

    def build_cmd(self, config: "CrudBotConfig") -> List[str]:
        cmd: List[str] = [
            self.python_executable,
            str(config.generator_path),
            "--root",
            str(config.project_root),
        ]

        if config.entities:
            cmd += ["--entities", ",".join(config.entities)]
        else:
            cmd += ["--all"]

        if config.api_prefix.strip():
            cmd += ["--api-prefix", config.api_prefix.strip()]

        cmd += ["--backup-mode", config.backup_mode]
        cmd += ["--overwrite-policy", config.overwrite_policy]

        if config.dry_run:
            cmd.append("--dry-run")
        if config.no_build:
            cmd.append("--no-build")
        if config.no_config:
            cmd.append("--no-config")
        if config.no_docker:
            cmd.append("--no-docker")
        if config.no_openapi:
            cmd.append("--no-openapi")
        if config.no_compile:
            cmd.append("--no-compile")
        if config.patch_all:
            cmd.append("--patch-all")

        return cmd

    def run(self, config: "CrudBotConfig", on_line: Optional[LogFn] = None) -> int:
        cmd = self.build_cmd(config)
        if on_line:
            on_line("[CMD] " + " ".join(cmd))
        return self.runner.run_stream(cmd, cwd=config.project_root, on_line=on_line)


class TestsBot:
    def __init__(self, runner: CommandRunner, python_executable: str) -> None:
        self.runner = runner
        self.python_executable = python_executable

    def run(self, config: "TestBotConfig", on_line: Optional[LogFn] = None) -> int:
        tests_py = Path(__file__).resolve().parent.parent / "crudbot_tests.py"
        if not tests_py.exists():
            raise RuntimeError("crudbot_tests.py not found next to application root.")

        cmd: List[str] = [
            self.python_executable,
            str(tests_py),
            "--root",
            str(config.project_root),
        ]
        if config.entities:
            cmd += ["--entities", ",".join(config.entities)]
        else:
            cmd += ["--all"]

        if on_line:
            on_line("[CMD] " + " ".join(cmd))
        return self.runner.run_stream(cmd, cwd=config.project_root, on_line=on_line)

    def run_build_tests(self, project_root: Path, on_line: Optional[LogFn] = None) -> int:
        if (project_root / "mvnw").exists() and not self._is_windows():
            cmd = ["./mvnw", "-q", "test"]
        elif (project_root / "mvnw.cmd").exists() and self._is_windows():
            cmd = ["cmd", "/c", "mvnw.cmd", "-q", "test"]
        elif (project_root / "gradlew").exists() and not self._is_windows():
            cmd = ["./gradlew", "-q", "test"]
        elif (project_root / "gradlew.bat").exists() and self._is_windows():
            cmd = ["cmd", "/c", "gradlew.bat", "-q", "test"]
        elif self._shutil_which("mvn"):
            cmd = ["mvn", "-q", "test"]
        elif self._shutil_which("gradle"):
            cmd = ["gradle", "-q", "test"]
        else:
            if on_line:
                on_line("[WARN] No mvn/gradle found; skipping test run.")
            return 0

        if on_line:
            on_line("[CMD] " + " ".join(cmd))
        return self.runner.run_stream(cmd, cwd=project_root, on_line=on_line)

    @staticmethod
    def _is_windows() -> bool:
        return sys.platform.startswith("win")

    @staticmethod
    def _shutil_which(name: str) -> Optional[str]:
        import shutil

        return shutil.which(name)


class AnalyzerBot:
    def run(self, config: "AnalyzerBotConfig") -> str:
        exclude_dirs = set(crudbot_analyzer.DEFAULT_EXCLUDE_DIRS) | set(config.exclude_dirs_extra)
        scan = crudbot_analyzer.scan_project(
            root=config.project_root,
            exclude_dirs=exclude_dirs,
            max_file_bytes=int(config.max_file_kb) * 1024,
            include_all_text=bool(config.include_all_text),
        )

        report_parts = [
            crudbot_analyzer.make_overview(scan),
            crudbot_analyzer.make_structure_section(scan),
            crudbot_analyzer.make_build_section(scan),
            crudbot_analyzer.make_packages_section(scan),
            crudbot_analyzer.make_files_section(scan),
        ]
        report = "\n\n".join(report_parts).rstrip() + "\n"
        crudbot_analyzer.safe_write(config.report_path, report)

        ctx_txt = crudbot_analyzer.make_ai_context(scan).rstrip() + "\n"
        crudbot_analyzer.safe_write(config.context_path, ctx_txt)

        return report
