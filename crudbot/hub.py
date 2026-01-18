from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional

from .bots import AnalyzerBot, CommandRunner, CrudGeneratorBot, TestsBot


LogFn = Callable[[str], None]


@dataclass
class CrudBotConfig:
    project_root: Path
    generator_path: Path
    entities: List[str]
    api_prefix: str
    backup_mode: str
    overwrite_policy: str
    patch_all: bool
    dry_run: bool
    no_build: bool
    no_config: bool
    no_docker: bool
    no_openapi: bool
    no_compile: bool


@dataclass
class TestBotConfig:
    project_root: Path
    entities: List[str]


@dataclass
class AnalyzerBotConfig:
    project_root: Path
    report_path: Path
    context_path: Path
    max_file_kb: int
    include_all_text: bool
    exclude_dirs_extra: Iterable[str]


class CrudBotHub:
    def __init__(self, *, python_executable: Optional[str] = None, runner: Optional[CommandRunner] = None) -> None:
        self.python_executable = python_executable or sys.executable
        self.runner = runner or CommandRunner()
        self.crud_bot = CrudGeneratorBot(self.runner, self.python_executable)
        self.tests_bot = TestsBot(self.runner, self.python_executable)
        self.analyzer_bot = AnalyzerBot()

    def run_crud(self, config: CrudBotConfig, on_line: Optional[LogFn] = None) -> int:
        return self.crud_bot.run(config, on_line=on_line)

    def run_tests(self, config: TestBotConfig, on_line: Optional[LogFn] = None) -> int:
        return self.tests_bot.run(config, on_line=on_line)

    def run_build_tests(self, project_root: Path, on_line: Optional[LogFn] = None) -> int:
        return self.tests_bot.run_build_tests(project_root, on_line=on_line)

    def run_analyzer(self, config: AnalyzerBotConfig) -> str:
        return self.analyzer_bot.run(config)
