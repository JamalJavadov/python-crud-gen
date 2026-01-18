#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Java Project Deep Doc Bot
- Verilən qovluqdakı Java proyektini incələyir
- Struktur, build/dependency, source paketləri, entrypoint-lər və s. çıxarır
- Bütün kodları report-a əlavə edir
- AI üçün ayrıca "context" txt generasiya edir

İstifadə:
  python3 java_doc_bot.py /path/to/project
  python3 java_doc_bot.py /path/to/project --out project_report.md --context ai_context.txt
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import sys
import textwrap
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Iterable


# ---------------------------
# Default ignore rules
# ---------------------------
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".idea", ".vscode",
    "target", "build", "out", ".gradle",
    "node_modules", "__pycache__",  # keep wrapper files but skip heavy caches if any
}
DEFAULT_EXCLUDE_FILES = {
    ".DS_Store",
}

BINARY_EXTS = {
    ".class", ".jar", ".war", ".ear",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
    ".pdf",
    ".mp3", ".mp4", ".mov", ".mkv", ".avi",
    ".exe", ".dll", ".so", ".dylib",
}

# Text-like config/code extensions we usually want
INTERESTING_TEXT_EXTS = {
    ".java", ".kt", ".kts",
    ".xml", ".yml", ".yaml", ".properties", ".conf", ".ini",
    ".gradle", ".md", ".txt", ".sql", ".json", ".toml",
    ".sh", ".bat", ".cmd",
}


# ---------------------------
# Helpers
# ---------------------------
def is_binary_by_ext(path: Path) -> bool:
    return path.suffix.lower() in BINARY_EXTS


def read_text_file(path: Path, max_bytes: int) -> str:
    data = path.read_bytes()
    if len(data) > max_bytes:
        # cut but keep deterministic
        head = data[:max_bytes]
        try:
            txt = head.decode("utf-8", errors="replace")
        except Exception:
            txt = head.decode(errors="replace")
        return txt + f"\n\n[TRUNCATED: file too large, first {max_bytes} bytes shown]\n"
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return data.decode(errors="replace")


def relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def fence_lang(path: Path) -> str:
    ext = path.suffix.lower()
    if ext == ".java":
        return "java"
    if ext in {".yml", ".yaml"}:
        return "yaml"
    if ext == ".xml":
        return "xml"
    if ext == ".properties":
        return "properties"
    if ext in {".gradle", ".kts"}:
        return "gradle"
    if ext == ".md":
        return "markdown"
    if ext == ".sql":
        return "sql"
    if ext == ".json":
        return "json"
    if ext in {".sh", ".bat", ".cmd"}:
        return "bash"
    return ""


def safe_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="replace")


def build_tree(root: Path, exclude_dirs: set[str], max_depth: int = 20) -> str:
    # Compact tree (not perfect like `tree` command, but good enough)
    lines: List[str] = []
    root = root.resolve()

    def _walk(dir_path: Path, prefix: str, depth: int) -> None:
        if depth > max_depth:
            lines.append(prefix + "… (max depth reached)")
            return

        try:
            entries = sorted(dir_path.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        except PermissionError:
            lines.append(prefix + "[permission denied]")
            return

        visible = []
        for p in entries:
            if p.name in DEFAULT_EXCLUDE_FILES:
                continue
            if p.is_dir() and p.name in exclude_dirs:
                continue
            visible.append(p)

        for i, p in enumerate(visible):
            last = (i == len(visible) - 1)
            branch = "└── " if last else "├── "
            lines.append(prefix + branch + p.name)
            if p.is_dir():
                extension = "    " if last else "│   "
                _walk(p, prefix + extension, depth + 1)

    lines.append(root.name + "/")
    _walk(root, "", 0)
    return "\n".join(lines)


# ---------------------------
# Java analysis (regex-based)
# ---------------------------
JAVA_PACKAGE_RE = re.compile(r"^\s*package\s+([a-zA-Z0-9_.]+)\s*;", re.M)
JAVA_IMPORT_RE = re.compile(r"^\s*import\s+(static\s+)?([a-zA-Z0-9_.]+)\s*;", re.M)
JAVA_TYPE_RE = re.compile(
    r"(?m)^\s*(?:@[\w.]+\s*)*"
    r"(public|protected|private)?\s*"
    r"(abstract\s+|final\s+)?"
    r"(class|interface|enum|record)\s+([A-Za-z_]\w*)"
    r"(?:\s+extends\s+([A-Za-z0-9_.,\s<>]+))?"
    r"(?:\s+implements\s+([A-Za-z0-9_.,\s<>]+))?"
    r"\s*\{?"
)
JAVA_MAIN_RE = re.compile(r"(?s)\bpublic\s+static\s+void\s+main\s*\(\s*String(\s*\[\s*\]|\.\.\.)\s+\w+\s*\)")
JAVA_METHOD_RE = re.compile(
    r"(?m)^\s*(public|protected|private)\s+"
    r"(static\s+)?"
    r"([A-Za-z0-9_<>\[\],.?]+\s+)+"
    r"([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:throws\s+[^{]+)?\s*\{"
)

SPRING_ANNOT_RE = re.compile(r"@(?:SpringBootApplication|RestController|Controller|Service|Component|Repository|Configuration)\b")

@dataclass
class JavaFileInfo:
    package: Optional[str]
    imports: List[str]
    types: List[Dict[str, str]]
    has_main: bool
    method_count: int
    public_method_signatures: List[str]
    spring_hints: List[str]


def analyze_java_source(text: str) -> JavaFileInfo:
    pkg = None
    m = JAVA_PACKAGE_RE.search(text)
    if m:
        pkg = m.group(1)

    imports = [im.group(2) for im in JAVA_IMPORT_RE.finditer(text)]

    types: List[Dict[str, str]] = []
    for t in JAVA_TYPE_RE.finditer(text):
        kind = t.group(3)
        name = t.group(4)
        extends_ = (t.group(5) or "").strip()
        impl_ = (t.group(6) or "").strip()
        types.append({
            "kind": kind,
            "name": name,
            "extends": extends_,
            "implements": impl_,
        })

    has_main = bool(JAVA_MAIN_RE.search(text))

    method_sigs = []
    method_count = 0
    for mm in JAVA_METHOD_RE.finditer(text):
        method_count += 1
        vis = mm.group(1)
        static_ = (mm.group(2) or "").strip()
        name = mm.group(4)
        args = " ".join(mm.group(5).split())
        sig = f"{vis} {static_+' ' if static_ else ''}{name}({args})".strip()
        # keep only a reasonable amount
        if len(method_sigs) < 50:
            method_sigs.append(sig)

    spring_hints = sorted(set(SPRING_ANNOT_RE.findall(text)))

    return JavaFileInfo(
        package=pkg,
        imports=imports,
        types=types,
        has_main=has_main,
        method_count=method_count,
        public_method_signatures=method_sigs,
        spring_hints=spring_hints,
    )


# ---------------------------
# Build file parsing
# ---------------------------
def parse_pom(pom_path: Path) -> Dict[str, object]:
    """
    Best-effort Maven pom.xml parser (namespace-safe).
    """
    result: Dict[str, object] = {
        "path": str(pom_path),
        "groupId": None,
        "artifactId": None,
        "version": None,
        "packaging": None,
        "modules": [],
        "properties": {},
        "dependencies": [],
        "plugins": [],
    }

    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()
    except Exception:
        return result

    # namespace handling
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0].strip("{")

    def _q(tag: str) -> str:
        return f"{{{ns}}}{tag}" if ns else tag

    def _text(parent: ET.Element, tag: str) -> Optional[str]:
        el = parent.find(_q(tag))
        if el is not None and el.text:
            return el.text.strip()
        return None

    result["groupId"] = _text(root, "groupId") or _text(root.find(_q("parent")) or root, "groupId")
    result["artifactId"] = _text(root, "artifactId")
    result["version"] = _text(root, "version") or _text(root.find(_q("parent")) or root, "version")
    result["packaging"] = _text(root, "packaging")

    # modules
    modules_el = root.find(_q("modules"))
    if modules_el is not None:
        for m in modules_el.findall(_q("module")):
            if m.text:
                result["modules"].append(m.text.strip())

    # properties
    props_el = root.find(_q("properties"))
    if props_el is not None:
        for child in list(props_el):
            tag = child.tag.split("}")[-1]
            result["properties"][tag] = (child.text or "").strip()

    # dependencies
    deps_el = root.find(_q("dependencies"))
    if deps_el is not None:
        for d in deps_el.findall(_q("dependency")):
            dep = {
                "groupId": _text(d, "groupId"),
                "artifactId": _text(d, "artifactId"),
                "version": _text(d, "version"),
                "scope": _text(d, "scope"),
            }
            result["dependencies"].append(dep)

    # plugins (build/plugins)
    build_el = root.find(_q("build"))
    if build_el is not None:
        plugins_el = build_el.find(_q("plugins"))
        if plugins_el is not None:
            for p in plugins_el.findall(_q("plugin")):
                plugin = {
                    "groupId": _text(p, "groupId"),
                    "artifactId": _text(p, "artifactId"),
                    "version": _text(p, "version"),
                }
                result["plugins"].append(plugin)

    return result


def parse_gradle_dependencies(text: str) -> List[str]:
    """
    Best-effort: extracts non-empty dependency lines inside dependencies { ... }.
    """
    deps: List[str] = []
    # crude block extraction
    m = re.search(r"(?s)\bdependencies\s*\{\s*(.*?)\s*\}", text)
    if not m:
        return deps
    block = m.group(1)
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("/*"):
            continue
        # keep concise
        deps.append(line)
        if len(deps) >= 200:
            deps.append("[TRUNCATED: too many dependency lines]")
            break
    return deps


def detect_frameworks_from_strings(strings: Iterable[str]) -> List[str]:
    joined = "\n".join(strings).lower()
    hints = []
    def add(key: str, name: str):
        if key in joined and name not in hints:
            hints.append(name)
    add("spring-boot", "Spring Boot")
    add("org.springframework", "Spring Framework")
    add("jakarta", "Jakarta EE")
    add("javax.", "Javax / Legacy Java EE")
    add("junit", "JUnit")
    add("mockito", "Mockito")
    add("hibernate", "Hibernate")
    add("mybatis", "MyBatis")
    add("lombok", "Lombok")
    add("mapstruct", "MapStruct")
    add("slf4j", "SLF4J")
    add("logback", "Logback")
    add("log4j", "Log4j")
    add("kafka", "Kafka")
    add("redis", "Redis")
    add("postgres", "PostgreSQL")
    add("mysql", "MySQL")
    add("mongodb", "MongoDB")
    add("gradle", "Gradle")
    add("maven", "Maven")
    return hints


# ---------------------------
# Collector
# ---------------------------
@dataclass
class CollectedFile:
    path: Path
    rel: str
    size: int
    text: Optional[str]  # None if skipped
    java_info: Optional[JavaFileInfo]


@dataclass
class ProjectScan:
    root: Path
    files: List[CollectedFile]
    tree: str
    pom_infos: List[Dict[str, object]]
    gradle_files: List[Tuple[str, List[str]]]  # (relpath, deps)
    readme_files: List[str]
    entrypoints: List[str]
    packages: Dict[str, int]
    root_packages: List[str]
    framework_hints: List[str]


def scan_project(
    root: Path,
    exclude_dirs: set[str],
    max_file_bytes: int,
    include_all_text: bool = True
) -> ProjectScan:
    root = root.resolve()
    all_files: List[CollectedFile] = []
    pom_infos: List[Dict[str, object]] = []
    gradle_files: List[Tuple[str, List[str]]] = []
    readmes: List[str] = []

    packages_count: Dict[str, int] = defaultdict(int)
    java_main_classes: List[str] = []
    all_dep_strings: List[str] = []

    # Walk with pruning
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for fn in filenames:
            if fn in DEFAULT_EXCLUDE_FILES:
                continue
            p = Path(dirpath) / fn
            if p.is_symlink():
                continue
            rel = relpath(p, root)
            try:
                size = p.stat().st_size
            except Exception:
                size = -1

            ext = p.suffix.lower()
            is_interesting_text = (ext in INTERESTING_TEXT_EXTS) or (p.name.lower() in {"pom.xml", "build.gradle", "settings.gradle", "gradle.properties"})
            if is_binary_by_ext(p):
                all_files.append(CollectedFile(p, rel, size, None, None))
                continue

            text = None
            java_info = None

            if include_all_text and (is_interesting_text or ext == "" or p.name.lower().startswith("readme")):
                try:
                    text = read_text_file(p, max_file_bytes)
                except Exception:
                    text = "[ERROR: could not read file]\n"

            # special: Maven
            if p.name.lower() == "pom.xml":
                info = parse_pom(p)
                pom_infos.append(info)
                # add to framework hints input
                for d in info.get("dependencies", []) or []:
                    g = (d.get("groupId") or "")
                    a = (d.get("artifactId") or "")
                    v = (d.get("version") or "")
                    all_dep_strings.append(f"{g}:{a}:{v}")
                for pl in info.get("plugins", []) or []:
                    g = (pl.get("groupId") or "")
                    a = (pl.get("artifactId") or "")
                    v = (pl.get("version") or "")
                    all_dep_strings.append(f"plugin {g}:{a}:{v}")

            # special: Gradle
            if p.name.lower() in {"build.gradle", "build.gradle.kts"} and text is not None:
                deps = parse_gradle_dependencies(text)
                gradle_files.append((rel, deps))
                all_dep_strings.extend(deps)

            # readmes
            if p.name.lower().startswith("readme") and text is not None:
                readmes.append(rel)

            # Java analysis
            if ext == ".java" and text is not None:
                java_info = analyze_java_source(text)
                if java_info.package:
                    packages_count[java_info.package] += 1
                if java_info.has_main:
                    # try to compute class names
                    for t in java_info.types:
                        if t.get("name"):
                            fq = f"{java_info.package}.{t['name']}" if java_info.package else t["name"]
                            java_main_classes.append(fq)
                            break

            all_files.append(CollectedFile(p, rel, size, text, java_info))

    tree = build_tree(root, exclude_dirs=exclude_dirs)

    # root packages (heuristic: take first 1-3 segments that are common)
    pkg_list = list(packages_count.keys())
    root_pkgs: List[str] = []
    if pkg_list:
        # pick most common first segment group
        first_seg = defaultdict(int)
        for pkg in pkg_list:
            first_seg[pkg.split(".")[0]] += packages_count[pkg]
        common_first = sorted(first_seg.items(), key=lambda x: x[1], reverse=True)[:5]
        for seg, _ in common_first:
            # optionally extend to two segments if exists
            candidates = [p for p in pkg_list if p.startswith(seg + ".")]
            if not candidates:
                root_pkgs.append(seg)
                continue
            second_seg = defaultdict(int)
            for p in candidates:
                parts = p.split(".")
                if len(parts) >= 2:
                    second_seg[f"{parts[0]}.{parts[1]}"] += packages_count[p]
            if second_seg:
                root_pkgs.append(sorted(second_seg.items(), key=lambda x: x[1], reverse=True)[0][0])
            else:
                root_pkgs.append(seg)

    frameworks = detect_frameworks_from_strings(all_dep_strings)

    return ProjectScan(
        root=root,
        files=all_files,
        tree=tree,
        pom_infos=pom_infos,
        gradle_files=gradle_files,
        readme_files=readmes,
        entrypoints=sorted(set(java_main_classes)),
        packages=dict(sorted(packages_count.items(), key=lambda x: x[1], reverse=True)),
        root_packages=sorted(set(root_pkgs)),
        framework_hints=frameworks,
    )


# ---------------------------
# Reporting
# ---------------------------
def make_overview(scan: ProjectScan) -> str:
    total = len(scan.files)
    java_files = sum(1 for f in scan.files if f.path.suffix.lower() == ".java")
    text_files = sum(1 for f in scan.files if f.text is not None)
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    build_systems = []
    if scan.pom_infos:
        build_systems.append("Maven (pom.xml)")
    if scan.gradle_files:
        build_systems.append("Gradle (build.gradle)")
    if not build_systems:
        build_systems.append("Unknown / custom")

    lines = []
    lines.append(f"# Project Report")
    lines.append("")
    lines.append(f"- Generated: **{now}**")
    lines.append(f"- Root: `{scan.root}`")
    lines.append(f"- Total files scanned: **{total}**")
    lines.append(f"- Java files: **{java_files}**")
    lines.append(f"- Text files included: **{text_files}**")
    lines.append(f"- Build: **{', '.join(build_systems)}**")
    if scan.framework_hints:
        lines.append(f"- Framework hints: **{', '.join(scan.framework_hints)}**")
    if scan.root_packages:
        lines.append(f"- Root package candidates: **{', '.join(scan.root_packages)}**")
    if scan.entrypoints:
        lines.append("")
        lines.append("## Entrypoints (main)")
        for e in scan.entrypoints[:50]:
            lines.append(f"- `{e}`")
        if len(scan.entrypoints) > 50:
            lines.append(f"- … (more: {len(scan.entrypoints) - 50})")
    if scan.readme_files:
        lines.append("")
        lines.append("## Readme/docs found")
        for r in scan.readme_files:
            lines.append(f"- `{r}`")
    lines.append("")
    return "\n".join(lines)


def make_build_section(scan: ProjectScan) -> str:
    lines = []
    lines.append("## Build & Dependencies")
    lines.append("")

    if scan.pom_infos:
        lines.append("### Maven (pom.xml)")
        for pom in scan.pom_infos:
            lines.append(f"- File: `{pom.get('path')}`")
            lines.append(f"  - groupId: `{pom.get('groupId')}`")
            lines.append(f"  - artifactId: `{pom.get('artifactId')}`")
            lines.append(f"  - version: `{pom.get('version')}`")
            lines.append(f"  - packaging: `{pom.get('packaging')}`")

            mods = pom.get("modules") or []
            if mods:
                lines.append("  - modules:")
                for m in mods:
                    lines.append(f"    - `{m}`")

            deps = pom.get("dependencies") or []
            if deps:
                lines.append("  - dependencies (first 200):")
                for d in deps[:200]:
                    gid = d.get("groupId") or ""
                    aid = d.get("artifactId") or ""
                    ver = d.get("version") or ""
                    scope = d.get("scope") or ""
                    lines.append(f"    - `{gid}:{aid}:{ver}`" + (f" (scope={scope})" if scope else ""))
                if len(deps) > 200:
                    lines.append(f"    - … (more: {len(deps)-200})")

            plugins = pom.get("plugins") or []
            if plugins:
                lines.append("  - plugins:")
                for p in plugins[:100]:
                    lines.append(f"    - `{(p.get('groupId') or '')}:{(p.get('artifactId') or '')}:{(p.get('version') or '')}`")
                if len(plugins) > 100:
                    lines.append(f"    - … (more: {len(plugins)-100})")
            lines.append("")

    if scan.gradle_files:
        lines.append("### Gradle")
        for rel, deps in scan.gradle_files:
            lines.append(f"- File: `{rel}`")
            if deps:
                lines.append("  - dependencies lines (first 200):")
                for d in deps[:200]:
                    lines.append(f"    - `{d}`")
            else:
                lines.append("  - dependencies: (not detected)")
            lines.append("")

    if not scan.pom_infos and not scan.gradle_files:
        lines.append("- No pom.xml / build.gradle detected.")
        lines.append("")

    return "\n".join(lines)


def make_structure_section(scan: ProjectScan) -> str:
    lines = []
    lines.append("## Project Tree")
    lines.append("")
    lines.append("```")
    lines.append(scan.tree)
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def make_packages_section(scan: ProjectScan) -> str:
    lines = []
    lines.append("## Packages (Java)")
    lines.append("")
    if not scan.packages:
        lines.append("- No Java packages detected.")
        lines.append("")
        return "\n".join(lines)

    lines.append("Top packages by file count (first 50):")
    for pkg, cnt in list(scan.packages.items())[:50]:
        lines.append(f"- `{pkg}` → **{cnt}** file(s)")
    if len(scan.packages) > 50:
        lines.append(f"- … (more: {len(scan.packages) - 50})")
    lines.append("")
    return "\n".join(lines)


def make_files_section(scan: ProjectScan) -> str:
    lines = []
    lines.append("## Files (Full Content)")
    lines.append("")
    lines.append("> Qeyd: Binary fayllar daxil edilmir. Böyük fayllar `TRUNCATED` ola bilər.")
    lines.append("")

    for f in sorted(scan.files, key=lambda x: x.rel.lower()):
        lines.append(f"### `{f.rel}`")
        lines.append(f"- Size: {f.size} bytes" if f.size >= 0 else "- Size: unknown")
        if f.text is None:
            lines.append("- Included: **no** (binary / skipped)")
            lines.append("")
            continue

        if f.java_info:
            ji = f.java_info
            lines.append("- Type: **Java source**")
            lines.append(f"- package: `{ji.package}`")
            if ji.types:
                lines.append("- types:")
                for t in ji.types[:20]:
                    lines.append(
                        f"  - {t.get('kind')} `{t.get('name')}`"
                        + (f" extends `{t.get('extends')}`" if t.get("extends") else "")
                        + (f" implements `{t.get('implements')}`" if t.get("implements") else "")
                    )
                if len(ji.types) > 20:
                    lines.append(f"  - … (more: {len(ji.types)-20})")
            lines.append(f"- methods detected: **{ji.method_count}**")
            if ji.public_method_signatures:
                lines.append("- sample method signatures (first 50):")
                for s in ji.public_method_signatures[:50]:
                    lines.append(f"  - `{s}`")
            if ji.imports:
                lines.append(f"- imports: **{len(ji.imports)}** (first 50)")
                for imp in ji.imports[:50]:
                    lines.append(f"  - `{imp}`")
            if ji.has_main:
                lines.append("- main(): **YES**")
            if ji.spring_hints:
                lines.append(f"- annotations hint: {', '.join(ji.spring_hints)}")
        else:
            lines.append("- Type: text/config")

        lang = fence_lang(f.path)
        lines.append("")
        lines.append(f"```{lang}".rstrip())
        lines.append(f.text.rstrip("\n"))
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def make_ai_context(scan: ProjectScan) -> str:
    """
    AI prompt üçün: hər fayl delimitər formatında.
    """
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append(f"PROJECT_CONTEXT")
    lines.append(f"Generated: {now}")
    lines.append(f"Root: {scan.root}")
    if scan.framework_hints:
        lines.append(f"Framework hints: {', '.join(scan.framework_hints)}")
    if scan.entrypoints:
        lines.append(f"Entrypoints: {', '.join(scan.entrypoints[:20])}" + (" ..." if len(scan.entrypoints) > 20 else ""))
    lines.append("")
    lines.append("TREE:")
    lines.append(scan.tree)
    lines.append("")
    lines.append("=" * 80)
    lines.append("FILES:")
    lines.append("=" * 80)
    lines.append("")

    for f in sorted(scan.files, key=lambda x: x.rel.lower()):
        if f.text is None:
            continue
        lines.append(f"===== FILE: {f.rel} =====")
        if f.java_info and f.java_info.package:
            lines.append(f"// package: {f.java_info.package}")
        lines.append(f.text.rstrip("\n"))
        lines.append("")
        lines.append("=" * 80)
        lines.append("")

    return "\n".join(lines)


# ---------------------------
# Main
# ---------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deep Java project analyzer -> report + AI context.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("path", nargs="?", help="Project folder path (Java project root).")
    parser.add_argument("--out", default="project_report.md", help="Output report file (default: project_report.md)")
    parser.add_argument("--context", default="ai_context.txt", help="Output AI context file (default: ai_context.txt)")
    parser.add_argument("--max-file-kb", type=int, default=512, help="Max bytes per file to include (default: 512KB)")
    parser.add_argument("--exclude-dir", action="append", default=[], help="Extra dirs to exclude (can repeat)")
    parser.add_argument("--include-all-text", action="store_true", default=True, help="Include all text-like files (default: true)")

    args = parser.parse_args()

    if not args.path:
        try:
            args.path = input("Qovluq yolunu yazın (məs: /home/me/att-project): ").strip()
        except KeyboardInterrupt:
            print("\nCanceled.")
            return 1

    root = Path(args.path).expanduser()
    if not root.exists() or not root.is_dir():
        print(f"[ERROR] Folder not found: {root}")
        return 2

    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)
    exclude_dirs.update(args.exclude_dir or [])

    max_file_bytes = int(args.max_file_kb) * 1024

    print(f"[INFO] Scanning: {root}")
    scan = scan_project(
        root=root,
        exclude_dirs=exclude_dirs,
        max_file_bytes=max_file_bytes,
        include_all_text=args.include_all_text
    )

    report_parts = [
        make_overview(scan),
        make_structure_section(scan),
        make_build_section(scan),
        make_packages_section(scan),
        make_files_section(scan),
    ]
    report = "\n".join(report_parts)

    out_path = Path(args.out).expanduser()
    ctx_path = Path(args.context).expanduser()

    safe_write(out_path, report)
    safe_write(ctx_path, make_ai_context(scan))

    print(f"[DONE] Report:   {out_path.resolve()}")
    print(f"[DONE] Context:  {ctx_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
