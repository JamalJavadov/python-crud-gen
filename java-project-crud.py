#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
java-project-crud.py  (PRO FINAL)

Professional, safe-by-default CRUD generator for Java Spring Boot projects.

Highlights:
- CLI (argparse) + interactive fallback
- Detect Maven/Gradle, base package, api prefix, package style
- Parse @Entity classes via javalang AST
- Patch entities (selected by default, optional --patch-all) with backup session:
  - Lombok @Getter/@Setter (idempotent; doesn't break @Data)
  - @NoArgsConstructor(access = PROTECTED) if missing
  - Auditing fields + @EntityListeners(AuditingEntityListener.class)
  - Soft delete flag + @Where(deleted=false)
  - Optimistic locking: @Version Long version
- Generates production-grade CRUD for selected entities:
  - Repository extends JpaRepository + JpaSpecificationExecutor
  - Specifications: q + field filters + min/max + from/to + relationId(s)
- DTOs (Request/Response) with validations
  - MapStruct Mapper (builder disabled; relations ignored on write; ids mapped on read)
  - Service with relation resolving (IDs) and soft delete filtering
  - Controller (CRUD: create/get/getAll/update/delete)
- Common layer:
  - ApiError + ErrorCode
  - GlobalExceptionHandler (400/404/409/500) + safe internal messaging + logging
  - AuditingConfig + AuditorAware
  - OpenAPI config (springdoc) optional (enabled by default)
- Infra:
  - application-dev.yml / application-prod.yml
  - docker-compose.yml with postgres healthcheck
- Safety:
  - Overwrite only BOT_MARKER files in managed packages (default)
  - else write to .crudbot/generated/.. (compile-safe; avoids *.generated.java public-class mismatch)
  - Backups: one session per run (.crudbot/backups/<timestamp>/)
- Optional compile check (mvn/gradle)

Deps:
  pip install javalang rich
"""

from __future__ import annotations

import argparse
import os
import re
import json
import time
import shutil
import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

# deps
try:
    import javalang
except Exception:
    javalang = None

try:
    from rich.console import Console
    from rich.table import Table
except Exception:
    Console = None
    Table = None

console = Console() if Console else None

# ---------------- constants ----------------

BOT_MARKER = '@jakarta.annotation.Generated("java-project-crud.py")'

EXCLUDE_DIRS = {
    ".crudbot",
    ".git", ".idea", ".vscode",
    "target", "build", "out", ".gradle",
    "node_modules", "__pycache__", ".mvn",
}
EXCLUDE_FILES = {".DS_Store"}

DEFAULT_LOMBOK_VERSION = "1.18.32"
MAPSTRUCT_VERSION = "1.5.5.Final"
SPRINGDOC_VERSION = "2.5.0"
SPRINGDOC_ARTIFACT = "springdoc-openapi-starter-webmvc-ui"
POSTGRES_VERSION = "42.7.3"

SPRING_BOOT_APP_RE = re.compile(r"@SpringBootApplication\b")
JAVA_PACKAGE_RE = re.compile(r"^\s*package\s+([a-zA-Z0-9_.]+)\s*;", re.M)

ENTITY_ANNOT = "Entity"
ID_ANNOT = "Id"
REL_SINGLE = {"ManyToOne", "OneToOne"}
REL_MULTI = {"OneToMany", "ManyToMany"}

STRING_TYPES = {"String"}
BOOLEAN_TYPES = {"boolean", "Boolean"}
PRIMITIVE_TO_WRAPPER = {
    "int": "Integer",
    "long": "Long",
    "double": "Double",
    "float": "Float",
    "short": "Short",
    "byte": "Byte",
    "boolean": "Boolean",
    "char": "Character",
}
NUMERIC_TYPES = {
    "Integer", "Long", "Double", "Float", "Short", "Byte",
    "int", "long", "double", "float", "short", "byte",
    "BigDecimal",
}
JAVA_TIME_TYPES = {"LocalDate", "LocalDateTime", "Instant", "OffsetDateTime", "ZonedDateTime"}

# ---------------- models ----------------

@dataclass
class Style:
    controller_pkg: str
    service_pkg: str
    repository_pkg: str
    dto_root_pkg: str
    mapper_pkg: str
    spec_pkg: str
    common_pkg: str
    exception_pkg: str
    audit_pkg: str

@dataclass
class Project:
    root: Path
    src_main_java: Path
    src_main_resources: Path
    base_package: str
    api_prefix: str
    build_kind: str  # maven | gradle_groovy | gradle_kts | unknown
    build_file: Optional[Path]
    build_root: Path
    style: Style
    has_security: bool
    with_openapi: bool
    overwrite_policy: str  # marked | force | never
    backup_mode: str       # none | managed | all
    dry_run: bool

@dataclass
class Field:
    name: str
    type_name: str
    is_id: bool
    is_rel_single: bool
    is_rel_multi: bool
    rel_target: Optional[str]
    is_collection: bool
    column_nullable: Optional[bool]
    column_length: Optional[int]
    has_notnull: bool
    size_max: Optional[int]
    has_email: bool
    has_positive: bool

@dataclass
class Entity:
    name: str
    package: str
    file_path: Path
    file_rel: str
    id_field: str
    id_type: str
    fields: List[Field]

# ---------------- tiny utils ----------------

def p(msg: str) -> None:
    if console:
        console.print(msg)
    else:
        print(msg)

def read_text(pth: Path) -> str:
    return pth.read_text(encoding="utf-8", errors="replace")

def write_text(pth: Path, txt: str) -> None:
    pth.parent.mkdir(parents=True, exist_ok=True)
    pth.write_text(txt, encoding="utf-8", errors="replace")

def relpath(pth: Path, root: Path) -> str:
    try:
        return str(pth.relative_to(root))
    except Exception:
        return str(pth)

def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

def strip_quotes(s: str) -> str:
    return s.strip().strip('"').strip("'")

def to_pkg_dir(src_main_java: Path, pkg: str) -> Path:
    return src_main_java / Path(pkg.replace(".", "/"))

def camel(s: str) -> str:
    return s[:1].upper() + s[1:] if s else s

def lower_first(s: str) -> str:
    return s[:1].lower() + s[1:] if s else s

def pluralize(name: str) -> str:
    if name.endswith("y") and len(name) > 1 and name[-2].lower() not in "aeiou":
        return name[:-1] + "ies"
    if name.endswith("s"):
        return name + "es"
    return name + "s"

def route_name(entity_name: str) -> str:
    return pluralize(entity_name).lower()

def iter_java_files(root: Path) -> List[Path]:
    out: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fn in filenames:
            if fn in EXCLUDE_FILES:
                continue
            pth = Path(dirpath) / fn
            if pth.suffix.lower() == ".java":
                out.append(pth)
    return sorted(out)

def find_first_dir(root: Path, rel: str) -> Optional[Path]:
    cand = root / rel
    if cand.exists() and cand.is_dir():
        return cand
    for pth in root.rglob(rel):
        if pth.is_dir() and not any(x in pth.parts for x in EXCLUDE_DIRS):
            return pth
    return None

def wrapper_type(t: str) -> str:
    return PRIMITIVE_TO_WRAPPER.get(t, t)

def java_simple_type(type_name: str) -> str:
    t = type_name.strip().replace("[]", "")
    if "<" in t:
        t = t.split("<", 1)[0].strip()
    return t

def add_type_imports(type_name: str, imports: Set[str]) -> None:
    t = type_name.strip()
    # handle generics
    if "<" in t and ">" in t:
        inner = t.split("<", 1)[1].split(">", 1)[0].strip()
        add_type_imports(inner, imports)
        t = t.split("<", 1)[0].strip()

    t = PRIMITIVE_TO_WRAPPER.get(t, t)
    if t == "UUID":
        imports.add("java.util.UUID")
    elif t == "BigDecimal":
        imports.add("java.math.BigDecimal")
    elif t in {"LocalDate", "LocalDateTime", "Instant", "OffsetDateTime", "ZonedDateTime"}:
        imports.add(f"java.time.{t}")

def render_import_block(items: Set[str], extra: Optional[List[str]] = None) -> str:
    """Render Java import lines.

    Accepts a mixed set where each item may be:
      - a fully qualified name (e.g. 'java.util.List')
      - an 'import ...' line with or without a trailing semicolon

    Always normalizes to 'import <FQN>;' and sorts/deduplicates.
    """
    out: Set[str] = set()

    def add_one(raw: str) -> None:
        if raw is None:
            return
        s = str(raw).strip()
        if not s:
            return
        # Normalize: strip leading 'import' (if any) and trailing ';'
        s2 = re.sub(r"^\s*import\s+", "", s).rstrip(";").strip()
        if not s2:
            return
        out.add(f"import {s2};")

    for x in (items or set()):
        add_one(x)

    if extra:
        for e in extra:
            add_one(e)

    return ("\n".join(sorted(out)) + "\n") if out else ""


# ---------------- versions config ----------------

def load_versions(proj_root: Path) -> Dict[str, str]:
    cfg = proj_root / ".crudbot" / "versions.json"
    if not cfg.exists():
        return {}
    try:
        data = json.loads(read_text(cfg))
        if isinstance(data, dict):
            return {str(k).lower(): str(v) for k, v in data.items()}
    except Exception:
        return {}
    return {}

def get_version(versions: Dict[str, str], key: str, default: str) -> str:
    return versions.get(key.lower(), default)

# ---------------- backups / manifest / safe-write ----------------

_BACKUP_SESSION_DIR: Dict[str, Path] = {}

def crudbot_dir(root: Path) -> Path:
    d = root / ".crudbot"
    d.mkdir(parents=True, exist_ok=True)
    return d

def get_backup_session_dir(project_root: Path) -> Path:
    key = str(project_root.resolve())
    if key in _BACKUP_SESSION_DIR:
        return _BACKUP_SESSION_DIR[key]
    d = crudbot_dir(project_root) / "backups" / time.strftime("%Y%m%d-%H%M%S")
    d.mkdir(parents=True, exist_ok=True)
    _BACKUP_SESSION_DIR[key] = d
    return d

def load_manifest(root: Path) -> Dict[str, str]:
    mf = crudbot_dir(root) / "manifest.json"
    if not mf.exists():
        return {}
    try:
        return json.loads(read_text(mf))
    except Exception:
        return {}

def save_manifest(root: Path, manifest: Dict[str, str]) -> None:
    mf = crudbot_dir(root) / "manifest.json"
    write_text(mf, json.dumps(manifest, indent=2, ensure_ascii=False))

def file_has_marker(path: Path) -> bool:
    try:
        return path.exists() and (BOT_MARKER in read_text(path))
    except Exception:
        return False

def is_managed_path(proj: Project, path: Path) -> bool:
    s = proj.style
    managed_pkgs = [
        s.controller_pkg, s.service_pkg, s.repository_pkg, s.dto_root_pkg,
        s.mapper_pkg, s.spec_pkg, s.common_pkg, s.exception_pkg, s.audit_pkg,
    ]
    managed_dirs = [to_pkg_dir(proj.src_main_java, pkg) for pkg in managed_pkgs]
    for d in managed_dirs:
        try:
            path.relative_to(d)
            return True
        except Exception:
            continue
    return False

def backup_file(proj: Project, f: Path, force: bool = False) -> None:
    if not f.exists():
        return
    if proj.backup_mode == "none":
        return
    if not force:
        if proj.backup_mode == "managed" and not is_managed_path(proj, f):
            return
    bdir = get_backup_session_dir(proj.root)
    rel = relpath(f, proj.root)
    target = bdir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(f, target)

def sanitize_java_file(path: Path) -> None:
    if not path.exists() or path.suffix != ".java":
        return
    txt = read_text(path)
    if not txt.endswith("\n"):
        write_text(path, txt + "\n")

def _alt_generated_path(proj: Project, path: Path) -> Path:
    # compile-safe location: under .crudbot/generated/..., preserving relative project path
    rel = relpath(path, proj.root)
    return crudbot_dir(proj.root) / "generated" / rel

def safe_write(proj: Project, path: Path, content: str, manifest: Dict[str, str]) -> Tuple[bool, str]:
    """
    Overwrite policy:
      - marked: overwrite only if managed AND existing has BOT_MARKER else write to .crudbot/generated/...
      - force:  overwrite managed files even if not marked (still backups)
      - never:  always write to .crudbot/generated/... if file exists
    """
    content = content.rstrip() + "\n"
    target = path

    if target.exists():
        managed = is_managed_path(proj, target)

        if proj.overwrite_policy == "never":
            target = _alt_generated_path(proj, target)

        elif managed:
            if proj.overwrite_policy == "marked" and not file_has_marker(target):
                target = _alt_generated_path(proj, target)
            else:
                backup_file(proj, target)  # managed overwrite backup
        else:
            target = _alt_generated_path(proj, target)

    rel = relpath(target, proj.root)

    if proj.dry_run:
        manifest[rel] = sha256_text(content)
        return True, rel

    write_text(target, content)
    sanitize_java_file(target)
    manifest[rel] = sha256_text(content)
    return True, rel

# ---------------- project detection ----------------

def find_build(root: Path) -> Tuple[str, Optional[Path]]:
    pom = root / "pom.xml"
    if pom.exists():
        return "maven", pom
    bg = root / "build.gradle"
    if bg.exists():
        return "gradle_groovy", bg
    bk = root / "build.gradle.kts"
    if bk.exists():
        return "gradle_kts", bk

    for pth in root.rglob("pom.xml"):
        if not any(x in pth.parts for x in EXCLUDE_DIRS):
            return "maven", pth
    for pth in root.rglob("build.gradle.kts"):
        if not any(x in pth.parts for x in EXCLUDE_DIRS):
            return "gradle_kts", pth
    for pth in root.rglob("build.gradle"):
        if not any(x in pth.parts for x in EXCLUDE_DIRS):
            return "gradle_groovy", pth

    return "unknown", None

def detect_base_package(java_files: List[Path]) -> str:
    for f in java_files:
        txt = read_text(f)
        if SPRING_BOOT_APP_RE.search(txt):
            m = JAVA_PACKAGE_RE.search(txt)
            if m:
                return m.group(1)
    freq: Dict[str, int] = {}
    for f in java_files[:4000]:
        m = JAVA_PACKAGE_RE.search(read_text(f))
        if m:
            freq[m.group(1)] = freq.get(m.group(1), 0) + 1
    if not freq:
        return "com.example"
    return sorted(freq.items(), key=lambda x: x[1], reverse=True)[0][0]

def detect_api_prefix(root: Path) -> str:
    found_v1 = False
    found_api = False
    for f in iter_java_files(root):
        txt = read_text(f)
        if "@RestController" not in txt and "@Controller" not in txt:
            continue
        for path in re.findall(r'@RequestMapping\(\s*"([^"]+)"\s*\)', txt):
            if path.startswith("/api/v1"):
                found_v1 = True
            elif path.startswith("/api"):
                found_api = True
    if found_v1:
        return "/api/v1"
    if found_api:
        return "/api"
    return "/api/v1"

def detect_security(build_file: Optional[Path]) -> bool:
    if not build_file or not build_file.exists():
        return False
    txt = read_text(build_file).lower()
    return "spring-boot-starter-security" in txt or "spring-security" in txt

def detect_style(root: Path, base_pkg: str) -> Style:
    pkgs: Dict[str, List[str]] = {
        "controller": [],
        "service": [],
        "repository": [],
        "dto": [],
        "mapper": [],
        "spec": [],
        "common": [],
        "exception": [],
        "audit": [],
    }
    for f in iter_java_files(root):
        m = JAVA_PACKAGE_RE.search(read_text(f))
        if not m:
            continue
        pkg = m.group(1)
        if ".controller" in pkg: pkgs["controller"].append(pkg)
        if ".service" in pkg: pkgs["service"].append(pkg)
        if ".repository" in pkg or ".repo" in pkg: pkgs["repository"].append(pkg)
        if ".dto" in pkg: pkgs["dto"].append(pkg)
        if ".mapper" in pkg: pkgs["mapper"].append(pkg)
        if ".spec" in pkg or ".specification" in pkg: pkgs["spec"].append(pkg)
        if ".common" in pkg: pkgs["common"].append(pkg)
        if ".exception" in pkg: pkgs["exception"].append(pkg)
        if ".audit" in pkg or ".config" in pkg: pkgs["audit"].append(pkg)

    def pick(key: str, suffix: str) -> str:
        arr = sorted(set(pkgs[key]), key=lambda x: (len(x), x))
        return arr[0] if arr else f"{base_pkg}.{suffix}"

    return Style(
        controller_pkg=pick("controller", "controller"),
        service_pkg=pick("service", "service"),
        repository_pkg=pick("repository", "repository"),
        dto_root_pkg=pick("dto", "dto"),
        mapper_pkg=pick("mapper", "mapper"),
        spec_pkg=pick("spec", "spec"),
        common_pkg=pick("common", "common"),
        exception_pkg=pick("exception", "exception"),
        audit_pkg=pick("audit", "audit"),
    )

def load_project(root: Path, *, with_openapi: bool, overwrite_policy: str, backup_mode: str, dry_run: bool,
                 api_prefix_override: Optional[str] = None) -> Project:
    java_files = iter_java_files(root)
    if not java_files:
        raise RuntimeError("No .java files found.")
    src_main_java = find_first_dir(root, "src/main/java")
    if not src_main_java:
        raise RuntimeError("src/main/java not found.")
    src_main_resources = find_first_dir(root, "src/main/resources") or (root / "src/main/resources")
    base_pkg = detect_base_package(java_files)
    api_prefix = api_prefix_override or detect_api_prefix(root)
    build_kind, build_file = find_build(root)
    build_root = build_file.parent if build_file else root
    style = detect_style(root, base_pkg)
    has_security = detect_security(build_file)
    return Project(
        root=root,
        src_main_java=src_main_java,
        src_main_resources=src_main_resources,
        base_package=base_pkg,
        api_prefix=api_prefix,
        build_kind=build_kind,
        build_file=build_file,
        build_root=build_root,
        style=style,
        has_security=has_security,
        with_openapi=with_openapi,
        overwrite_policy=overwrite_policy,
        backup_mode=backup_mode,
        dry_run=dry_run,
    )

# ---------------- entity parsing (AST) ----------------

def _type_to_str(t) -> str:
    try:
        base = t.name if hasattr(t, "name") else str(t)
        if hasattr(t, "arguments") and t.arguments:
            try:
                arg0 = t.arguments[0].type
                g = getattr(arg0, "name", "Object")
                return f"{base}<{g}>"
            except Exception:
                return base + "<...>"
        if hasattr(t, "dimensions") and t.dimensions:
            return base + "[]"
        return base
    except Exception:
        return "Object"

def _extract_ann_kv(ann) -> Dict[str, str]:
    kv: Dict[str, str] = {}
    try:
        el = getattr(ann, "element", None)
        if el is None:
            return kv
        if isinstance(el, list):
            for e in el:
                if hasattr(e, "name") and hasattr(e, "value"):
                    kv[e.name] = str(getattr(e.value, "value", e.value))
    except Exception:
        pass
    return kv

def parse_entities(proj: Project) -> List[Entity]:
    if javalang is None:
        raise RuntimeError("Missing dependency: javalang. Install: pip install javalang rich")

    entities: List[Entity] = []
    for f in iter_java_files(proj.root):
        txt = read_text(f)
        if "@Entity" not in txt:
            continue
        try:
            tree = javalang.parse.parse(txt)
        except Exception:
            continue

        pkg = tree.package.name if tree.package else ""
        for t in tree.types:
            anns = getattr(t, "annotations", None) or []
            ann_names = {a.name for a in anns}
            if ENTITY_ANNOT not in ann_names:
                continue

            id_field, id_type = "id", "Long"
            fields: List[Field] = []

            for node in t.body:
                if not isinstance(node, javalang.tree.FieldDeclaration):
                    continue
                if getattr(node, "modifiers", None) and "static" in node.modifiers:
                    continue

                ftype = _type_to_str(node.type)
                ann_list = node.annotations or []
                ann_names2 = {a.name for a in ann_list}

                is_id = ID_ANNOT in ann_names2
                is_rel_single = any(a in ann_names2 for a in REL_SINGLE)
                is_rel_multi = any(a in ann_names2 for a in REL_MULTI)

                rel_target = None
                is_collection = False
                if is_rel_multi:
                    if "<" in ftype and ">" in ftype:
                        rel_target = ftype.split("<", 1)[1].split(">", 1)[0].strip()
                    is_collection = True
                elif is_rel_single:
                    rel_target = ftype

                column_nullable = None
                column_length = None
                has_notnull = "NotNull" in ann_names2
                has_email = "Email" in ann_names2
                has_positive = "Positive" in ann_names2
                size_max = None

                for a in ann_list:
                    if a.name in {"Column", "JoinColumn"}:
                        kv = _extract_ann_kv(a)
                        if "nullable" in kv:
                            v = kv["nullable"].strip().lower()
                            if v in {"true", "false"}:
                                column_nullable = (v == "true")
                        if "length" in kv:
                            try:
                                column_length = int(kv["length"])
                            except Exception:
                                pass
                    if a.name == "Size":
                        kv = _extract_ann_kv(a)
                        if "max" in kv:
                            try:
                                size_max = int(kv["max"])
                            except Exception:
                                pass

                for decl in node.declarators:
                    fname = decl.name
                    fields.append(Field(
                        name=fname,
                        type_name=ftype,
                        is_id=is_id,
                        is_rel_single=is_rel_single,
                        is_rel_multi=is_rel_multi,
                        rel_target=rel_target,
                        is_collection=is_collection,
                        column_nullable=column_nullable,
                        column_length=column_length,
                        has_notnull=has_notnull,
                        size_max=size_max,
                        has_email=has_email,
                        has_positive=has_positive,
                    ))
                    if is_id:
                        id_field, id_type = fname, ftype

            if not any(x.is_id for x in fields):
                for fm in fields:
                    if fm.name == "id":
                        id_field, id_type = "id", fm.type_name
                        break

            entities.append(Entity(
                name=t.name,
                package=pkg,
                file_path=f,
                file_rel=relpath(f, proj.root),
                id_field=id_field,
                id_type=id_type,
                fields=fields,
            ))

    return sorted(entities, key=lambda e: (e.package, e.name))

def entity_map(entities: List[Entity]) -> Dict[str, Entity]:
    return {e.name: e for e in entities}

def required_entities(selected: List[Entity], emap: Dict[str, Entity]) -> List[Entity]:
    """Selected + direct relation targets (for generating repositories + NotFound)."""
    out: Dict[str, Entity] = {e.name: e for e in selected}
    for e in selected:
        for f in e.fields:
            if (f.is_rel_single or f.is_rel_multi) and f.rel_target and f.rel_target in emap:
                out[f.rel_target] = emap[f.rel_target]
    return sorted(out.values(), key=lambda x: (x.package, x.name))

# ---------------- build updates ----------------

def ensure_maven_dependencies(proj: Project, versions: Dict[str, str]) -> List[str]:
    changes: List[str] = []
    pom_path = proj.build_file
    if not pom_path or not pom_path.exists():
        return ["pom.xml not found; skipping dependency update."]

    lombok_v = get_version(versions, "lombok", DEFAULT_LOMBOK_VERSION)
    mapstruct_v = get_version(versions, "mapstruct", MAPSTRUCT_VERSION)
    postgres_v = get_version(versions, "postgres", POSTGRES_VERSION)
    springdoc_v = get_version(versions, "springdoc", SPRINGDOC_VERSION)

    txt = read_text(pom_path)
    original = txt

    def has_artifact(artifact: str) -> bool:
        return f"<artifactId>{artifact}</artifactId>" in txt

    deps: List[str] = []

    for art in ["spring-boot-starter-web", "spring-boot-starter-data-jpa", "spring-boot-starter-validation"]:
        if not has_artifact(art):
            deps.append(f"""<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>{art}</artifactId>
</dependency>""")
            changes.append(f"Added: {art}")

    if not has_artifact("spring-boot-starter-test"):
        deps.append("""<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-test</artifactId>
  <scope>test</scope>
</dependency>""")
        changes.append("Added: spring-boot-starter-test (test)")

    if not ("<groupId>org.projectlombok</groupId>" in txt and "<artifactId>lombok</artifactId>" in txt):
        deps.append(f"""<dependency>
  <groupId>org.projectlombok</groupId>
  <artifactId>lombok</artifactId>
  <version>{lombok_v}</version>
  <scope>provided</scope>
</dependency>""")
        changes.append("Added: lombok")

    if not ("<groupId>org.mapstruct</groupId>" in txt and "<artifactId>mapstruct</artifactId>" in txt):
        deps.append(f"""<dependency>
  <groupId>org.mapstruct</groupId>
  <artifactId>mapstruct</artifactId>
  <version>{mapstruct_v}</version>
</dependency>""")
        changes.append("Added: mapstruct")

    if proj.with_openapi and not has_artifact(SPRINGDOC_ARTIFACT):
        deps.append(f"""<dependency>
  <groupId>org.springdoc</groupId>
  <artifactId>{SPRINGDOC_ARTIFACT}</artifactId>
  <version>{springdoc_v}</version>
</dependency>""")
        changes.append(f"Added: {SPRINGDOC_ARTIFACT}")

    if not ("<groupId>org.postgresql</groupId>" in txt and "<artifactId>postgresql</artifactId>" in txt):
        deps.append(f"""<dependency>
  <groupId>org.postgresql</groupId>
  <artifactId>postgresql</artifactId>
  <version>{postgres_v}</version>
  <scope>runtime</scope>
</dependency>""")
        changes.append("Added: postgresql (runtime)")

    if deps:
        if "<dependencies>" in txt:
            idx = txt.rfind("</dependencies>")
            txt = txt[:idx] + "\n" + "\n".join(deps) + "\n" + txt[idx:]
        else:
            idx = txt.rfind("</project>")
            txt = txt[:idx] + "\n<dependencies>\n" + "\n".join(deps) + "\n</dependencies>\n" + txt[idx:]

    def ensure_compiler_plugin(s: str) -> Tuple[str, bool]:
        if "<artifactId>maven-compiler-plugin</artifactId>" in s and "<annotationProcessorPaths>" in s:
            return s, False

        ap_block = f"""
          <annotationProcessorPaths>
            <path>
              <groupId>org.projectlombok</groupId>
              <artifactId>lombok</artifactId>
              <version>{lombok_v}</version>
            </path>
            <path>
              <groupId>org.mapstruct</groupId>
              <artifactId>mapstruct-processor</artifactId>
              <version>{mapstruct_v}</version>
            </path>
          </annotationProcessorPaths>
""".rstrip()

        if "<artifactId>maven-compiler-plugin</artifactId>" in s:
            m = re.search(r"(<plugin>\s*.*?<artifactId>maven-compiler-plugin</artifactId>.*?</plugin>)", s, flags=re.S)
            if not m:
                return s, False
            blk = m.group(1)
            if "<configuration>" in blk:
                blk2 = re.sub(r"</configuration>", ap_block + "\n        </configuration>", blk, count=1, flags=re.S)
            else:
                blk2 = blk.replace("</plugin>", f"""
        <configuration>
{ap_block}
        </configuration>
      </plugin>""")
            s2 = s.replace(blk, blk2)
            return s2, (s2 != s)

        plugin_full = f"""
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <configuration>
{ap_block}
        </configuration>
      </plugin>
""".rstrip()

        if "<plugins>" in s:
            idx = s.rfind("</plugins>")
            s2 = s[:idx] + plugin_full + "\n" + s[idx:]
            return s2, True

        idx = s.rfind("</project>")
        if idx != -1:
            s2 = s[:idx] + f"""
  <build>
    <plugins>
{plugin_full}
    </plugins>
  </build>
""" + s[idx:]
            return s2, True
        return s, False

    txt2, changed = ensure_compiler_plugin(txt)
    if changed:
        changes.append("Updated: maven-compiler-plugin annotationProcessorPaths (lombok+mapstruct)")
        txt = txt2

    if txt != original:
        if proj.backup_mode == "all":
            backup_file(proj, pom_path, force=True)
        if not proj.dry_run:
            write_text(pom_path, txt)

    return changes

def _insert_gradle_dep_block(txt: str, line: str) -> str:
    m = re.search(r"(?m)^\s*dependencies\s*\{\s*$", txt)
    if not m:
        return txt.rstrip() + "\n\ndependencies {\n" + line + "}\n"
    i = m.end()
    depth = 1
    while i < len(txt):
        ch = txt[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return txt[:i] + line + txt[i:]
        i += 1
    return txt.rstrip() + "\n" + line

def ensure_gradle_dependencies(proj: Project, versions: Dict[str, str], kts: bool) -> List[str]:
    changes: List[str] = []
    build_path = proj.build_file
    if not build_path or not build_path.exists():
        return ["build.gradle not found; skipping dependency update."]

    lombok_v = get_version(versions, "lombok", DEFAULT_LOMBOK_VERSION)
    mapstruct_v = get_version(versions, "mapstruct", MAPSTRUCT_VERSION)
    postgres_v = get_version(versions, "postgres", POSTGRES_VERSION)
    springdoc_v = get_version(versions, "springdoc", SPRINGDOC_VERSION)

    txt = read_text(build_path)
    original = txt

    def add(line: str, key: str):
        nonlocal txt
        if key in txt:
            return
        txt = _insert_gradle_dep_block(txt, line)
        changes.append(f"Added: {key}")

    if kts:
        add('    implementation("org.springframework.boot:spring-boot-starter-web")\n', "spring-boot-starter-web")
        add('    implementation("org.springframework.boot:spring-boot-starter-data-jpa")\n', "spring-boot-starter-data-jpa")
        add('    implementation("org.springframework.boot:spring-boot-starter-validation")\n', "spring-boot-starter-validation")
        add('    testImplementation("org.springframework.boot:spring-boot-starter-test")\n', "spring-boot-starter-test")
        add(f'    compileOnly("org.projectlombok:lombok:{lombok_v}")\n', "org.projectlombok:lombok")
        add(f'    annotationProcessor("org.projectlombok:lombok:{lombok_v}")\n', "annotationProcessor(lombok)")
        add(f'    implementation("org.mapstruct:mapstruct:{mapstruct_v}")\n', "org.mapstruct:mapstruct")
        add(f'    annotationProcessor("org.mapstruct:mapstruct-processor:{mapstruct_v}")\n', "mapstruct-processor")
        if proj.with_openapi:
            add(f'    implementation("org.springdoc:{SPRINGDOC_ARTIFACT}:{springdoc_v}")\n', SPRINGDOC_ARTIFACT)
        add(f'    runtimeOnly("org.postgresql:postgresql:{postgres_v}")\n', "org.postgresql:postgresql")
    else:
        add("    implementation 'org.springframework.boot:spring-boot-starter-web'\n", "spring-boot-starter-web")
        add("    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'\n", "spring-boot-starter-data-jpa")
        add("    implementation 'org.springframework.boot:spring-boot-starter-validation'\n", "spring-boot-starter-validation")
        add("    testImplementation 'org.springframework.boot:spring-boot-starter-test'\n", "spring-boot-starter-test")
        add(f"    compileOnly 'org.projectlombok:lombok:{lombok_v}'\n", "org.projectlombok:lombok")
        add(f"    annotationProcessor 'org.projectlombok:lombok:{lombok_v}'\n", "annotationProcessor(lombok)")
        add(f"    implementation 'org.mapstruct:mapstruct:{mapstruct_v}'\n", "org.mapstruct:mapstruct")
        add(f"    annotationProcessor 'org.mapstruct:mapstruct-processor:{mapstruct_v}'\n", "mapstruct-processor")
        if proj.with_openapi:
            add(f"    implementation 'org.springdoc:{SPRINGDOC_ARTIFACT}:{springdoc_v}'\n", SPRINGDOC_ARTIFACT)
        add(f"    runtimeOnly 'org.postgresql:postgresql:{postgres_v}'\n", "org.postgresql:postgresql")

    if txt != original:
        if proj.backup_mode == "all":
            backup_file(proj, build_path, force=True)
        if not proj.dry_run:
            write_text(build_path, txt)

    return changes

def update_build(proj: Project, versions: Dict[str, str]) -> List[str]:
    if not proj.build_file:
        return ["Build file not found; skipping dependency update."]
    if proj.build_kind == "maven":
        return ensure_maven_dependencies(proj, versions)
    if proj.build_kind == "gradle_groovy":
        return ensure_gradle_dependencies(proj, versions, kts=False)
    if proj.build_kind == "gradle_kts":
        return ensure_gradle_dependencies(proj, versions, kts=True)
    return ["Unknown build tool; skipping dependency update."]

# ---------------- configs (profiles + docker) ----------------

def ensure_application_profiles(proj: Project) -> List[str]:
    changes: List[str] = []
    res = proj.src_main_resources
    res.mkdir(parents=True, exist_ok=True)

    app_yml = res / "application.yml"
    dev_yml = res / "application-dev.yml"
    prod_yml = res / "application-prod.yml"
    gen_yml = res / "application.crudbot.generated.yml"

    dev_content = """# GENERATED BY java-project-crud.py
spring:
  datasource:
    url: ${DB_URL:jdbc:postgresql://localhost:5432/app}
    username: ${DB_USER:app}
    password: ${DB_PASS:app}
  jpa:
    hibernate:
      ddl-auto: update
    open-in-view: false
server:
  port: ${PORT:8081}
"""
    prod_content = """# GENERATED BY java-project-crud.py
spring:
  datasource:
    url: ${DB_URL:jdbc:postgresql://localhost:5432/app}
    username: ${DB_USER:app}
    password: ${DB_PASS:app}
  jpa:
    hibernate:
      ddl-auto: validate
    open-in-view: false
server:
  port: ${PORT:8081}
"""

    if not dev_yml.exists():
        if not proj.dry_run:
            write_text(dev_yml, dev_content)
        changes.append("Created application-dev.yml")

    if not prod_yml.exists():
        if not proj.dry_run:
            write_text(prod_yml, prod_content)
        changes.append("Created application-prod.yml")

    base_content = """# GENERATED BY java-project-crud.py
spring:
  profiles:
    active: dev
  jpa:
    open-in-view: false
"""

    if not app_yml.exists():
        if not proj.dry_run:
            write_text(app_yml, base_content)
        changes.append("Created application.yml (active=dev, open-in-view=false)")
    else:
        if file_has_marker(app_yml):
            txt = read_text(app_yml)
            add: List[str] = []
            if "profiles:" not in txt:
                add.append("\n  profiles:\n    active: dev\n")
            if "open-in-view" not in txt:
                add.append("\n  jpa:\n    open-in-view: false\n")
            if add:
                if not proj.dry_run:
                    write_text(app_yml, (txt.rstrip() + "\n" + "".join(add)).rstrip() + "\n")
                changes.append("Updated application.yml (marker-safe)")
        else:
            if not gen_yml.exists():
                if not proj.dry_run:
                    write_text(gen_yml, base_content)
                changes.append("Created application.crudbot.generated.yml (manual merge recommended)")

    return changes

def ensure_docker_compose(proj: Project) -> List[str]:
    changes: List[str] = []
    compose = proj.root / "docker-compose.yml"
    if compose.exists():
        return changes

    content = """# GENERATED BY java-project-crud.py
services:
  postgres:
    image: postgres:16
    container_name: app-postgres
    environment:
      POSTGRES_DB: app
      POSTGRES_USER: app
      POSTGRES_PASSWORD: app
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U app -d app"]
      interval: 5s
      timeout: 5s
      retries: 20
volumes:
  pgdata:
"""
    if not proj.dry_run:
        write_text(compose, content)
    changes.append("Created docker-compose.yml (postgres + healthcheck)")
    return changes

# ---------------- entity patching ----------------

def ensure_import(lines: List[str], fqn: str) -> bool:
    txt = "\n".join(lines)
    if re.search(rf"(?m)^\s*import\s+{re.escape(fqn)}\s*;\s*$", txt):
        return False
    pkg_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith("package "):
            pkg_idx = i
            break
    insert_at = (pkg_idx + 1) if pkg_idx is not None else 0
    while insert_at < len(lines) and (lines[insert_at].strip() == "" or lines[insert_at].strip().startswith("import ")):
        insert_at += 1
    lines.insert(insert_at, f"import {fqn};")
    return True

def patch_entity(proj: Project, ent: Entity) -> List[str]:
    changes: List[str] = []
    pth = ent.file_path
    txt = read_text(pth)
    lines = txt.splitlines()

    class_idx = None
    for i, line in enumerate(lines):
        if re.search(rf"\bclass\s+{re.escape(ent.name)}\b", line):
            class_idx = i
            break
    if class_idx is None:
        return changes

    backup_file(proj, pth, force=True)

    start = max(0, class_idx - 40)
    ann_block = "\n".join(lines[start:class_idx])

    def imp(fqn: str):
        if ensure_import(lines, fqn):
            changes.append(f"import {fqn}")

    has_data = "@Data" in ann_block
    has_getter = "@Getter" in ann_block
    has_setter = "@Setter" in ann_block

    insert_pos = class_idx
    if not has_data and not has_setter:
        imp("lombok.Setter")
        lines.insert(insert_pos, "@Setter")
        changes.append("added @Setter")
        class_idx += 1
        insert_pos += 1

    if not has_data and not has_getter:
        imp("lombok.Getter")
        lines.insert(insert_pos, "@Getter")
        changes.append("added @Getter")
        class_idx += 1

    ann_block = "\n".join(lines[start:class_idx])

    has_noargs_annot = "@NoArgsConstructor" in ann_block
    has_noargs_ctor = re.search(rf"(?m)^\s*(public|protected|private)?\s*{re.escape(ent.name)}\s*\(\s*\)\s*\{{", txt) is not None
    if not has_noargs_annot and not has_noargs_ctor:
        imp("lombok.NoArgsConstructor")
        imp("lombok.AccessLevel")
        lines.insert(class_idx, "@NoArgsConstructor(access = AccessLevel.PROTECTED)")
        changes.append("added @NoArgsConstructor(PROTECTED)")
        class_idx += 1
        ann_block = "\n".join(lines[start:class_idx])

    if "@EntityListeners" not in ann_block:
        imp("jakarta.persistence.EntityListeners")
        imp("org.springframework.data.jpa.domain.support.AuditingEntityListener")
        lines.insert(class_idx, "@EntityListeners(AuditingEntityListener.class)")
        changes.append("added @EntityListeners")
        class_idx += 1
        ann_block = "\n".join(lines[start:class_idx])

    if "@Where" not in ann_block:
        imp("org.hibernate.annotations.Where")
        lines.insert(class_idx, '@Where(clause = "deleted=false")')
        changes.append('added @Where(deleted=false)')
        class_idx += 1

    # field imports
    for fqn in [
        "jakarta.persistence.Column",
        "jakarta.persistence.Version",
        "org.springframework.data.annotation.CreatedDate",
        "org.springframework.data.annotation.LastModifiedDate",
        "org.springframework.data.annotation.CreatedBy",
        "org.springframework.data.annotation.LastModifiedBy",
        "java.time.Instant",
    ]:
        imp(fqn)

    txt2 = "\n".join(lines)
    has_deleted = re.search(r"(?m)^\s*(?:private|protected|public)\s+(?:boolean|Boolean)\s+deleted\b", txt2) is not None
    has_createdAt = re.search(r"\bcreatedAt\b", txt2) is not None
    has_updatedAt = re.search(r"\bupdatedAt\b", txt2) is not None
    has_createdBy = re.search(r"\bcreatedBy\b", txt2) is not None
    has_updatedBy = re.search(r"\bupdatedBy\b", txt2) is not None
    has_version = ("@Version" in txt2) or (re.search(r"(?m)^\s*(?:private|protected|public)\s+Long\s+version\b", txt2) is not None)

    end_idx = None
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip() == "}":
            end_idx = i
            break
    if end_idx is None:
        return changes

    add_block: List[str] = []
    if not has_createdAt:
        add_block += ["", "    @CreatedDate", '    @Column(nullable = false, updatable = false)', "    private Instant createdAt;"]
        changes.append("added createdAt")
    if not has_updatedAt:
        add_block += ["", "    @LastModifiedDate", "    @Column(nullable = true)", "    private Instant updatedAt;"]
        changes.append("added updatedAt")
    if not has_createdBy:
        add_block += ["", "    @CreatedBy", '    @Column(length = 100, updatable = false)', "    private String createdBy;"]
        changes.append("added createdBy")
    if not has_updatedBy:
        add_block += ["", "    @LastModifiedBy", "    @Column(length = 100)", "    private String updatedBy;"]
        changes.append("added updatedBy")
    if not has_version:
        add_block += ["", "    @Version", "    private Long version;"]
        changes.append("added @Version version")
    if not has_deleted:
        add_block += ["", '    @Column(nullable = false)', "    private boolean deleted = false;"]
        changes.append("added deleted")

    if add_block and not proj.dry_run:
        lines[end_idx:end_idx] = add_block
        write_text(pth, "\n".join(lines).rstrip() + "\n")

    return changes

# ---------------- DTO generation ----------------

def dto_pkg(proj: Project, ent: Entity) -> str:
    return f"{proj.style.dto_root_pkg}.{ent.name.lower()}"

def dto_names(ent: Entity) -> Tuple[str, str]:
    return (
        f"{ent.name}RequestDto",
        f"{ent.name}ResponseDto",
    )

def validation_for_field(f: Field, for_patch: bool) -> Tuple[List[str], Set[str]]:
    ann: List[str] = []
    imps: Set[str] = set()

    is_string = f.type_name in STRING_TYPES
    is_numeric = f.type_name in NUMERIC_TYPES

    notnull = (f.has_notnull or (f.column_nullable is False)) and (not for_patch)
    if notnull:
        imps.add("jakarta.validation.constraints.NotNull")
        ann.append("@NotNull")
        if is_string:
            imps.add("jakarta.validation.constraints.NotBlank")
            ann.append("@NotBlank")

    max_len = f.size_max or f.column_length
    if is_string and max_len and max_len > 0:
        imps.add("jakarta.validation.constraints.Size")
        ann.append(f"@Size(max = {max_len})")

    if is_string and (f.has_email or "email" in f.name.lower()):
        imps.add("jakarta.validation.constraints.Email")
        ann.append("@Email")

    if is_numeric and f.has_positive and not for_patch:
        imps.add("jakarta.validation.constraints.Positive")
        ann.append("@Positive")

    return ann, imps

def build_dto_fields(ent: Entity, emap: Dict[str, Entity]) -> Tuple[List[str], List[str], Set[str]]:
    request_lines: List[str] = []
    resp_lines: List[str] = []
    imports: Set[str] = set()

    skip_fields = {"createdAt", "updatedAt", "createdBy", "updatedBy", "deleted"}

    add_type_imports(ent.id_type, imports)
    resp_lines.append(f"    private {wrapper_type(ent.id_type)} {ent.id_field};")
    for f in ent.fields:
        if f.is_id or f.name == ent.id_field:
            continue
        if f.name in skip_fields or f.name == "version":
            continue

        if f.is_rel_single and f.rel_target:
            target = emap.get(f.rel_target)
            idt = wrapper_type(target.id_type) if target else "Long"
            add_type_imports(idt, imports)
            name = f"{f.name}Id"

            fake = Field(**{**f.__dict__, "type_name": idt})
            anns_c, imps_c = validation_for_field(fake, for_patch=False)
            imports |= imps_c

            for a in anns_c:
                request_lines.append(f"    {a}")
            request_lines.append(f"    private {idt} {name};")

            resp_lines.append(f"    private {idt} {name};")
            continue

        if f.is_rel_multi and f.rel_target:
            target = emap.get(f.rel_target)
            idt = wrapper_type(target.id_type) if target else "Long"
            add_type_imports(idt, imports)
            imports.add("java.util.List")
            name = f"{f.name}Ids"

            request_lines.append(f"    private List<{idt}> {name};")
            resp_lines.append(f"    private List<{idt}> {name};")
            continue

        t = wrapper_type(f.type_name)
        add_type_imports(t, imports)

        anns_u, imps_u = validation_for_field(f, for_patch=False)
        imports |= imps_u

        for a in anns_u:
            request_lines.append(f"    {a}")
        request_lines.append(f"    private {t} {f.name};")

        resp_lines.append(f"    private {t} {f.name};")

    return request_lines, resp_lines, imports

def gen_dtos(proj: Project, ent: Entity, emap: Dict[str, Entity]) -> List[Tuple[Path, str]]:
    pkg = dto_pkg(proj, ent)
    request_name, resp_name = dto_names(ent)
    request_lines, resp_lines, imps = build_dto_fields(ent, emap)

    imp_lines = render_import_block(imps, extra=["lombok.*"])
    dto_dir = to_pkg_dir(proj.src_main_java, pkg)

    def dto_code(name: str, lines: List[str]) -> str:
        body = "\n".join(lines) if lines else ""
        return f"""package {pkg};

{imp_lines}
{BOT_MARKER}
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class {name} {{
{body}
}}
"""

    return [
        (dto_dir / f"{request_name}.java", dto_code(request_name, request_lines)),
        (dto_dir / f"{resp_name}.java", dto_code(resp_name, resp_lines)),
    ]

# ---------------- common + exceptions + auditing + openapi ----------------

def gen_common_files(proj: Project) -> List[Tuple[Path, str]]:
    s = proj.style
    common = s.common_pkg
    exc = s.exception_pkg
    audit = s.audit_pkg

    error_code = f"""package {common};

{BOT_MARKER}
public enum ErrorCode {{
    VALIDATION_ERROR,
    BAD_REQUEST,
    NOT_FOUND,
    CONFLICT,
    INTERNAL_ERROR
}}
"""

    api_error = f"""package {common};

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;

{BOT_MARKER}
@Data
@Builder
public class ApiError {{
    private Instant timestamp;
    private String path;
    private ErrorCode errorCode;
    private String message;
    private List<String> details;
}}
"""

    notfound = f"""package {exc};

import {common}.ErrorCode;
import lombok.Getter;

{BOT_MARKER}
@Getter
public class NotFoundException extends RuntimeException {{
    private final ErrorCode errorCode = ErrorCode.NOT_FOUND;

    public NotFoundException(String message) {{
        super(message);
    }}
}}
"""

    bre = f"""package {exc};

import {common}.ErrorCode;
import lombok.Getter;

{BOT_MARKER}
@Getter
public class BadRequestException extends RuntimeException {{
    private final ErrorCode errorCode = ErrorCode.BAD_REQUEST;

    public BadRequestException(String message) {{
        super(message);
    }}
}}
"""

    conflict = f"""package {exc};

import {common}.ErrorCode;
import lombok.Getter;

{BOT_MARKER}
@Getter
public class ConflictException extends RuntimeException {{
    private final ErrorCode errorCode = ErrorCode.CONFLICT;

    public ConflictException(String message) {{
        super(message);
    }}
}}
"""

    # IMPORTANT: slf4j placeholder braces must be escaped in Python f-string => {{}} -> {}
    geh = f"""package {exc};

import {common}.ApiError;
import {common}.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

{BOT_MARKER}
@RestControllerAdvice
public class GlobalExceptionHandler {{

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ApiError> notFound(NotFoundException ex, HttpServletRequest req) {{
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                ApiError.builder()
                        .timestamp(Instant.now())
                        .path(req.getRequestURI())
                        .errorCode(ex.getErrorCode())
                        .message(ex.getMessage())
                        .details(List.of())
                        .build()
        );
    }}

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ApiError> badRequest(BadRequestException ex, HttpServletRequest req) {{
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                ApiError.builder()
                        .timestamp(Instant.now())
                        .path(req.getRequestURI())
                        .errorCode(ex.getErrorCode())
                        .message(ex.getMessage())
                        .details(List.of())
                        .build()
        );
    }}

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ApiError> conflict(ConflictException ex, HttpServletRequest req) {{
        return ResponseEntity.status(HttpStatus.CONFLICT).body(
                ApiError.builder()
                        .timestamp(Instant.now())
                        .path(req.getRequestURI())
                        .errorCode(ex.getErrorCode())
                        .message(ex.getMessage())
                        .details(List.of())
                        .build()
        );
    }}

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> validation(MethodArgumentNotValidException ex, HttpServletRequest req) {{
        List<String> details = ex.getBindingResult().getFieldErrors().stream()
                .map(e -> e.getField() + ": " + e.getDefaultMessage())
                .collect(Collectors.toList());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                ApiError.builder()
                        .timestamp(Instant.now())
                        .path(req.getRequestURI())
                        .errorCode(ErrorCode.VALIDATION_ERROR)
                        .message("Validation error")
                        .details(details)
                        .build()
        );
    }}

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiError> constraint(ConstraintViolationException ex, HttpServletRequest req) {{
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                ApiError.builder()
                        .timestamp(Instant.now())
                        .path(req.getRequestURI())
                        .errorCode(ErrorCode.VALIDATION_ERROR)
                        .message("Validation error")
                        .details(List.of(ex.getMessage()))
                        .build()
        );
    }}

    @ExceptionHandler(ObjectOptimisticLockingFailureException.class)
    public ResponseEntity<ApiError> optimistic(ObjectOptimisticLockingFailureException ex, HttpServletRequest req) {{
        return ResponseEntity.status(HttpStatus.CONFLICT).body(
                ApiError.builder()
                        .timestamp(Instant.now())
                        .path(req.getRequestURI())
                        .errorCode(ErrorCode.CONFLICT)
                        .message("Conflict")
                        .details(List.of("Optimistic lock failure"))
                        .build()
        );
    }}

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiError> integrity(DataIntegrityViolationException ex, HttpServletRequest req) {{
        return ResponseEntity.status(HttpStatus.CONFLICT).body(
                ApiError.builder()
                        .timestamp(Instant.now())
                        .path(req.getRequestURI())
                        .errorCode(ErrorCode.CONFLICT)
                        .message("Conflict")
                        .details(List.of("Data integrity violation"))
                        .build()
        );
    }}

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> general(Exception ex, HttpServletRequest req) {{
        log.error("Unhandled exception on {{}}", req.getRequestURI(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                ApiError.builder()
                        .timestamp(Instant.now())
                        .path(req.getRequestURI())
                        .errorCode(ErrorCode.INTERNAL_ERROR)
                        .message("Internal error")
                        .details(List.of())
                        .build()
        );
    }}
}}
"""

    auditing_cfg = f"""package {audit};

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

{BOT_MARKER}
@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class AuditingConfig {{

    @Bean
    public AuditorAware<String> auditorProvider() {{
        return new {"SecurityAuditorAware" if proj.has_security else "SimpleAuditorAware"}();
    }}
}}
"""

    if proj.has_security:
        auditor = f"""package {audit};

import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

{BOT_MARKER}
public class SecurityAuditorAware implements AuditorAware<String> {{
    @Override
    public Optional<String> getCurrentAuditor() {{
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return Optional.of("system");
        return Optional.ofNullable(auth.getName()).or(() -> Optional.of("system"));
    }}
}}
"""
        auditor_name = "SecurityAuditorAware.java"
    else:
        auditor = f"""package {audit};

import org.springframework.data.domain.AuditorAware;

import java.util.Optional;

{BOT_MARKER}
public class SimpleAuditorAware implements AuditorAware<String> {{
    @Override
    public Optional<String> getCurrentAuditor() {{
        return Optional.of("system");
    }}
}}
"""
        auditor_name = "SimpleAuditorAware.java"

    files: List[Tuple[Path, str]] = [
        (to_pkg_dir(proj.src_main_java, common) / "ErrorCode.java", error_code),
        (to_pkg_dir(proj.src_main_java, common) / "ApiError.java", api_error),
        (to_pkg_dir(proj.src_main_java, exc) / "NotFoundException.java", notfound),
        (to_pkg_dir(proj.src_main_java, exc) / "BadRequestException.java", bre),
        (to_pkg_dir(proj.src_main_java, exc) / "ConflictException.java", conflict),
        (to_pkg_dir(proj.src_main_java, exc) / "GlobalExceptionHandler.java", geh),
        (to_pkg_dir(proj.src_main_java, audit) / "AuditingConfig.java", auditing_cfg),
        (to_pkg_dir(proj.src_main_java, audit) / auditor_name, auditor),
    ]

    if proj.with_openapi:
        sec_imports = ""
        sec_scheme = ""
        if proj.has_security:
            sec_imports = """import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;"""
            sec_scheme = '@SecurityScheme(name = "bearerAuth", type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT", in = SecuritySchemeIn.HEADER)'

        openapi_cfg = f"""package {proj.base_package};

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
{sec_imports}

{BOT_MARKER}
@OpenAPIDefinition(
        info = @Info(
                title = "API",
                version = "v1"
        )
)
{sec_scheme}
public class OpenApiConfig {{
}}
"""
        files.append((to_pkg_dir(proj.src_main_java, proj.base_package) / "OpenApiConfig.java", openapi_cfg))

    return files

def gen_entity_notfound_files(proj: Project, ents: List[Entity]) -> List[Tuple[Path, str]]:
    exc = proj.style.exception_pkg
    out: List[Tuple[Path, str]] = []
    for e in ents:
        cls = f"{e.name}NotFound"
        code = f"""package {exc};

{BOT_MARKER}
public class {cls} extends NotFoundException {{
    public {cls}(Object idOrHint) {{
        super("{e.name} not found: " + idOrHint);
    }}
}}
"""
        out.append((to_pkg_dir(proj.src_main_java, exc) / f"{cls}.java", code))
    return out

# ---------------- repo + spec + mapper + service + controller ----------------

def gen_repository(proj: Project, ent: Entity) -> Tuple[Path, str]:
    pkg = proj.style.repository_pkg
    imports: Set[str] = {
        f"{ent.package}.{ent.name}",
        "org.springframework.data.jpa.repository.JpaRepository",
        "org.springframework.data.jpa.repository.JpaSpecificationExecutor",
    }
    add_type_imports(ent.id_type, imports)

    code = f"""package {pkg};

{render_import_block(imports)}
{BOT_MARKER}
public interface {ent.name}Repository extends JpaRepository<{ent.name}, {ent.id_type}>, JpaSpecificationExecutor<{ent.name}> {{
}}
"""
    return to_pkg_dir(proj.src_main_java, pkg) / f"{ent.name}Repository.java", code

def _parse_expr(java_type: str, var: str) -> Tuple[Set[str], str]:
    t = wrapper_type(java_type)
    imps: Set[str] = set()
    if t == "String":
        return imps, f"{var}.trim()"
    if t == "Long":
        return imps, f"Long.parseLong({var}.trim())"
    if t == "Integer":
        return imps, f"Integer.parseInt({var}.trim())"
    if t == "Double":
        return imps, f"Double.parseDouble({var}.trim())"
    if t == "Float":
        return imps, f"Float.parseFloat({var}.trim())"
    if t == "Short":
        return imps, f"Short.parseShort({var}.trim())"
    if t == "Byte":
        return imps, f"Byte.parseByte({var}.trim())"
    if t == "BigDecimal":
        imps.add("java.math.BigDecimal")
        return imps, f"new BigDecimal({var}.trim())"
    if t == "UUID":
        imps.add("java.util.UUID")
        return imps, f"UUID.fromString({var}.trim())"
    if t in JAVA_TIME_TYPES:
        imps.add(f"java.time.{t}")
        return imps, f"{t}.parse({var}.trim())"
    return imps, f"{var}.trim()"

def gen_specifications(proj: Project, ent: Entity, emap: Dict[str, Entity]) -> Tuple[Path, str]:
    pkg = proj.style.spec_pkg
    blocks: List[str] = []
    imports: Set[str] = {
        f"{ent.package}.{ent.name}",
        "org.springframework.data.jpa.domain.Specification",
        "java.util.*",
        "java.util.stream.Collectors",
    }

    def add_block(s: str):
        blocks.append(s.rstrip() + "\n")

    q_fields = [f for f in ent.fields if f.type_name == "String" and f.name not in {"createdBy", "updatedBy"}]
    if q_fields:
        ors = [f'cb.like(cb.lower(root.get("{f.name}")), "%" + q.toLowerCase() + "%")' for f in q_fields]
        add_block(f"""
        String q = params.get("q");
        if (q != null && !q.isBlank()) {{
            spec = spec.and((root, query, cb) -> cb.or({", ".join(ors)}));
        }}
""")

    for f in ent.fields:
        if f.is_id or f.name in {ent.id_field, "createdAt", "updatedAt", "createdBy", "updatedBy", "deleted", "version"}:
            continue

        if f.is_rel_single and f.rel_target and f.rel_target in emap:
            target = emap[f.rel_target]
            id_field = target.id_field
            id_type = target.id_type
            key = f"{f.name}Id"
            imps, parse = _parse_expr(id_type, key)
            imports |= imps
            add_block(f"""
        String {key} = params.get("{key}");
        if ({key} != null && !{key}.isBlank()) {{
            var parsed = {parse};
            spec = spec.and((root, query, cb) -> cb.equal(root.join("{f.name}").get("{id_field}"), parsed));
        }}
""")
            continue

        if f.is_rel_multi and f.rel_target and f.rel_target in emap:
            target = emap[f.rel_target]
            id_field = target.id_field
            id_type = target.id_type
            key = f"{f.name}Ids"
            imps, parseOne = _parse_expr(id_type, "x")
            imports |= imps
            add_block(f"""
        String {key} = params.get("{key}");
        if ({key} != null && !{key}.isBlank()) {{
            var ids = Arrays.stream({key}.split(","))
                    .map(String::trim)
                    .filter(x -> !x.isBlank())
                    .map(x -> {parseOne})
                    .collect(Collectors.toList());
            spec = spec.and((root, query, cb) -> {{
                query.distinct(true);
                var join = root.join("{f.name}");
                return join.get("{id_field}").in(ids);
            }});
        }}
""")
            continue

        if f.type_name == "String":
            add_block(f"""
        String {f.name} = params.get("{f.name}");
        if ({f.name} != null && !{f.name}.isBlank()) {{
            spec = spec.and((root, query, cb) -> cb.like(cb.lower(root.get("{f.name}")), "%" + {f.name}.toLowerCase() + "%"));
        }}
""")
            continue

        if f.type_name in BOOLEAN_TYPES:
            add_block(f"""
        String {f.name} = params.get("{f.name}");
        if ({f.name} != null && !{f.name}.isBlank()) {{
            spec = spec.and((root, query, cb) -> cb.equal(root.get("{f.name}"), Boolean.parseBoolean({f.name}.trim())));
        }}
""")
            continue

        if f.type_name in NUMERIC_TYPES:
            base = wrapper_type(f.type_name)
            mn = f"min{camel(f.name)}"
            mx = f"max{camel(f.name)}"
            imps1, parseEq = _parse_expr(base, f.name)
            imps2, parseMin = _parse_expr(base, mn)
            imps3, parseMax = _parse_expr(base, mx)
            imports |= imps1 | imps2 | imps3
            add_block(f"""
        String {f.name} = params.get("{f.name}");
        if ({f.name} != null && !{f.name}.isBlank()) {{
            var v = {parseEq};
            spec = spec.and((root, query, cb) -> cb.equal(root.get("{f.name}"), v));
        }}
        String {mn} = params.get("{mn}");
        if ({mn} != null && !{mn}.isBlank()) {{
            var v = {parseMin};
            spec = spec.and((root, query, cb) -> cb.greaterThanOrEqualTo(root.get("{f.name}"), v));
        }}
        String {mx} = params.get("{mx}");
        if ({mx} != null && !{mx}.isBlank()) {{
            var v = {parseMax};
            spec = spec.and((root, query, cb) -> cb.lessThanOrEqualTo(root.get("{f.name}"), v));
        }}
""")
            continue

        if f.type_name in JAVA_TIME_TYPES:
            frm = f"from{camel(f.name)}"
            to = f"to{camel(f.name)}"
            imps1, parseFrom = _parse_expr(f.type_name, frm)
            imps2, parseTo = _parse_expr(f.type_name, to)
            imports |= imps1 | imps2
            add_block(f"""
        String {frm} = params.get("{frm}");
        if ({frm} != null && !{frm}.isBlank()) {{
            var v = {parseFrom};
            spec = spec.and((root, query, cb) -> cb.greaterThanOrEqualTo(root.get("{f.name}"), v));
        }}
        String {to} = params.get("{to}");
        if ({to} != null && !{to}.isBlank()) {{
            var v = {parseTo};
            spec = spec.and((root, query, cb) -> cb.lessThanOrEqualTo(root.get("{f.name}"), v));
        }}
""")

    code = f"""package {pkg};

{render_import_block(imports)}
{BOT_MARKER}
public class {ent.name}Specifications {{
    private {ent.name}Specifications() {{}}

    public static Specification<{ent.name}> fromParams(Map<String, String> params) {{
        Specification<{ent.name}> spec = Specification.where(notDeleted());
{''.join(blocks)}
        return spec;
    }}

    public static Specification<{ent.name}> notDeleted() {{
        return (root, query, cb) -> cb.isFalse(root.get("deleted"));
    }}
}}
"""
    return to_pkg_dir(proj.src_main_java, pkg) / f"{ent.name}Specifications.java", code

def gen_mapper(proj: Project, ent: Entity, emap: Dict[str, Entity]) -> Tuple[Path, str]:
    pkg = proj.style.mapper_pkg
    dtoP = dto_pkg(proj, ent)
    request_name, resp_name = dto_names(ent)

    imports: Set[str] = {
        f"{ent.package}.{ent.name}",
        f"{dtoP}.{request_name}",
        f"{dtoP}.{resp_name}",
        "org.mapstruct.*",
        "java.util.*",
        "java.util.stream.Collectors",
    }

    ignores = ["createdAt", "updatedAt", "createdBy", "updatedBy", "deleted", "version"]
    create_maps = [f'    @Mapping(target = "{x}", ignore = true)' for x in ignores]
    update_maps = [f'    @Mapping(target = "{x}", ignore = true)' for x in ignores]

    to_resp: List[str] = []
    helpers: List[str] = []

    for f in ent.fields:
        if f.is_rel_single and f.rel_target and f.rel_target in emap:
            create_maps.append(f'    @Mapping(target = "{f.name}", ignore = true)')
            update_maps.append(f'    @Mapping(target = "{f.name}", ignore = true)')
            target = emap[f.rel_target]
            to_resp.append(f'    @Mapping(target = "{f.name}Id", source = "{f.name}.{target.id_field}")')

        if f.is_rel_multi and f.rel_target and f.rel_target in emap:
            create_maps.append(f'    @Mapping(target = "{f.name}", ignore = true)')
            update_maps.append(f'    @Mapping(target = "{f.name}", ignore = true)')
            target = emap[f.rel_target]
            imports.add(f"{target.package}.{target.name}")
            add_type_imports(target.id_type, imports)
            idt = target.id_type

            helpers.append(f"""
    default List<{idt}> map{camel(f.name)}Ids(Collection<{target.name}> col) {{
        if (col == null) return null;
        return col.stream()
                .filter(Objects::nonNull)
                .map(x -> x.get{camel(target.id_field)}())
                .collect(Collectors.toList());
    }}
""".rstrip())

            to_resp.append(
                f'    @Mapping(target = "{f.name}Ids", expression = "java(map{camel(f.name)}Ids(entity.get{camel(f.name)}()))")'
            )

    code = f"""package {pkg};

{render_import_block(imports)}
{BOT_MARKER}
@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE,
        builder = @org.mapstruct.Builder(disableBuilder = true)
)
public interface {ent.name}Mapper {{

{chr(10).join(create_maps)}
    {ent.name} toEntity({request_name} dto);

{chr(10).join(update_maps)}
    void updateFromRequest(@MappingTarget {ent.name} entity, {request_name} dto);

{chr(10).join(to_resp) if to_resp else ""}
    {resp_name} toDto({ent.name} entity);

{chr(10).join(helpers) if helpers else ""}
}}
"""
    return to_pkg_dir(proj.src_main_java, pkg) / f"{ent.name}Mapper.java", code

def _collection_assign_expr(field_type: str, refs_var: str) -> Tuple[Set[str], str, str]:
    base = java_simple_type(field_type)
    imps: Set[str] = set()
    if base in {"List", "ArrayList"}:
        imps |= {"java.util.ArrayList", "java.util.List"}
        return imps, f"new ArrayList<>({refs_var})", "new ArrayList<>()"
    if base in {"Set", "HashSet"}:
        imps |= {"java.util.HashSet", "java.util.Set"}
        return imps, f"new HashSet<>({refs_var})", "new HashSet<>()"
    imps |= {"java.util.HashSet"}
    return imps, f"new HashSet<>({refs_var})", "new HashSet<>()"

def gen_service(proj: Project, ent: Entity, emap: Dict[str, Entity]) -> Tuple[Path, str]:
    s = proj.style
    pkg = s.service_pkg
    repo_pkg = s.repository_pkg
    mapper_pkg = s.mapper_pkg
    spec_pkg = s.spec_pkg
    dtoP = dto_pkg(proj, ent)
    exc_pkg = s.exception_pkg

    request_name, resp_name = dto_names(ent)

    imports: Set[str] = {
        f"{repo_pkg}.{ent.name}Repository",
        f"{mapper_pkg}.{ent.name}Mapper",
        f"{spec_pkg}.{ent.name}Specifications",
        f"{dtoP}.{request_name}",
        f"{dtoP}.{resp_name}",
        f"{ent.package}.{ent.name}",
        f"{exc_pkg}.{ent.name}NotFound",
        "lombok.RequiredArgsConstructor",
        "org.springframework.stereotype.Service",
        "org.springframework.transaction.annotation.Transactional",
        "java.util.*",
        "java.util.stream.Collectors",
    }
    add_type_imports(ent.id_type, imports)

    fields = [
        f"private final {ent.name}Repository repository;",
        f"private final {ent.name}Mapper mapper;",
    ]

    resolve_create: List[str] = []
    resolve_update: List[str] = []
    for f in ent.fields:
        if f.is_rel_single and f.rel_target and f.rel_target in emap:
            target = emap[f.rel_target]
            target_repo = f"{target.name}Repository"
            imports.add(f"{repo_pkg}.{target_repo}")
            imports.add(f"{exc_pkg}.{target.name}NotFound")
            fields.append(f"private final {target_repo} {lower_first(target_repo)};")
            getter = f"dto.get{camel(f.name)}Id()"
            resolve_create.append(f"""
        if ({getter} != null) {{
            var ref = {lower_first(target_repo)}.findById({getter})
                    .orElseThrow(() -> new {target.name}NotFound({getter}));
            entity.set{camel(f.name)}(ref);
        }}""")
            resolve_update.append(f"""
        if ({getter} != null) {{
            var ref = {lower_first(target_repo)}.findById({getter})
                    .orElseThrow(() -> new {target.name}NotFound({getter}));
            entity.set{camel(f.name)}(ref);
        }} else {{
            entity.set{camel(f.name)}(null);
        }}""")
        if f.is_rel_multi and f.rel_target and f.rel_target in emap:
            target = emap[f.rel_target]
            target_repo = f"{target.name}Repository"
            imports.add(f"{repo_pkg}.{target_repo}")
            imports.add(f"{exc_pkg}.{target.name}NotFound")
            fields.append(f"private final {target_repo} {lower_first(target_repo)};")

            coll_imps, coll_expr, empty_expr = _collection_assign_expr(f.type_name, "refs")
            imports |= coll_imps

            getter = f"dto.get{camel(f.name)}Ids()"
            resolve_create.append(f"""
        if ({getter} != null) {{
            var ids = {getter};
            var refs = {lower_first(target_repo)}.findAllById(ids);
            if (refs.size() != ids.size()) {{
                throw new {target.name}NotFound("Some IDs not found: " + ids);
            }}
            entity.set{camel(f.name)}({coll_expr});
        }}""")
            resolve_update.append(f"""
        if ({getter} != null) {{
            var ids = {getter};
            var refs = {lower_first(target_repo)}.findAllById(ids);
            if (refs.size() != ids.size()) {{
                throw new {target.name}NotFound("Some IDs not found: " + ids);
            }}
            entity.set{camel(f.name)}({coll_expr});
        }} else {{
            entity.set{camel(f.name)}({empty_expr});
        }}""")
    code = f"""package {pkg};

{render_import_block(imports)}
{BOT_MARKER}
@Service
@RequiredArgsConstructor
@Transactional
public class {ent.name}Service {{

    {chr(10).join(fields)}

    public {resp_name} create({request_name} dto) {{
        {ent.name} entity = mapper.toEntity(dto);
{chr(10).join(resolve_create)}
        entity = repository.save(entity);
        return mapper.toDto(entity);
    }}

    public {resp_name} update({ent.id_type} id, {request_name} dto) {{
        {ent.name} entity = repository.findById(id)
                .orElseThrow(() -> new {ent.name}NotFound(id));

        mapper.updateFromRequest(entity, dto);
{chr(10).join(resolve_update)}
        entity = repository.save(entity);
        return mapper.toDto(entity);
    }}

    @Transactional(readOnly = true)
    public {resp_name} getById({ent.id_type} id) {{
        {ent.name} entity = repository.findById(id)
                .orElseThrow(() -> new {ent.name}NotFound(id));
        return mapper.toDto(entity);
    }}

    @Transactional(readOnly = true)
    public List<{resp_name}> getAll() {{
        var spec = {ent.name}Specifications.notDeleted();
        return repository.findAll(spec).stream().map(mapper::toDto).collect(Collectors.toList());
    }}

    public void delete({ent.id_type} id) {{
        {ent.name} entity = repository.findById(id)
                .orElseThrow(() -> new {ent.name}NotFound(id));
        entity.setDeleted(true);
        repository.save(entity);
    }}
}}
"""
    return to_pkg_dir(proj.src_main_java, pkg) / f"{ent.name}Service.java", code

def gen_controller(proj: Project, ent: Entity) -> Tuple[Path, str]:
    s = proj.style
    pkg = s.controller_pkg
    dtoP = dto_pkg(proj, ent)
    service_pkg = s.service_pkg

    request_name, resp_name = dto_names(ent)
    route = f"{proj.api_prefix}/{route_name(ent.name)}"

    imports: Set[str] = {
        f"{dtoP}.{request_name}",
        f"{dtoP}.{resp_name}",
        f"{service_pkg}.{ent.name}Service",
        "jakarta.validation.Valid",
        "java.util.List",
        "org.springframework.http.HttpStatus",
        "org.springframework.http.ResponseEntity",
        "org.springframework.web.bind.annotation.*",
    }
    add_type_imports(ent.id_type, imports)
    code = f"""package {pkg};

{render_import_block(imports)}
{BOT_MARKER}
@RestController
@RequestMapping("{route}")
public class {ent.name}Controller {{

    private final {ent.name}Service service;

    public {ent.name}Controller({ent.name}Service service) {{
        this.service = service;
    }}

    @PostMapping
    public ResponseEntity<{resp_name}> create(@Valid @RequestBody {request_name} request) {{
        {resp_name} response = service.create(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }}

    @GetMapping("/{{id}}")
    public {resp_name} getById(@PathVariable {ent.id_type} id) {{
        return service.getById(id);
    }}

    @GetMapping
    public List<{resp_name}> getAll() {{
        return service.getAll();
    }}

    @PutMapping("/{{id}}")
    public {resp_name} update(@PathVariable {ent.id_type} id, @Valid @RequestBody {request_name} request) {{
        return service.update(id, request);
    }}

    @DeleteMapping("/{{id}}")
    public ResponseEntity<Void> delete(@PathVariable {ent.id_type} id) {{
        service.delete(id);
        return ResponseEntity.noContent().build();
    }}
}}
"""
    return to_pkg_dir(proj.src_main_java, pkg) / f"{ent.name}Controller.java", code

# ---------------- compile / wrapper ----------------

def ensure_maven_wrapper(proj: Project) -> None:
    if proj.build_kind != "maven":
        return
    mvnw = proj.build_root / "mvnw"
    if mvnw.exists():
        return
    if shutil.which("mvn") is None:
        return
    try:
        subprocess.run(["mvn", "-q", "-N", "io.takari:maven:wrapper"], cwd=str(proj.build_root), check=False)
    except Exception:
        pass

def ensure_gradle_wrapper(proj: Project) -> None:
    if "gradle" not in proj.build_kind:
        return
    gradlew = proj.build_root / "gradlew"
    if gradlew.exists():
        return
    if shutil.which("gradle") is None:
        return
    try:
        subprocess.run(["gradle", "-q", "wrapper"], cwd=str(proj.build_root), check=False)
    except Exception:
        pass

def run_compile(proj: Project) -> Tuple[bool, str]:
    ensure_maven_wrapper(proj)
    ensure_gradle_wrapper(proj)

    cwd = proj.build_root
    if proj.build_kind == "maven":
        mvnw = cwd / "mvnw"
        cmd = ["./mvnw", "-q", "-DskipTests", "compile"] if mvnw.exists() else (["mvn", "-q", "-DskipTests", "compile"] if shutil.which("mvn") else None)
    elif "gradle" in proj.build_kind:
        gradlew = cwd / "gradlew"
        cmd = ["./gradlew", "-q", "classes"] if gradlew.exists() else (["gradle", "-q", "classes"] if shutil.which("gradle") else None)
    else:
        cmd = None

    if cmd is None:
        return False, "build tool not available for compile check"

    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=300)
        if proc.returncode == 0:
            return True, "compile OK"
        tail = (proc.stdout + "\n" + proc.stderr).strip().splitlines()[-140:]
        return False, "compile failed:\n" + "\n".join(tail)
    except subprocess.TimeoutExpired:
        return False, "compile timeout (300s)"
    except Exception as e:
        return False, f"compile error: {e}"

# ---------------- UI / selection ----------------

def show_entities(entities: List[Entity]) -> None:
    if Table and console:
        t = Table(title="Entities found (@Entity)")
        t.add_column("#", justify="right")
        t.add_column("Entity")
        t.add_column("Package")
        t.add_column("ID")
        t.add_column("File")
        for i, e in enumerate(entities, start=1):
            t.add_row(str(i), e.name, e.package, f"{e.id_field}:{e.id_type}", e.file_rel)
        console.print(t)
    else:
        p("Entities:")
        for i, e in enumerate(entities, start=1):
            p(f"{i}) {e.name}  ({e.package})  id={e.id_field}:{e.id_type}  file={e.file_rel}")

def pick_entities_interactive(entities: List[Entity]) -> List[Entity]:
    p("\nSeçim: məsələn 1,3,5 və ya all")
    raw = input("Entity seç: ").strip().lower()
    if raw in {"all", "*"}:
        return entities
    idxs = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            idxs.append(int(part))
    chosen: List[Entity] = []
    for i in idxs:
        if 1 <= i <= len(entities):
            chosen.append(entities[i - 1])
    return chosen

def select_entities(entities: List[Entity], names: Optional[List[str]], select_all: bool) -> List[Entity]:
    if select_all:
        return entities
    if names:
        name_set = {n.strip() for n in names if n and n.strip()}
        return [e for e in entities if e.name in name_set]
    return pick_entities_interactive(entities)

# ---------------- main ----------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Professional Spring Boot CRUD generator")
    ap.add_argument("--root", type=str, default=None, help="Project root path")
    ap.add_argument("--entities", type=str, default=None, help="Comma-separated entity names (e.g. User,Order)")
    ap.add_argument("--all", action="store_true", help="Select all entities")
    ap.add_argument("--api-prefix", type=str, default=None, help="Override api prefix (e.g. /api/v1)")
    ap.add_argument("--backup-mode", type=str, default="managed", choices=["none", "managed", "all"], help="Backup mode")
    ap.add_argument("--overwrite-policy", type=str, default="marked", choices=["marked", "force", "never"], help="Overwrite policy")
    ap.add_argument("--dry-run", action="store_true", help="Do not write files")
    ap.add_argument("--no-build", action="store_true", help="Skip build dependency updates")
    ap.add_argument("--no-config", action="store_true", help="Skip application yml generation")
    ap.add_argument("--no-docker", action="store_true", help="Skip docker-compose generation")
    ap.add_argument("--no-openapi", action="store_true", help="Disable OpenAPI (springdoc) generation/deps")
    ap.add_argument("--no-compile", action="store_true", help="Skip compile check")
    ap.add_argument("--patch-all", action="store_true", help="Patch ALL entities (default: only selected)")
    return ap.parse_args()

def main() -> int:
    if javalang is None:
        p("[ERROR] Missing dependency: javalang. Run: pip install javalang rich")
        return 2

    args = parse_args()

    root_in = args.root or strip_quotes(input("Java Spring Boot proyekt qovluğunun yolunu yaz: "))
    root = Path(strip_quotes(root_in)).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        p(f"[ERROR] Folder not found: {root}")
        return 2

    proj = load_project(
        root,
        with_openapi=(not args.no_openapi),
        overwrite_policy=args.overwrite_policy,
        backup_mode=args.backup_mode,
        dry_run=args.dry_run,
        api_prefix_override=args.api_prefix
    )
    versions = load_versions(proj.root)

    p("\nProject detected")
    p(f"- Root: {proj.root}")
    p(f"- src/main/java: {proj.src_main_java}")
    p(f"- base package: {proj.base_package}")
    p(f"- api prefix: {proj.api_prefix}")
    p(f"- build: {proj.build_kind} ({proj.build_file})")
    p(f"- style: controller={proj.style.controller_pkg}, service={proj.style.service_pkg}, repo={proj.style.repository_pkg}, spec={proj.style.spec_pkg}")
    p(f"- openapi: {proj.with_openapi}")
    p(f"- overwrite: {proj.overwrite_policy}, backup: {proj.backup_mode}, dry-run: {proj.dry_run}")

    entities = parse_entities(proj)
    if not entities:
        p("[WARN] No @Entity found.")
        return 1

    show_entities(entities)

    names = [x.strip() for x in args.entities.split(",")] if args.entities else None
    selected = select_entities(entities, names, args.all)
    if not selected:
        p("[WARN] Nothing selected.")
        return 1

    p("\nSelected entities: " + ", ".join(e.name for e in selected))

    if not args.no_build:
        bch = update_build(proj, versions)
        if bch:
            p("\nBuild update:")
            for c in bch:
                p(f" - {c}")

    if not args.no_config:
        cch = ensure_application_profiles(proj)
        if cch:
            p("\nConfig update:")
            for c in cch:
                p(f" - {c}")

    if not args.no_docker:
        dch = ensure_docker_compose(proj)
        if dch:
            p("\nDocker:")
            for c in dch:
                p(f" - {c}")

    em_before = entity_map(entities)
    to_patch = entities if args.patch_all else selected
    p("\nPatching entities (" + ("ALL" if args.patch_all else "selected") + ") ...")
    patched_total = 0
    for e in to_patch:
        ch = patch_entity(proj, e)
        if ch:
            patched_total += 1
    p(f"Patched entities: {patched_total}/{len(to_patch)}")

    entities2 = parse_entities(proj)
    em = entity_map(entities2)
    selected2 = [em[e.name] for e in selected if e.name in em]

    manifest = load_manifest(proj.root)

    files: List[Tuple[Path, str]] = []
    files.extend(gen_common_files(proj))

    # Generate minimal dependencies for direct relation targets too (repo + NotFound),
    # so services compile even when relations point to non-selected entities.
    required = required_entities(selected2, em)
    files.extend(gen_entity_notfound_files(proj, required))
    for e in required:
        files.append(gen_repository(proj, e))

    # Full CRUD only for selected entities
    for e in selected2:
        files.append(gen_specifications(proj, e, em))
        files.append(gen_mapper(proj, e, em))
        files.append(gen_service(proj, e, em))
        files.append(gen_controller(proj, e))
        files.extend(gen_dtos(proj, e, em))

    written = 0
    for path, content in files:
        ok, rel = safe_write(proj, path, content, manifest)
        if ok:
            written += 1

    save_manifest(proj.root, manifest)

    p("\nGeneration complete.")
    p(f"Written/updated: {written} file(s)")
    if proj.backup_mode != "none":
        p("Backups: .crudbot/backups/<session>/")
    p("If any files were not overwritten due to policy, see: .crudbot/generated/")

    if args.no_compile:
        p("\nFINAL AUDIT: compile check skipped (--no-compile)")
        return 0

    ok, msg = run_compile(proj)
    p("\nFINAL AUDIT")
    if ok:
        p("[OK] Compile OK.")
        p("\n✅ Run:")
        p("  docker-compose up -d")
        if proj.build_kind == "maven":
            p("  ./mvnw spring-boot:run   (və ya: mvn spring-boot:run)")
        else:
            p("  ./gradlew bootRun        (və ya: gradle bootRun)")
        if proj.with_openapi:
            p("Swagger UI: /swagger-ui/index.html")
        return 0

    p("[FAIL] Compile failed:")
    p(msg)
    p("\n⚠️ Compile olmadı. Log-un son hissəsini göndər, proyektinə görə generatoru daha da sərtləşdirək.")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
