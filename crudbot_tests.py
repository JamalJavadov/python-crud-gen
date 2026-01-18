#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crudbot_tests.py

Generates production-friendly integration tests (MockMvc + H2) for CrudBot-generated endpoints.

- @SpringBootTest + @AutoConfigureMockMvc(addFilters=false) + @ActiveProfiles("test")
- POST/GET/LIST/PATCH (version conflict)/DELETE flow
- Creates application-test.yml (H2)
- Ensures build deps: spring-boot-starter-test + H2 (test)
"""
from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

try:
    import javalang
except Exception:
    javalang = None

EXCLUDE_DIRS = {
    ".crudbot",
    ".git", ".idea", ".vscode",
    "target", "build", "out", ".gradle", ".mvn",
    "node_modules", "__pycache__",
}

JAVA_PACKAGE_RE = re.compile(r"^\s*package\s+([a-zA-Z0-9_.]+)\s*;", re.M)
SPRING_BOOT_APP_RE = re.compile(r"@SpringBootApplication\b")

ENTITY_ANNOT = "Entity"
ID_ANNOT = "Id"
REL_SINGLE = {"ManyToOne", "OneToOne"}
REL_MULTI = {"OneToMany", "ManyToMany"}

JAVA_TIME_TYPES = {"LocalDate", "LocalDateTime", "Instant", "OffsetDateTime", "ZonedDateTime"}
NUMERIC_TYPES = {"Integer","Long","Double","Float","Short","Byte","BigDecimal","int","long","double","float","short","byte"}
BOOLEAN_TYPES = {"boolean","Boolean"}

def strip_quotes(s: str) -> str:
    return s.strip().strip('"').strip("'")

def iter_java_files(root: Path) -> List[Path]:
    out: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fn in filenames:
            if fn.endswith(".java"):
                out.append(Path(dirpath) / fn)
    return sorted(out)

def find_first_dir(root: Path, rel: str) -> Optional[Path]:
    cand = root / rel
    if cand.exists() and cand.is_dir():
        return cand
    for pth in root.rglob(rel):
        if pth.is_dir() and not any(x in pth.parts for x in EXCLUDE_DIRS):
            return pth
    return None

def read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")

def write_text(p: Path, txt: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(txt, encoding="utf-8", errors="replace")

def pluralize(name: str) -> str:
    if name.endswith("y") and len(name) > 1 and name[-2].lower() not in "aeiou":
        return name[:-1] + "ies"
    if name.endswith("s"):
        return name + "es"
    return name + "s"

def route_name(entity_name: str) -> str:
    return pluralize(entity_name).lower()

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

@dataclass
class Field:
    name: str
    type_name: str
    is_id: bool
    is_rel_single: bool
    is_rel_multi: bool
    rel_target: Optional[str]
    column_nullable: Optional[bool]
    has_notnull: bool

@dataclass
class Entity:
    name: str
    package: str
    file_path: Path
    id_field: str
    id_type: str
    fields: List[Field]

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

def parse_entities(root: Path) -> List[Entity]:
    if javalang is None:
        raise RuntimeError("Missing dependency: javalang (pip install javalang rich)")

    ents: List[Entity] = []
    for f in iter_java_files(root):
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
            if not any(a.name == ENTITY_ANNOT for a in anns):
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
                ann_names = {a.name for a in ann_list}

                is_id = ID_ANNOT in ann_names
                is_rel_single = any(a in ann_names for a in REL_SINGLE)
                is_rel_multi = any(a in ann_names for a in REL_MULTI)

                rel_target = None
                if is_rel_multi and "<" in ftype and ">" in ftype:
                    rel_target = ftype.split("<", 1)[1].split(">", 1)[0].strip()
                elif is_rel_single:
                    rel_target = ftype

                column_nullable: Optional[bool] = None
                has_notnull = "NotNull" in ann_names

                for a in ann_list:
                    if a.name in {"Column", "JoinColumn"}:
                        kv = _extract_ann_kv(a)
                        if "nullable" in kv:
                            v = kv["nullable"].strip().lower()
                            if v in {"true", "false"}:
                                column_nullable = (v == "true")

                for decl in node.declarators:
                    fname = decl.name
                    fields.append(Field(
                        name=fname,
                        type_name=ftype,
                        is_id=is_id,
                        is_rel_single=is_rel_single,
                        is_rel_multi=is_rel_multi,
                        rel_target=rel_target,
                        column_nullable=column_nullable,
                        has_notnull=has_notnull,
                    ))
                    if is_id:
                        id_field, id_type = fname, ftype

            if not any(x.is_id for x in fields):
                # try "id"
                for fm in fields:
                    if fm.name == "id":
                        id_field, id_type = "id", fm.type_name
                        break

            ents.append(Entity(t.name, pkg, f, id_field, id_type, fields))
    ents.sort(key=lambda e: (e.package, e.name))
    return ents

def entity_map(entities: List[Entity]) -> Dict[str, Entity]:
    return {e.name: e for e in entities}

def wrapper_type(t: str) -> str:
    return {"int":"Integer","long":"Long","double":"Double","float":"Float","short":"Short","byte":"Byte","boolean":"Boolean","char":"Character"}.get(t, t)

def to_pkg_dir(src: Path, pkg: str) -> Path:
    return src / Path(pkg.replace(".", "/"))

def dummy_json_value(java_type: str) -> str:
    base = java_type.strip()
    if "<" in base:
        base = base.split("<", 1)[0].strip()
    base = wrapper_type(base)
    if base == "String":
        return '"test"'
    if base in {"Integer","Long","Short","Byte"}:
        return "1"
    if base in {"Double","Float","BigDecimal"}:
        return "1.0"
    if base in BOOLEAN_TYPES:
        return "false"
    if base in JAVA_TIME_TYPES:
        # ISO-8601 parse friendly
        if base == "LocalDate":
            return '"2025-01-01"'
        return '"2025-01-01T10:00:00"'
    # fallback string
    return '"test"'

def ensure_test_config(root: Path) -> List[str]:
    res = find_first_dir(root, "src/test/resources") or (root / "src/test/resources")
    res.mkdir(parents=True, exist_ok=True)
    yml = res / "application-test.yml"
    if yml.exists():
        return []
    content = """# GENERATED BY CrudBot test generator
spring:
  datasource:
    url: jdbc:h2:mem:testdb;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false
    driver-class-name: org.h2.Driver
    username: sa
    password:
  jpa:
    hibernate:
      ddl-auto: create-drop
    properties:
      hibernate:
        format_sql: true
    open-in-view: false
logging:
  level:
    org.hibernate.SQL: warn
"""
    write_text(yml, content)
    return [f"Created {yml.relative_to(root)}"]

def ensure_build_test_deps(root: Path) -> List[str]:
    kind, build_file = find_build(root)
    if not build_file or not build_file.exists():
        return ["Build file not found; skipped deps update."]
    txt = read_text(build_file)
    changes: List[str] = []

    if kind == "maven":
        if "<artifactId>spring-boot-starter-test</artifactId>" not in txt:
            # user may already have it via CRUD generator, but ensure anyway
            insert = """<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-test</artifactId>
  <scope>test</scope>
</dependency>"""
            if "<dependencies>" in txt:
                i = txt.rfind("</dependencies>")
                txt = txt[:i] + "\n" + insert + "\n" + txt[i:]
            else:
                i = txt.rfind("</project>")
                txt = txt[:i] + "\n<dependencies>\n" + insert + "\n</dependencies>\n" + txt[i:]
            changes.append("Added spring-boot-starter-test")

        if "<artifactId>h2</artifactId>" not in txt:
            insert = """<dependency>
  <groupId>com.h2database</groupId>
  <artifactId>h2</artifactId>
  <scope>test</scope>
</dependency>"""
            i = txt.rfind("</dependencies>")
            if i != -1:
                txt = txt[:i] + "\n" + insert + "\n" + txt[i:]
            changes.append("Added H2 (test)")

        write_text(build_file, txt)
        return changes

    # Gradle
    def insert_dep(line: str, key: str) -> None:
        nonlocal txt
        if key in txt:
            return
        m = re.search(r"(?m)^\s*dependencies\s*\{\s*$", txt)
        if not m:
            txt = txt.rstrip() + "\n\ndependencies {\n" + line + "}\n"
            changes.append(f"Added {key}")
            return
        i = m.end()
        depth = 1
        while i < len(txt):
            ch = txt[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    txt = txt[:i] + line + txt[i:]
                    changes.append(f"Added {key}")
                    return
            i += 1
        txt = txt.rstrip() + "\n" + line
        changes.append(f"Added {key}")

    kts = kind == "gradle_kts"
    if kts:
        insert_dep('    testImplementation("org.springframework.boot:spring-boot-starter-test")\n', "spring-boot-starter-test")
        insert_dep('    testRuntimeOnly("com.h2database:h2")\n', "com.h2database:h2")
    else:
        insert_dep("    testImplementation 'org.springframework.boot:spring-boot-starter-test'\n", "spring-boot-starter-test")
        insert_dep("    testRuntimeOnly 'com.h2database:h2'\n", "com.h2database:h2")

    write_text(build_file, txt)
    return changes

def json_object(pairs: List[Tuple[str, str]]) -> str:
    inner = ",\n            ".join([f'"{k}": {v}' for k, v in pairs])
    return "{\n            " + inner + "\n        }"

def generate_test_for_entity(base_pkg: str, api_prefix: str, src_test_java: Path, ent: Entity, emap: Dict[str, Entity], selected_names: Set[str]) -> Tuple[Path, str]:
    pkg = f"{base_pkg}.crudbottests"
    cls = f"{ent.name}CrudIT"
    route = f"{api_prefix}/{route_name(ent.name)}"
    id_field = ent.id_field
    id_type = wrapper_type(ent.id_type)

    # Build JSON payload (create)
    create_pairs: List[Tuple[str, str]] = []
    patch_pairs: List[Tuple[str, str]] = []

    # Determine one updatable simple field for patch
    patch_field_name: Optional[str] = None
    patch_field_value: Optional[str] = None

    # Relation setup snippets
    repo_fields: List[str] = []
    setup_lines: List[str] = []
    create_required_relations: List[Tuple[str, str]] = []  # (jsonField, javaVarId)

    for f in ent.fields:
        if f.is_id or f.name == id_field or f.name in {"createdAt","updatedAt","createdBy","updatedBy","deleted","version"}:
            continue

        required = (f.has_notnull or f.column_nullable is False)

        if f.is_rel_single and f.rel_target and f.rel_target in emap:
            target = emap[f.rel_target]
            target_repo = f"{target.name}Repository"
            repo_fields.append(f"    @Autowired private {target_repo} {target_repo[0].lower() + target_repo[1:]};")
            # create target entity in DB and use its id if required
            json_key = f"{f.name}Id"
            var_name = f"{f.name}Id"
            if required:
                create_required_relations.append((json_key, var_name))
            # patch doesn't touch relations by default
            continue

        if f.is_rel_multi and f.rel_target and f.rel_target in emap:
            # optional: set empty list
            create_pairs.append((f"{f.name}Ids", "[]"))
            continue

        # simple field
        v = dummy_json_value(f.type_name)
        create_pairs.append((f.name, v))

        if patch_field_name is None:
            patch_field_name = f.name
            # change value
            if v == '"test"':
                patch_field_value = '"test2"'
            elif v == "1":
                patch_field_value = "2"
            elif v == "1.0":
                patch_field_value = "2.0"
            elif v == "false":
                patch_field_value = "true"
            else:
                patch_field_value = '"patched"'

    # setup required relations: create/persist targets via repository + reflection
    for json_key, var_name in create_required_relations:
        # var_name is id variable; we need to persist target entity and extract id field reflectively
        # Find target entity by json_key prefix => field name
        field_name = json_key[:-2]  # remove "Id"
        fdef = next((x for x in ent.fields if x.name == field_name), None)
        target = emap.get(fdef.rel_target) if fdef and fdef.rel_target else None
        if not target:
            continue
        tgt_cls = target.name
        tgt_id_field = target.id_field
        tgt_repo = f"{tgt_cls}Repository"
        repo_var = tgt_repo[0].lower() + tgt_repo[1:]
        setup_lines.append(f"        {tgt_cls} ref{tgt_cls} = new {tgt_cls}();")
        setup_lines.append(f"        ReflectionUtil.fillDefaults(ref{tgt_cls});")
        setup_lines.append(f"        ref{tgt_cls} = {repo_var}.saveAndFlush(ref{tgt_cls});")
        setup_lines.append(f"        Object {var_name} = ReflectionUtil.getField(ref{tgt_cls}, \"{tgt_id_field}\");")
        # add to create json
        create_pairs.append((json_key, f"\" + {var_name} + \""))  # will be embedded in String building below

    # Build create JSON string — needs special handling for relation ids set at runtime
    # We'll build it as Java text block with String.format? We'll do manual concatenation safely.
    # If there are dynamic values, we embed using + var + in Java.
    has_dynamic = any(v.startswith('" + ') for _, v in create_pairs)

    if not has_dynamic:
        create_json_java = f'        String createJson = """\n{json_object(create_pairs)}\n        """;'
    else:
        # Build JSON with placeholders via concatenation. We'll escape quotes around keys.
        lines = ['        String createJson = "{\\n" +']
        for i, (k, v) in enumerate(create_pairs):
            comma = "," if i < len(create_pairs) - 1 else ""
            if v.startswith('" + '):
                # dynamic id embedded as string => numeric allowed too; we keep as raw.
                # v looks like: " + var + "
                # We want:  "key": <var>,
                dyn = v[len('" + '):-len(' + "')]
                lines.append(f'                "            \\"{k}\\": " + {dyn} + "{comma}\\n" +')
            else:
                lines.append(f'                "            \\"{k}\\": {v}{comma}\\n" +')
        lines.append('                "        }";')
        create_json_java = "\n".join(lines)

    # Patch JSON: must include version and one changed field if available
    if patch_field_name is None:
        patch_pairs = [("version", '" + version + "')]  # only version
        patch_json_java = '        String patchJson = "{\\n            \\"version\\": " + version + "\\n        }";'
    else:
        patch_pairs = [("version", '" + version + "'), (patch_field_name, patch_field_value or '"patched"')]
        # patch has dynamic version, maybe static field value
        patch_lines = ['        String patchJson = "{\\n" +',
                       '                "            \\"version\\": " + version + ",\\n" +',
                       f'                "            \\"{patch_field_name}\\": {patch_field_value}\\n" +',
                       '                "        }";']
        patch_json_java = "\n".join(patch_lines)

    code = f"""package {pkg};

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import {ent.package}.{ent.name};
import {base_pkg}.repository.{ent.name}Repository;
{chr(10).join([f"import {base_pkg}.repository.{emap[ent.fields[i].rel_target].name}Repository;" for i in range(len(ent.fields)) if ent.fields[i].is_rel_single and ent.fields[i].rel_target in emap]) if False else ""}

@SpringBootTest
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
class {cls} {{

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper om;
    @Autowired private {ent.name}Repository repository;
{chr(10).join(repo_fields)}

    @Test
    void fullCrudFlow() throws Exception {{
        // Arrange: ensure clean slate for this entity
        repository.deleteAll();
        repository.flush();

{chr(10).join(setup_lines) if setup_lines else ""}
{create_json_java}

        // 1) Create
        MvcResult createdRes = mvc.perform(post("{route}")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createJson))
                .andExpect(status().isCreated())
                .andExpect(header().exists("Location"))
                .andExpect(jsonPath("$.success").value(true))
                .andReturn();

        JsonNode created = om.readTree(createdRes.getResponse().getContentAsString()).get("data");
        assertThat(created).isNotNull();

        String idStr = created.get("{id_field}").asText();
        long version = created.get("version").asLong();

        // 2) Get
        mvc.perform(get("{route}/" + idStr))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.{id_field}").value(idStr));

        // 3) List
        mvc.perform(get("{route}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.totalElements").value(1));

        // 4) Patch (valid version)
{patch_json_java}
        MvcResult patchedRes = mvc.perform(patch("{route}/" + idStr)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(patchJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andReturn();

        JsonNode patched = om.readTree(patchedRes.getResponse().getContentAsString()).get("data");
        long newVersion = patched.get("version").asLong();
        assertThat(newVersion).isGreaterThanOrEqualTo(version);

        // 5) Patch with stale version -> 409
        String stalePatch = "{{\\n            \\"version\\": " + version + "\\n        }}";
        mvc.perform(patch("{route}/" + idStr)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(stalePatch))
                .andExpect(status().isConflict());

        // 6) Delete (soft delete)
        mvc.perform(delete("{route}/" + idStr))
                .andExpect(status().isNoContent());

        // 7) List should hide deleted (soft delete filter)
        mvc.perform(get("{route}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.totalElements").value(0));
    }}

    /** Reflection helpers so tests don't depend on Lombok setters. */
    static class ReflectionUtil {{
        static void fillDefaults(Object entity) {{
            // Try to set some safe defaults to avoid NOT NULL issues in H2 schema.
            // Skips id/version/auditing/deleted and relation fields.
            for (Field f : entity.getClass().getDeclaredFields()) {{
                f.setAccessible(true);
                String n = f.getName();
                if (n.equals("{id_field}") || n.equals("version") || n.equals("createdAt") || n.equals("updatedAt") ||
                    n.equals("createdBy") || n.equals("updatedBy") || n.equals("deleted")) {{
                    continue;
                }}
                Class<?> t = f.getType();
                try {{
                    Object cur = f.get(entity);
                    if (cur != null) continue;

                    if (t.equals(String.class)) f.set(entity, "test");
                    else if (t.equals(Integer.class) || t.equals(int.class)) f.set(entity, 1);
                    else if (t.equals(Long.class) || t.equals(long.class)) f.set(entity, 1L);
                    else if (t.equals(Double.class) || t.equals(double.class)) f.set(entity, 1.0d);
                    else if (t.equals(Float.class) || t.equals(float.class)) f.set(entity, 1.0f);
                    else if (t.equals(Boolean.class) || t.equals(boolean.class)) f.set(entity, false);
                    else if (t.getName().equals("java.time.Instant")) f.set(entity, Instant.now());
                    else if (t.getName().equals("java.time.LocalDate")) f.set(entity, java.time.LocalDate.parse("2025-01-01"));
                    else if (t.getName().equals("java.time.LocalDateTime")) f.set(entity, java.time.LocalDateTime.parse("2025-01-01T10:00:00"));
                    // Collections/relations are left alone.
                }} catch (Exception ignored) {{}}
            }}
        }}

        static Object getField(Object entity, String fieldName) {{
            try {{
                Field f = entity.getClass().getDeclaredField(fieldName);
                f.setAccessible(true);
                return f.get(entity);
            }} catch (Exception e) {{
                throw new RuntimeException(e);
            }}
        }}
    }}
}}
"""
    # Clean imports: repository package might not match base_pkg.repository in all projects, but CrudBot generator defaults there.
    # We'll still place tests under base package and rely on generated repositories being there.
    test_path = to_pkg_dir(src_test_java, pkg) / f"{cls}.java"
    return test_path, code

def main() -> int:
    if javalang is None:
        print("[ERROR] Missing dependency: javalang. Run: pip install javalang rich")
        return 2

    ap = argparse.ArgumentParser(description="CrudBot integration test generator")
    ap.add_argument("--root", required=True, help="Project root")
    ap.add_argument("--entities", required=True, help="Comma-separated entity names")
    ap.add_argument("--api-prefix", default="/api/v1", help="API prefix (default: /api/v1)")
    args = ap.parse_args()

    root = Path(strip_quotes(args.root)).expanduser().resolve()
    if not root.exists():
        print(f"[ERROR] Folder not found: {root}")
        return 2

    names = {x.strip() for x in args.entities.split(",") if x.strip()}
    if not names:
        print("[ERROR] No entities provided.")
        return 2

    src_main_java = find_first_dir(root, "src/main/java")
    if not src_main_java:
        print("[ERROR] src/main/java not found.")
        return 2

    src_test_java = find_first_dir(root, "src/test/java") or (root / "src/test/java")
    src_test_java.mkdir(parents=True, exist_ok=True)

    java_files = iter_java_files(root)
    base_pkg = detect_base_package(java_files)

    entities = parse_entities(root)
    emap = entity_map(entities)
    selected = [emap[n] for n in names if n in emap]
    missing = sorted(names - set(emap.keys()))
    if missing:
        print("[WARN] Not found entities: " + ", ".join(missing))

    if not selected:
        print("[ERROR] None of the requested entities were found as @Entity.")
        return 2

    changes = []
    changes += ensure_test_config(root)
    changes += ensure_build_test_deps(root)

    written = 0
    for ent in selected:
        pth, code = generate_test_for_entity(base_pkg, args.api_prefix, src_test_java, ent, emap, names)
        write_text(pth, code)
        written += 1
        print(f"Generated: {pth.relative_to(root)}")

    if changes:
        print("\nBuild/Test config updates:")
        for c in changes:
            print(" - " + c)

    print(f"\nDone. Generated {written} test class(es).")
    print("Run: ./mvnw test  OR  ./gradlew test")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
