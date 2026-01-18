#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crudbot_app.py

Professional cross-platform Desktop UI for:
  1) java-project-crud.py  (CRUD generator)
  2) crudbot_tests.py      (integration test generator)
  3) crudbot_analyzer.py   (project analyzer / doc bot)

Works on macOS (including Apple Silicon), Windows and Linux.

Dependencies:
  pip install javalang rich

Run:
  python3 crudbot_app.py
"""
from __future__ import annotations

import os
import sys
import subprocess
import threading
import queue
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

# --- UI (tkinter) ---
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# --- optional deps for entity scanning ---
try:
    import javalang  # type: ignore
except Exception:
    javalang = None

BOT_TITLE = "CrudBot PRO UI"
DEFAULT_GENERATOR_NAME = "java-project-crud.py"

EXCLUDE_DIRS = {
    ".crudbot", ".git", ".idea", ".vscode",
    "target", "build", "out", ".gradle",
    "node_modules", "__pycache__", ".mvn",
}

SPRING_BOOT_APP_RE = __import__("re").compile(r"@SpringBootApplication\b")
JAVA_PACKAGE_RE = __import__("re").compile(r"^\s*package\s+([a-zA-Z0-9_.]+)\s*;", __import__("re").M)
ENTITY_ANNOT = "Entity"
ID_ANNOT = "Id"

def is_windows() -> bool:
    return os.name == "nt"

def strip_quotes(s: str) -> str:
    return (s or "").strip().strip('"').strip("'")

def open_in_default_app(path: Path) -> None:
    try:
        if is_windows():
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception as e:
        messagebox.showwarning("Open failed", f"Could not open file:\n{path}\n\n{e}")

def iter_java_files(root: Path) -> List[Path]:
    out: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fn in filenames:
            if fn.lower().endswith(".java"):
                out.append(Path(dirpath) / fn)
    return sorted(out)

@dataclass
class EntityInfo:
    name: str
    package: str
    file: Path
    id_field: str
    id_type: str

def scan_entities(root: Path) -> List[EntityInfo]:
    """Fast scan for @Entity classes (for UI selection list)."""
    if javalang is None:
        raise RuntimeError("Missing dependency: javalang (pip install javalang rich)")

    entities: List[EntityInfo] = []
    for f in iter_java_files(root):
        try:
            txt = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if "@Entity" not in txt:
            continue
        try:
            tree = javalang.parse.parse(txt)
        except Exception:
            continue

        pkg = tree.package.name if getattr(tree, "package", None) else ""
        for t in getattr(tree, "types", []) or []:
            anns = getattr(t, "annotations", None) or []
            ann_names = {a.name for a in anns}
            if ENTITY_ANNOT not in ann_names:
                continue

            id_field, id_type = "id", "Long"
            for node in getattr(t, "body", []) or []:
                if not isinstance(node, javalang.tree.FieldDeclaration):
                    continue
                if getattr(node, "modifiers", None) and "static" in node.modifiers:
                    continue
                ann_list = node.annotations or []
                ann_names2 = {a.name for a in ann_list}
                if ID_ANNOT in ann_names2:
                    # first declarator only is enough for UI
                    try:
                        decl = node.declarators[0]
                        id_field = decl.name
                        id_type = getattr(node.type, "name", "Long")
                    except Exception:
                        pass
                    break

            entities.append(EntityInfo(
                name=t.name,
                package=pkg,
                file=f,
                id_field=id_field,
                id_type=id_type,
            ))

    entities.sort(key=lambda e: (e.package, e.name))
    return entities

def detect_base_package(root: Path) -> str:
    java_files = iter_java_files(root)
    for f in java_files:
        try:
            txt = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if SPRING_BOOT_APP_RE.search(txt):
            m = JAVA_PACKAGE_RE.search(txt)
            if m:
                return m.group(1)
    # fallback: most frequent package
    freq = {}
    for f in java_files[:3000]:
        try:
            m = JAVA_PACKAGE_RE.search(f.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if m:
            freq[m.group(1)] = freq.get(m.group(1), 0) + 1
    if not freq:
        return "com.example"
    return sorted(freq.items(), key=lambda x: x[1], reverse=True)[0][0]

def run_stream(cmd: List[str], cwd: Optional[Path], on_line) -> int:
    """Run command and stream stdout+stderr lines to callback."""
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        on_line(line.rstrip("\n"))
    proc.wait()
    return int(proc.returncode or 0)

class App(ttk.Frame):
    def __init__(self, master: tk.Tk):
        super().__init__(master)
        self.master.title(BOT_TITLE)
        self.master.geometry("1120x760")
        self.master.minsize(980, 680)

        self.q: "queue.Queue[Tuple[str,str]]" = queue.Queue()

        # --- state ---
        self.project_root = tk.StringVar()
        self.generator_path = tk.StringVar()
        self.analyzer_out = tk.StringVar()
        self.analyzer_ctx = tk.StringVar()

        self.entities: List[EntityInfo] = []
        self.selected_names: List[str] = []

        # CRUD options
        self.api_prefix = tk.StringVar(value="")
        self.backup_mode = tk.StringVar(value="managed")
        self.overwrite_policy = tk.StringVar(value="marked")
        self.patch_all = tk.BooleanVar(value=False)
        self.dry_run = tk.BooleanVar(value=False)

        self.no_build = tk.BooleanVar(value=False)
        self.no_config = tk.BooleanVar(value=False)
        self.no_docker = tk.BooleanVar(value=False)
        self.no_openapi = tk.BooleanVar(value=False)
        # On Windows, default to skip compile because wrappers are cmd/bat unless generator is patched.
        self.no_compile = tk.BooleanVar(value=is_windows())

        # Tests
        self.gen_tests = tk.BooleanVar(value=True)
        self.run_tests = tk.BooleanVar(value=False)
        self.force_windows_friendly_compile = tk.BooleanVar(value=True)

        # Analyzer options
        self.max_file_kb = tk.IntVar(value=512)
        self.include_all_text = tk.BooleanVar(value=True)
        self.exclude_dirs_extra = tk.StringVar(value="")

        self._build_ui()
        self._poll_queue()

    # -------------- UI layout --------------

    def _build_ui(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=10)

        # Project root
        ttk.Label(top, text="Project root:").grid(row=0, column=0, sticky="w")
        ent = ttk.Entry(top, textvariable=self.project_root)
        ent.grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Button(top, text="Browse…", command=self._pick_project_root).grid(row=0, column=2, sticky="ew")

        # Generator path
        ttk.Label(top, text="CRUD generator (.py):").grid(row=1, column=0, sticky="w", pady=(8,0))
        ent2 = ttk.Entry(top, textvariable=self.generator_path)
        ent2.grid(row=1, column=1, sticky="ew", padx=(8, 8), pady=(8,0))
        ttk.Button(top, text="Browse…", command=self._pick_generator).grid(row=1, column=2, sticky="ew", pady=(8,0))

        top.columnconfigure(1, weight=1)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=12, pady=6)

        self.tab_crud = ttk.Frame(nb)
        self.tab_an = ttk.Frame(nb)
        nb.add(self.tab_crud, text="CRUD Generator")
        nb.add(self.tab_an, text="Project Analyzer")

        self._build_tab_crud()
        self._build_tab_analyzer()

        # Bottom log
        bottom = ttk.Frame(self)
        bottom.pack(fill="both", expand=False, padx=12, pady=(6, 12))

        ttk.Label(bottom, text="Log:").pack(anchor="w")
        self.log = tk.Text(bottom, height=12, wrap="none")
        self.log.pack(fill="both", expand=True)
        self.log.configure(state="disabled")

        yscroll = ttk.Scrollbar(self.log, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=yscroll.set)
        yscroll.place(relx=1.0, rely=0, relheight=1.0, anchor="ne")

    def _build_tab_crud(self) -> None:
        root = self.tab_crud
        root.columnconfigure(0, weight=1)
        root.columnconfigure(1, weight=0)

        # left: entities list
        left = ttk.Frame(root)
        left.grid(row=0, column=0, sticky="nsew", padx=(6, 10), pady=6)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)

        ttk.Label(left, text="Entities (@Entity):").grid(row=0, column=0, sticky="w")

        self.entity_list = tk.Listbox(left, selectmode="extended", height=18)
        self.entity_list.grid(row=1, column=0, sticky="nsew", pady=(6, 6))
        sc = ttk.Scrollbar(left, orient="vertical", command=self.entity_list.yview)
        self.entity_list.configure(yscrollcommand=sc.set)
        sc.grid(row=1, column=1, sticky="ns", pady=(6, 6))

        btns = ttk.Frame(left)
        btns.grid(row=2, column=0, sticky="ew")
        ttk.Button(btns, text="Scan entities", command=self._scan_entities).pack(side="left")
        ttk.Button(btns, text="Select all", command=lambda: self.entity_list.select_set(0, "end")).pack(side="left", padx=(8,0))
        ttk.Button(btns, text="Select none", command=lambda: self.entity_list.select_clear(0, "end")).pack(side="left", padx=(8,0))

        # right: options
        right = ttk.Frame(root)
        right.grid(row=0, column=1, sticky="nsew", padx=(0, 6), pady=6)

        opt = ttk.LabelFrame(right, text="Options")
        opt.pack(fill="x", pady=(0,10))

        row = 0
        ttk.Label(opt, text="API prefix override (optional):").grid(row=row, column=0, sticky="w", padx=10, pady=(8,2))
        row += 1
        ttk.Entry(opt, textvariable=self.api_prefix).grid(row=row, column=0, sticky="ew", padx=10)
        row += 1

        frm = ttk.Frame(opt)
        frm.grid(row=row, column=0, sticky="ew", padx=10, pady=(8,0))
        ttk.Label(frm, text="backup-mode:").grid(row=0, column=0, sticky="w")
        ttk.Combobox(frm, textvariable=self.backup_mode, values=["none","managed","all"], state="readonly", width=10).grid(row=0, column=1, padx=(8,14))
        ttk.Label(frm, text="overwrite-policy:").grid(row=0, column=2, sticky="w")
        ttk.Combobox(frm, textvariable=self.overwrite_policy, values=["marked","force","never"], state="readonly", width=10).grid(row=0, column=3, padx=(8,0))
        opt.columnconfigure(0, weight=1)

        row += 1
        chk = ttk.Frame(opt)
        chk.grid(row=row, column=0, sticky="ew", padx=10, pady=(10,10))
        ttk.Checkbutton(chk, text="Patch ALL entities (--patch-all)", variable=self.patch_all).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(chk, text="Dry-run (no writes)", variable=self.dry_run).grid(row=1, column=0, sticky="w", pady=(6,0))
        ttk.Checkbutton(chk, text="Skip build updates (--no-build)", variable=self.no_build).grid(row=2, column=0, sticky="w", pady=(6,0))
        ttk.Checkbutton(chk, text="Skip config yml (--no-config)", variable=self.no_config).grid(row=3, column=0, sticky="w", pady=(6,0))
        ttk.Checkbutton(chk, text="Skip docker-compose (--no-docker)", variable=self.no_docker).grid(row=4, column=0, sticky="w", pady=(6,0))
        ttk.Checkbutton(chk, text="Disable OpenAPI (--no-openapi)", variable=self.no_openapi).grid(row=5, column=0, sticky="w", pady=(6,0))
        ttk.Checkbutton(chk, text="Skip compile check (--no-compile)", variable=self.no_compile).grid(row=6, column=0, sticky="w", pady=(6,0))

        # Tests
        tst = ttk.LabelFrame(right, text="Tests")
        tst.pack(fill="x", pady=(0,10))
        ttk.Checkbutton(tst, text="Generate integration tests (MockMvc + H2)", variable=self.gen_tests).grid(row=0, column=0, sticky="w", padx=10, pady=(8,0))
        ttk.Checkbutton(tst, text="Run tests after generation (mvn/gradle test)", variable=self.run_tests).grid(row=1, column=0, sticky="w", padx=10, pady=(6,8))
        # A helper for Windows wrapper behavior (doesn't patch your generator; just suggests skipping compile)
        ttk.Checkbutton(
            tst,
            text="Windows-friendly behavior (default: skip compile)",
            variable=self.force_windows_friendly_compile
        ).grid(row=2, column=0, sticky="w", padx=10, pady=(0,10))

        runbox = ttk.Frame(right)
        runbox.pack(fill="x", pady=(6,0))
        ttk.Button(runbox, text="Run CRUD generation", command=self._run_crud).pack(fill="x")
        ttk.Button(runbox, text="Run tests only", command=self._run_tests_only).pack(fill="x", pady=(8,0))

        note = ttk.Label(right, foreground="#555", text=(
            "Tip: On Windows, your original java-project-crud.py uses ./mvnw and ./gradlew.\n"
            "If you didn't patch it to use mvnw.cmd / gradlew.bat, enable “Skip compile check”."
        ))
        note.pack(fill="x", pady=(10,0))

    def _build_tab_analyzer(self) -> None:
        root = self.tab_an
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        top = ttk.LabelFrame(root, text="Analyzer output")
        top.grid(row=0, column=0, sticky="ew", padx=6, pady=6)
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="Report (.md):").grid(row=0, column=0, sticky="w", padx=10, pady=(10,2))
        ttk.Entry(top, textvariable=self.analyzer_out).grid(row=0, column=1, sticky="ew", padx=(8,8), pady=(10,2))
        ttk.Button(top, text="Browse…", command=self._pick_analyzer_out).grid(row=0, column=2, padx=(0,10), pady=(10,2))

        ttk.Label(top, text="AI context (.txt):").grid(row=1, column=0, sticky="w", padx=10, pady=(6,2))
        ttk.Entry(top, textvariable=self.analyzer_ctx).grid(row=1, column=1, sticky="ew", padx=(8,8), pady=(6,2))
        ttk.Button(top, text="Browse…", command=self._pick_analyzer_ctx).grid(row=1, column=2, padx=(0,10), pady=(6,2))

        opts = ttk.Frame(top)
        opts.grid(row=2, column=0, columnspan=3, sticky="ew", padx=10, pady=(10,10))
        ttk.Label(opts, text="Max file KB:").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(opts, from_=64, to=4096, increment=64, textvariable=self.max_file_kb, width=8).grid(row=0, column=1, padx=(8,18))
        ttk.Checkbutton(opts, text="Include all text-like files", variable=self.include_all_text).grid(row=0, column=2, sticky="w")
        ttk.Label(opts, text="Extra exclude dirs (comma):").grid(row=1, column=0, sticky="w", pady=(8,0))
        ttk.Entry(opts, textvariable=self.exclude_dirs_extra).grid(row=1, column=1, columnspan=2, sticky="ew", padx=(8,0), pady=(8,0))
        opts.columnconfigure(2, weight=1)

        btns = ttk.Frame(top)
        btns.grid(row=3, column=0, columnspan=3, sticky="ew", padx=10, pady=(0,10))
        ttk.Button(btns, text="Run analyzer", command=self._run_analyzer).pack(side="left")
        ttk.Button(btns, text="Open report", command=self._open_report).pack(side="left", padx=(8,0))
        ttk.Button(btns, text="Open context", command=self._open_context).pack(side="left", padx=(8,0))
        ttk.Button(btns, text="Copy context", command=self._copy_context).pack(side="left", padx=(8,0))

        prev = ttk.LabelFrame(root, text="Report preview")
        prev.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0,6))
        prev.rowconfigure(0, weight=1)
        prev.columnconfigure(0, weight=1)

        self.preview = tk.Text(prev, wrap="word")
        self.preview.grid(row=0, column=0, sticky="nsew")
        sc = ttk.Scrollbar(prev, orient="vertical", command=self.preview.yview)
        self.preview.configure(yscrollcommand=sc.set)
        sc.grid(row=0, column=1, sticky="ns")

    # -------------- helpers --------------

    def _log(self, line: str) -> None:
        self.q.put(("log", line))

    def _set_preview(self, txt: str) -> None:
        self.q.put(("preview", txt))

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self.log.configure(state="normal")
                    self.log.insert("end", payload + "\n")
                    self.log.see("end")
                    self.log.configure(state="disabled")
                elif kind == "preview":
                    self.preview.delete("1.0", "end")
                    self.preview.insert("1.0", payload)
        except queue.Empty:
            pass
        self.after(90, self._poll_queue)

    # -------------- pickers --------------

    def _pick_project_root(self) -> None:
        d = filedialog.askdirectory(title="Select Spring Boot project root")
        if d:
            root = Path(d)
            self.project_root.set(str(root))
            # default analyzer outputs under project root
            self.analyzer_out.set(str(root / "project_report.md"))
            self.analyzer_ctx.set(str(root / "ai_context.txt"))
            # try auto-locate generator
            cand = root / DEFAULT_GENERATOR_NAME
            if cand.exists():
                self.generator_path.set(str(cand))

    def _pick_generator(self) -> None:
        f = filedialog.askopenfilename(
            title="Select java-project-crud.py",
            filetypes=[("Python files", "*.py"), ("All files", "*.*")]
        )
        if f:
            self.generator_path.set(f)

    def _pick_analyzer_out(self) -> None:
        f = filedialog.asksaveasfilename(
            title="Save report (.md)",
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("All files", "*.*")]
        )
        if f:
            self.analyzer_out.set(f)

    def _pick_analyzer_ctx(self) -> None:
        f = filedialog.asksaveasfilename(
            title="Save AI context (.txt)",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")]
        )
        if f:
            self.analyzer_ctx.set(f)

    # -------------- actions: CRUD --------------

    def _scan_entities(self) -> None:
        root = Path(strip_quotes(self.project_root.get() or ""))
        if not root.exists():
            messagebox.showerror("Missing project root", "Please select a valid project root.")
            return

        def work():
            try:
                self._log(f"[INFO] Scanning entities in: {root}")
                ents = scan_entities(root)
                self.entities = ents
                self.q.put(("log", f"[INFO] Found {len(ents)} entity(ies)."))
                self.q.put(("log", ""))
                self.q.put(("log", "Entities:"))
                self.entity_list.delete(0, "end")
                for e in ents:
                    self.entity_list.insert("end", f"{e.name}  ({e.package})  id={e.id_field}:{e.id_type}")
            except Exception as e:
                self._log(f"[ERROR] Entity scan failed: {e}")
                messagebox.showerror("Scan failed", str(e))

        threading.Thread(target=work, daemon=True).start()

    def _selected_entity_names(self) -> List[str]:
        idxs = list(self.entity_list.curselection())
        names: List[str] = []
        for i in idxs:
            try:
                names.append(self.entities[i].name)
            except Exception:
                pass
        return names

    def _build_crud_cmd(self, *, entities: List[str]) -> Tuple[List[str], Path]:
        root = Path(strip_quotes(self.project_root.get()))
        gen = Path(strip_quotes(self.generator_path.get()))
        if not gen.exists():
            raise RuntimeError("CRUD generator file not found. Select java-project-crud.py")
        if not root.exists():
            raise RuntimeError("Project root not found.")
        cmd: List[str] = [sys.executable, str(gen), "--root", str(root)]
        if entities:
            cmd += ["--entities", ",".join(entities)]
        else:
            cmd += ["--all"]

        if self.api_prefix.get().strip():
            cmd += ["--api-prefix", self.api_prefix.get().strip()]

        cmd += ["--backup-mode", self.backup_mode.get()]
        cmd += ["--overwrite-policy", self.overwrite_policy.get()]

        if self.dry_run.get():
            cmd += ["--dry-run"]
        if self.no_build.get():
            cmd += ["--no-build"]
        if self.no_config.get():
            cmd += ["--no-config"]
        if self.no_docker.get():
            cmd += ["--no-docker"]
        if self.no_openapi.get():
            cmd += ["--no-openapi"]
        if self.no_compile.get():
            cmd += ["--no-compile"]
        if self.patch_all.get():
            cmd += ["--patch-all"]

        return cmd, root

    def _run_crud(self) -> None:
        root = Path(strip_quotes(self.project_root.get() or ""))
        if not root.exists():
            messagebox.showerror("Missing project root", "Please select a valid project root.")
            return
        entities = self._selected_entity_names()
        if not entities:
            if not messagebox.askyesno("No entities selected", "No entities selected. Generate for ALL entities?"):
                return

        def work():
            try:
                self._log("=" * 80)
                self._log("[RUN] CRUD generator")
                cmd, cwd = self._build_crud_cmd(entities=entities)
                self._log("[CMD] " + " ".join(cmd))
                rc = run_stream(cmd, cwd=cwd, on_line=self._log)
                self._log(f"[DONE] CRUD generator exit code: {rc}")

                if rc != 0:
                    self._log("[STOP] CRUD generation failed; tests skipped.")
                    return

                if self.gen_tests.get():
                    self._log("")
                    self._log("[RUN] Test generator")
                    rc2 = self._run_tests_generator(root, entities)
                    self._log(f"[DONE] Test generator exit code: {rc2}")

                    if rc2 != 0:
                        self._log("[WARN] Test generation failed.")
                        return

                if self.run_tests.get():
                    self._log("")
                    self._log("[RUN] mvn/gradle test")
                    rc3 = self._run_build_tests(root)
                    self._log(f"[DONE] test task exit code: {rc3}")

            except Exception as e:
                self._log(f"[ERROR] {e}")
                messagebox.showerror("Run failed", str(e))

        threading.Thread(target=work, daemon=True).start()

    def _run_tests_only(self) -> None:
        root = Path(strip_quotes(self.project_root.get() or ""))
        if not root.exists():
            messagebox.showerror("Missing project root", "Please select a valid project root.")
            return
        entities = self._selected_entity_names()

        def work():
            try:
                self._log("=" * 80)
                self._log("[RUN] Test generator (only)")
                rc2 = self._run_tests_generator(root, entities)
                self._log(f"[DONE] Test generator exit code: {rc2}")
                if self.run_tests.get() and rc2 == 0:
                    self._log("")
                    self._log("[RUN] mvn/gradle test")
                    rc3 = self._run_build_tests(root)
                    self._log(f"[DONE] test task exit code: {rc3}")
            except Exception as e:
                self._log(f"[ERROR] {e}")
                messagebox.showerror("Run failed", str(e))

        threading.Thread(target=work, daemon=True).start()

    def _run_tests_generator(self, project_root: Path, entities: List[str]) -> int:
        # crudbot_tests.py is shipped with this UI (same folder)
        tests_py = Path(__file__).with_name("crudbot_tests.py")
        if not tests_py.exists():
            raise RuntimeError("crudbot_tests.py not found рядом with UI.")

        cmd: List[str] = [sys.executable, str(tests_py), "--root", str(project_root)]
        if entities:
            cmd += ["--entities", ",".join(entities)]
        else:
            cmd += ["--all"]
        self._log("[CMD] " + " ".join(cmd))
        return run_stream(cmd, cwd=project_root, on_line=self._log)

    def _run_build_tests(self, project_root: Path) -> int:
        # Try Maven wrapper, then Gradle wrapper, then system binaries.
        cwd = project_root
        # if project uses multi-module, wrappers are usually at root; we just run at project_root
        if (cwd / "mvnw").exists() and not is_windows():
            cmd = ["./mvnw", "-q", "test"]
        elif (cwd / "mvnw.cmd").exists() and is_windows():
            cmd = ["cmd", "/c", "mvnw.cmd", "-q", "test"]
        elif (cwd / "gradlew").exists() and not is_windows():
            cmd = ["./gradlew", "-q", "test"]
        elif (cwd / "gradlew.bat").exists() and is_windows():
            cmd = ["cmd", "/c", "gradlew.bat", "-q", "test"]
        elif shutil_which("mvn"):
            cmd = ["mvn", "-q", "test"]
        elif shutil_which("gradle"):
            cmd = ["gradle", "-q", "test"]
        else:
            self._log("[WARN] No mvn/gradle found; skipping test run.")
            return 0

        self._log("[CMD] " + " ".join(cmd))
        return run_stream(cmd, cwd=cwd, on_line=self._log)

    # -------------- actions: Analyzer --------------

    def _run_analyzer(self) -> None:
        root = Path(strip_quotes(self.project_root.get() or ""))
        if not root.exists():
            messagebox.showerror("Missing project root", "Please select a valid project root.")
            return

        out_path = Path(strip_quotes(self.analyzer_out.get() or "")).expanduser()
        ctx_path = Path(strip_quotes(self.analyzer_ctx.get() or "")).expanduser()
        if not out_path.name:
            out_path = root / "project_report.md"
            self.analyzer_out.set(str(out_path))
        if not ctx_path.name:
            ctx_path = root / "ai_context.txt"
            self.analyzer_ctx.set(str(ctx_path))

        max_bytes = int(self.max_file_kb.get()) * 1024
        include_all = bool(self.include_all_text.get())
        extra_excl = [x.strip() for x in (self.exclude_dirs_extra.get() or "").split(",") if x.strip()]

        def work():
            try:
                self._log("=" * 80)
                self._log("[RUN] Project analyzer")
                self._log(f"[INFO] Root: {root}")
                self._log(f"[INFO] Report: {out_path}")
                self._log(f"[INFO] Context: {ctx_path}")
                # Import analyzer module (shipped in this zip)
                import importlib
                analyzer = importlib.import_module("crudbot_analyzer")

                exclude_dirs = set(getattr(analyzer, "DEFAULT_EXCLUDE_DIRS", [])) | set(extra_excl)

                scan = analyzer.scan_project(
                    root=root,
                    exclude_dirs=exclude_dirs,
                    max_file_bytes=max_bytes,
                    include_all_text=include_all
                )

                report_parts = [
                    analyzer.make_overview(scan),
                    analyzer.make_structure_section(scan),
                    analyzer.make_build_section(scan),
                    analyzer.make_packages_section(scan),
                    analyzer.make_files_section(scan),
                ]
                report = "\n\n".join(report_parts).rstrip() + "\n"
                analyzer.safe_write(out_path, report)

                ctx_txt = analyzer.make_ai_context(scan).rstrip() + "\n"
                analyzer.safe_write(ctx_path, ctx_txt)

                self._log("[DONE] Analyzer complete.")
                self._log(f"[DONE] Report:  {out_path.resolve()}")
                self._log(f"[DONE] Context: {ctx_path.resolve()}")

                # preview (first 200KB for UI)
                try:
                    prev = report if len(report) <= 200_000 else report[:200_000] + "\n\n...(truncated in UI preview)\n"
                except Exception:
                    prev = "Preview unavailable."
                self._set_preview(prev)

            except Exception as e:
                self._log(f"[ERROR] Analyzer failed: {e}")
                messagebox.showerror("Analyzer failed", str(e))

        threading.Thread(target=work, daemon=True).start()

    def _open_report(self) -> None:
        p = Path(strip_quotes(self.analyzer_out.get() or ""))
        if p.exists():
            open_in_default_app(p)
        else:
            messagebox.showinfo("Not found", "Report file not found yet. Run analyzer first.")

    def _open_context(self) -> None:
        p = Path(strip_quotes(self.analyzer_ctx.get() or ""))
        if p.exists():
            open_in_default_app(p)
        else:
            messagebox.showinfo("Not found", "Context file not found yet. Run analyzer first.")

    def _copy_context(self) -> None:
        p = Path(strip_quotes(self.analyzer_ctx.get() or ""))
        if not p.exists():
            messagebox.showinfo("Not found", "Context file not found yet. Run analyzer first.")
            return
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
            self.clipboard_clear()
            self.clipboard_append(txt)
            self._log("[OK] Context copied to clipboard.")
        except Exception as e:
            messagebox.showwarning("Copy failed", str(e))


def shutil_which(name: str) -> Optional[str]:
    # small wrapper to avoid importing shutil in global scope (faster cold start)
    import shutil
    return shutil.which(name)

def main() -> int:
    root = tk.Tk()
    # nicer spacing on mac/win
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    app = App(root)
    app.pack(fill="both", expand=True)
    root.mainloop()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
