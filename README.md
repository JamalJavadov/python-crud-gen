# CrudBot PRO UI (CRUD + Tests + Analyzer)

This package includes a desktop UI to manage:

- **java-project-crud.py** (your Spring Boot CRUD generator)
- **crudbot_tests.py** (generates integration tests for generated controllers/services)
- **crudbot_analyzer.py** (project analyzer/report + AI context exporter)

## Install

Python 3.10+ recommended.

```bash
pip install javalang rich
```

> Tkinter is bundled with Python on macOS and Windows in most installations.
> If tkinter is missing on Linux, install your distro package (e.g. `python3-tk`).

## Run UI

```bash
python3 crudbot_app.py
```

## Workflow

1. Select your **Spring Boot project root**
2. Select **java-project-crud.py**
3. Click **Scan entities**, select entities
4. Click **Run CRUD generation**
   - optionally: generate tests
   - optionally: run tests

### Windows note

Your original generator script uses `./mvnw` and `./gradlew` for compile check.
On Windows those wrappers are usually `mvnw.cmd` / `gradlew.bat`.
So, in the UI keep **Skip compile check (--no-compile)** enabled unless you patched the generator.

## Analyzer

Open **Project Analyzer** tab:
- choose report/context output paths
- run analyzer
- open report or copy AI context
