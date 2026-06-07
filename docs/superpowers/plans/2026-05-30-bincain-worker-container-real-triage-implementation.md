# binCain Worker Container and Real Triage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Docker-ready binCain worker with real GDB triage, fixture-backed smoke coverage, and AI-friendly command examples.

**Architecture:** Keep all behavior worker-side. Add debugger execution to `bincain.triage`, expose missing console scripts through `pyproject.toml`, add a Dockerfile that installs binCain and pwn tooling, and add opt-in Docker smoke tests using a small pwn fixture.

**Tech Stack:** Python 3.11+, pytest, click, Docker, GCC/GDB.

---

## Task 1: Real GDB Triage

**Files:**
- Modify: `src/bincain/triage.py`
- Modify: `src/bincain/cli.py`
- Test: `tests/test_triage.py`

- [ ] Add failing tests for `run_gdb_triage` success and failure using fake command runners.
- [ ] Implement GDB script generation, command execution with timeout, register/signal/backtrace parsing, success JSON, failure JSON, log file, and workspace event/summary updates.
- [ ] Add `binCain-triage --gdb --workspace --gdb-bin --timeout` CLI options.
- [ ] Run `PYTHONPATH=src python -m pytest tests/test_triage.py -q`.
- [ ] Commit with `git commit -m "Add real gdb triage support"`.

## Task 2: Console Scripts

**Files:**
- Modify: `pyproject.toml`
- Test: `tests/test_imports.py`

- [ ] Add failing tests that project scripts include `binCain-repro`, `binCain-primitive`, and `binCain-protocol-template`.
- [ ] Add console script entries pointing to existing click commands.
- [ ] Run `PYTHONPATH=src python -m pytest tests/test_imports.py -q`.
- [ ] Commit with `git commit -m "Expose operational helper console scripts"`.

## Task 3: Worker Dockerfile and Docs

**Files:**
- Create: `worker/Dockerfile`
- Modify: `worker/AGENTS.md`
- Test: `tests/test_worker_dockerfile.py`
- Test: `tests/test_worker_docs.py`

- [ ] Add failing Dockerfile and docs tests for required packages, installed scripts, workspace layout, and copy-paste GDB triage examples.
- [ ] Implement Dockerfile using Ubuntu base, apt pwn tools, pip Python tools, source install, non-root `kali` user, workspace directories, and `/home/kali/AGENTS.md`.
- [ ] Update worker guidance with `binCain-triage --gdb` examples.
- [ ] Run `PYTHONPATH=src python -m pytest tests/test_worker_dockerfile.py tests/test_worker_docs.py -q`.
- [ ] Commit with `git commit -m "Add binCain worker Dockerfile"`.

## Task 4: Pwn Fixture and Opt-In Docker Smoke Test

**Files:**
- Create: `tests/fixtures/pwn/controlled_pc.c`
- Create: `tests/test_worker_docker_smoke.py`

- [ ] Add a fixture source that reads stdin and calls an input-controlled function pointer.
- [ ] Add an opt-in pytest skipped unless `BINCAIN_DOCKER_TEST=1`.
- [ ] The smoke test builds the image, compiles the fixture inside a temporary directory, runs `init -> triage --gdb -> repro -> primitive assert-pc` in Docker, and checks final artifacts.
- [ ] Run default tests and verify Docker smoke is skipped without env.
- [ ] Run `BINCAIN_DOCKER_TEST=1 PYTHONPATH=src python -m pytest tests/test_worker_docker_smoke.py -q` when Docker is available.
- [ ] Commit with `git commit -m "Add worker Docker smoke test fixture"`.

## Task 5: Full Verification and Push

**Files:**
- All changed files

- [ ] Run `PYTHONPATH=src python -m pytest -q`.
- [ ] Run Docker smoke if Docker build is available.
- [ ] Run `git status --short --branch`.
- [ ] Push only after tests pass.

