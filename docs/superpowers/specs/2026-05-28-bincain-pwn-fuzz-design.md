# binCain Pwn Fuzz Design

## Goal

binCain is a Cairn-inspired exploration engine for CTF Pwn challenges. The first version targets binary-only or mostly binary-only challenges where the user provides a local challenge directory and optionally a remote `host:port`.

The first success target is not a complete exploit. The first success target is a reproducible proof of controllability, such as controlled PC/RIP, controlled write, a stable leak primitive, a format-string offset, or another clearly documented primitive that can become an exploit path.

## Scope

Supported first-version inputs:

- A local challenge directory containing one or more binaries.
- Optional `libc.so.6`, `ld-linux`, Dockerfile, README, or run script.
- Optional remote `host:port` for later validation.
- Multi-architecture ELF targets, including amd64, i386, ARM, AArch64, MIPS, and MIPSEL where tool support permits.

Out of scope for the first version:

- Full automatic exploit generation as a required success condition.
- Source-level fuzzing workflows that require compiling instrumented source.
- Kernel pwn, browser pwn, Windows PE exploitation, and firmware-scale unpacking.
- A new database schema beyond the Cairn-style project graph.

## Core Model

binCain keeps the Cairn-style blackboard model:

- `Fact`: confirmed objective information.
- `Intent`: a high-value direction for further exploration.
- `Hint`: human judgment injected at any time.

The Pwn version specializes the meanings:

- Facts include checksec results, architecture, run commands, crash paths, debugger output, controlled offsets, memory maps, primitive evidence, and failed hypotheses.
- Intents include input-surface discovery, seed generation, fuzzing, crash reproduction, crash classification, controllability analysis, leak analysis, and exploit-direction analysis.
- Hints include user guidance such as "focus on heap", "remote uses this libc", "this is menu-driven", or "do not spend time on angr".

The model remains intentionally minimal. Pwn-specific evidence is stored in standard Fact text plus referenced files in the worker workspace rather than a new schema in version one.

## Architecture

binCain will use the same separation of concerns as Cairn:

- Server: stores projects, facts, intents, hints, and project status.
- Dispatcher: runs the scheduling loop and starts worker tasks.
- Worker container: provides a persistent per-project binary-analysis workspace.
- Agent runtime: Claude Code, Codex, or a similar CLI agent invoked per task.
- Pwn toolchain: command-line tools inside the worker container.

The model process is short-lived. The dispatcher starts an agent process for a `bootstrap`, `reason`, or `explore` task. The agent reads the current graph snapshot, uses tools inside the container, returns structured JSON, and exits. Cross-task memory lives in the graph and project workspace files.

## Worker Image

The pwn worker image should include:

- Python and pwntools.
- gdb, gdbserver, gdb-multiarch, pwndbg or gef.
- qemu-user and qemu-user-static.
- binutils and multiarch binutils where available.
- file, readelf, objdump, strings, ldd, patchelf, pwninit.
- AFL++ with qemu mode where practical.
- honggfuzz or a comparable fallback fuzzer.
- radare2 or rizin.
- ROPgadget, ropper, one_gadget where architecture support permits.
- capstone, unicorn, z3, angr.
- seccomp-tools.
- ripgrep, jq, yq, tmux, socat, ncat.

The image should include a clear `AGENTS.md` that explains the workspace layout, available tools, and required evidence standard.

## Workspace Convention

Each project container should use a stable layout:

```text
/home/kali/workspace/
  target/       original attachments and normalized copies
  scripts/      generated runners, mutators, triage scripts, exploit drafts
  fuzz/         fuzzer work directories
  crashes/      minimized or selected crash inputs
  findings/     debugger logs, checksec output, triage summaries
  notes/        optional scratch notes
```

Facts should reference files under this layout instead of embedding long logs.

## First-Version Workflow

### Bootstrap

The bootstrap task performs binary triage:

- Identify binaries and supporting files.
- Run `file`, `checksec`, `readelf`, `strings`, and basic import/symbol analysis.
- Determine architecture, endianness, bitness, linking, protections, and likely input model.
- Try a safe local run with timeout.
- Determine whether native execution, qemu-user, or a wrapper is needed.
- Write a Fact summarizing the confirmed baseline and artifact paths.

### Reason

The reason task reads the graph and proposes up to a small number of non-overlapping pwn Intents. High-value first-version intents include:

- Discover input surface and interaction protocol.
- Generate seed corpus.
- Fuzz stdin/file input with AFL++ QEMU mode or honggfuzz.
- Fuzz menu/socket interaction with a pwntools action mutator.
- Reproduce a crash under gdb or gdb-multiarch.
- Classify a crash and determine whether user input controls registers or memory.
- Prove offset/control with cyclic patterns or targeted mutations.

Reason should prefer intents that reduce uncertainty and produce reproducible evidence.

### Explore

The explore task receives one current Intent and only advances that direction. It may create scripts, run fuzzers, reproduce crashes, inspect assembly, or drive the binary through pwntools.

An explore result must be an evidence-bearing Fact. If the intent fails, the Fact should still record what was tested and why the result is negative. If the task times out, the conclude fallback should summarize only confirmed progress.

## Hybrid Fuzz Strategy

binCain uses a hybrid fuzz policy.

For stdin or file-style targets:

- Prefer AFL++ QEMU mode when the target can run under qemu or natively.
- Use honggfuzz or a simple timeout runner as fallback.
- Store corpus, queue, hangs, and crashes under `fuzz/`.

For menu, socket, or stateful interaction targets:

- Generate a pwntools-based action-sequence mutator.
- Learn or encode menu prompts and operations.
- Mutate operation sequences, sizes, indexes, numbers, and payload fields.
- Store interesting transcripts and crash inputs under `crashes/` and `findings/`.

All crashes feed a shared triage path:

- Reproduce under debugger or qemu debugger.
- Capture signal, PC/RIP, stack pointer, registers, backtrace, memory maps, and nearby disassembly.
- Try cyclic patterns or delta mutations to prove input control.
- Write a control-proof Fact when controllability is confirmed.

## Control-Proof Standard

A controllability Fact should include:

- Target binary and architecture.
- Input model and reproduction command.
- Crash input path or generated reproducer script.
- Crash site, signal, and key register values.
- Controlled register, memory address, format-string offset, leak primitive, or write primitive.
- Offset or mutation proof.
- Confidence level and limitations.

Example shape:

```text
Confirmed controllable PC in target/chall (mipsel). Reproduce with
`qemu-mipsel -L target/sysroot target/chall < crashes/id_000017`.
gdb-multiarch shows PC=0x41414140 after cyclic input; cyclic analysis maps
control to offset 136. Logs: findings/crash_000017_gdb.txt. Confidence: high.
```

## Completion Semantics

Version one considers the project successful when a control-proof Fact exists and Reason can mark the goal complete using that Fact.

The system may continue beyond this if the user sets a stronger goal, such as local shell, remote shell, or flag capture. Those stronger goals are not required for the first version.

## Error Handling

- If a binary cannot run, write a Fact describing the missing loader, architecture, syscall issue, or dependency.
- If fuzzing finds no crash within budget, write a negative Fact with command, duration, corpus size, and coverage or iteration evidence when available.
- If qemu/gdb is unsupported for the architecture, Reason should switch to static or black-box mutation paths.
- If a worker times out, conclude fallback should preserve confirmed artifacts and paths.
- If all known directions are exhausted, the project should remain active and wait for a Hint in version one.

## Testing Strategy

Use a small fixture set:

- amd64 stack overflow with no canary.
- i386 format string.
- menu-driven heap bug.
- one qemu-user target such as mipsel or arm.

Acceptance checks:

- Bootstrap creates a baseline Fact with architecture and protection data.
- Reason creates pwn-specific Intents.
- Explore can run a fuzz task and save artifacts.
- Crash triage can produce a control-proof Fact on a known vulnerable fixture.
- Negative fuzz results are written as useful Facts rather than silent failures.

## Initial Implementation Direction

Start with the minimal-intrusion version:

- Keep Cairn-style graph semantics.
- Add a pwn prompt group.
- Add a pwn worker image and workspace convention.
- Add reusable scripts/templates in the worker image.
- Use standard Fact text for pwn evidence before adding any new schema.

This keeps the first version small enough to validate on real CTF Pwn challenges before committing to deeper schema or UI changes.
