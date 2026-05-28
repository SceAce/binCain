# binCain Pwn Fuzz Design

## Goal

binCain is a Cairn-inspired exploration engine for CTF Pwn challenges. The first version targets binary-only or mostly binary-only challenges where the user provides a local challenge directory and optionally a remote `host:port`.

The first success target is not a complete exploit. The first success target is a reproducible proof of an exploitation primitive. The primitive may be a stable data leak, a controlled write, controlled PC/RIP, a format-string offset, or another clearly documented capability that can become an exploit path.

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
- Automatic state-machine extraction for complex heap menus as a required V1 feature.

## Core Model

binCain keeps the Cairn-style blackboard model:

- `Fact`: confirmed objective information.
- `Intent`: a high-value direction for further exploration.
- `Hint`: human judgment injected at any time.

The Pwn version specializes the meanings:

- Facts include checksec results, architecture, run commands, crash paths, debugger output, controlled offsets, memory maps, primitive evidence, and failed hypotheses.
- Intents include input-surface discovery, seed generation, fuzzing, crash reproduction, crash classification, primitive analysis, leak analysis, and exploit-direction analysis.
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

The image should also include binCain helper scripts that absorb repetitive binary-analysis mechanics from the agent:

- `binCain-init`: normalize a challenge directory, identify binaries, apply libc/ld patching when possible, and emit native or qemu run commands.
- `binCain-triage`: reproduce a crash under gdb or gdb-multiarch and emit a compact JSON crash report.

These helpers keep the Server and Dispatcher unchanged while reducing agent context load and avoiding common arithmetic and dynamic-linking mistakes.

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

Helper outputs should be stored under this layout:

```text
findings/init.json             normalized binary and runtime metadata
findings/crash_<id>.json       compact crash triage report
findings/crash_<id>_gdb.txt    optional full debugger log
scripts/run_<binary>.sh        generated local or qemu run wrapper
```

## First-Version Workflow

### Bootstrap

The bootstrap task performs binary triage:

- Identify binaries and supporting files.
- Run `binCain-init` when the challenge directory contains local artifacts.
- Run `file`, `checksec`, `readelf`, `strings`, and basic import/symbol analysis.
- Determine architecture, endianness, bitness, linking, protections, and likely input model.
- Try a safe local run with timeout.
- Determine whether native execution, qemu-user, or a wrapper is needed.
- Write a Fact summarizing the confirmed baseline and artifact paths.

`binCain-init` should wrap `pwninit` and `patchelf` where possible. If it detects a local `libc.so.6` without a matching loader, it should attempt to locate or download the matching `ld-linux` through the configured pwninit source, patch a copy of the binary, and emit a reliable command that the agent can reuse. If patching fails, the failure and next manual command should be written to `findings/init.json`.

### Reason

The reason task reads the graph and proposes up to a small number of non-overlapping pwn Intents. High-value first-version intents include:

- Discover input surface and interaction protocol.
- Generate seed corpus.
- Fuzz stdin/file input with AFL++ QEMU mode or honggfuzz.
- Fuzz menu/socket interaction with a pwntools action mutator.
- Reproduce a crash with `binCain-triage` under gdb or gdb-multiarch.
- Classify a crash from the triage JSON and determine whether user input controls registers or memory.
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

- Reproduce through `binCain-triage` under debugger or qemu debugger.
- Capture signal, PC/RIP, stack pointer, registers, backtrace, memory maps, nearby disassembly, and cyclic matches in compact JSON.
- Try cyclic patterns or delta mutations to prove input control.
- Write a primitive-proof Fact when a useful primitive is confirmed.

## Primitive Hierarchy

V1 accepts three levels of exploitation primitive as valid positive progress:

- Level 1, Data Leak: stable leakage of canary, stack address, heap address, PIE base, libc base, or another useful address or secret.
- Level 2, Controlled Write: controlled write to a chosen or partially chosen address, heap metadata corruption with controllable consequence, or a reliable write-like primitive.
- Level 3, Control Flow Hijack: controlled PC/RIP, return address, function pointer, vtable, GOT/PLT target, signal frame, or equivalent control-flow primitive.

This hierarchy is part of the evidence policy, not a new database schema. Facts should explicitly state the primitive level.

## Primitive-Proof Standard

A primitive-proof Fact should include:

- Target binary and architecture.
- Input model and reproduction command.
- Crash input path or generated reproducer script.
- Crash site, signal, and key register values when applicable.
- Primitive level.
- Controlled register, memory address, format-string offset, leak source, write primitive, or control-flow primitive.
- Offset or mutation proof.
- Confidence level and limitations.

Example shape:

```text
Confirmed Level 3 primitive in target/chall (mipsel): controllable PC. Reproduce with
`qemu-mipsel -L target/sysroot target/chall < crashes/id_000017`.
gdb-multiarch shows PC=0x41414140 after cyclic input; cyclic analysis maps
control to offset 136. Logs: findings/crash_000017_gdb.txt. Confidence: high.
```

## Completion Semantics

Version one considers the project successful when a Level 1, Level 2, or Level 3 primitive-proof Fact exists and Reason can mark the goal complete using that Fact. Stronger goals can be requested by the user, but the default V1 completion target is primitive confirmation rather than a final exploit.

The system may continue beyond this if the user sets a stronger goal, such as local shell, remote shell, or flag capture. Those stronger goals are not required for the first version.

## Tool Guardrails

Some binary-analysis tools are powerful but expensive. V1 should use prompt and `AGENTS.md` guardrails instead of Server-side enforcement:

- Do not invoke angr in the first triage round.
- Prefer fuzzing, debugger reproduction, and targeted static inspection before symbolic execution.
- If angr is used, it must run with explicit wall-clock timeout, bounded path depth or step count, and a written reason explaining why cheaper methods were insufficient.
- Long-running fuzzers must run with explicit time budgets and write command lines plus output directories to Facts.

These rules prevent the agent from turning every challenge into an unbounded symbolic-execution job.

## Error Handling

- If a binary cannot run, write a Fact describing the missing loader, architecture, syscall issue, or dependency.
- If fuzzing finds no crash within budget, write a negative Fact with command, duration, corpus size, and coverage or iteration evidence when available.
- If qemu/gdb is unsupported for the architecture, Reason should switch to static or black-box mutation paths.
- If a worker times out, conclude fallback should preserve confirmed artifacts and paths.
- If `binCain-init` cannot patch a binary, write the exact failure and fallback run command instead of retrying blindly.
- If `binCain-triage` cannot reproduce a crash, preserve the crash input, original fuzzer command, and observed failure mode.
- If all known directions are exhausted, the project should remain active and wait for a Hint in version one.

## V1.5 Menu Topology

Menu-driven heap and stateful interaction programs benefit from explicit protocol discovery. This is useful but not required for V1.

V1.5 should add a dedicated `explore_protocol` style intent through prompts, still without changing Server schema. The agent should run the program, observe banners and prompts, inspect strings when useful, and write a compact menu topology JSON:

```json
{
  "prompt": "> ",
  "actions": {
    "1": {"name": "add", "fields": ["size", "content"]},
    "2": {"name": "delete", "fields": ["index"]},
    "3": {"name": "show", "fields": ["index"]},
    "4": {"name": "edit", "fields": ["index", "content"]}
  }
}
```

Later pwntools action mutators can use this topology as a seed instead of rediscovering the interaction pattern.

## Testing Strategy

Use a small fixture set:

- amd64 stack overflow with no canary.
- i386 format string.
- menu-driven heap bug.
- one qemu-user target such as mipsel or arm.

Acceptance checks:

- Bootstrap creates a baseline Fact with architecture and protection data.
- `binCain-init` writes `findings/init.json` and a run wrapper on a fixture with supplied libc.
- Reason creates pwn-specific Intents.
- Explore can run a fuzz task and save artifacts.
- `binCain-triage` can produce a compact crash JSON on a known crashing input.
- Crash triage can produce a primitive-proof Fact on a known vulnerable fixture.
- Negative fuzz results are written as useful Facts rather than silent failures.

## Initial Implementation Direction

Start with the minimal-intrusion version:

- Keep Cairn-style graph semantics.
- Add a pwn prompt group.
- Add a pwn worker image and workspace convention.
- Add `binCain-init`, `binCain-triage`, and reusable fuzz/script templates in the worker image.
- Use standard Fact text for pwn evidence before adding any new schema.
- Encode primitive hierarchy and heavy-tool guardrails in prompts and `AGENTS.md`.

This keeps the first version small enough to validate on real CTF Pwn challenges before committing to deeper schema or UI changes.

## Implementation Priority

Implement immediately in V1:

- `binCain-init` for pwninit/patchelf based dependency normalization.
- Primitive hierarchy and completion semantics in prompts and `AGENTS.md`.
- Heavy-tool guardrails, especially angr timeout and first-round restrictions.

Develop during V1 fixture validation:

- `binCain-triage` JSON crash reporter using GDB Python and pwntools cyclic helpers.

Defer to V1.5:

- Dedicated menu topology extraction and topology-driven action mutators.
