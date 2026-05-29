# binCain Operational Hardening Design

## Goal

This spec hardens the Cairn-compatible binCain design for real CTF competition pressure.

The original design defines binCain as a binary-security affordance layer for Cairn, not a pwn workflow engine. This remains unchanged. The hardening goal is to make that model survive high-pressure conditions:

- run environments change between raw execution, fuzzing, debugging, qemu, and remote validation
- background tools may generate artifacts while short-lived agents reason from snapshots
- LLM agents may repeat failed tactics without enough self-correction
- primitive claims need tool-side assertions instead of subjective model judgment

The guiding rule is:

```text
Tool and artifact contracts may be hard.
AI strategy remains soft.
Cairn protocol remains untouched.
```

## Non-Negotiable Boundaries

binCain must not:

- add pwn-specific objects to the Cairn server
- require typed pwn Intents
- require a fixed pwn workflow
- make the Dispatcher choose pwn strategy
- add new fields to Cairn Reason or Explore JSON payloads
- make human Hints mandatory for progress

binCain may:

- standardize worker filesystem artifacts
- provide robust helper commands
- generate compact summaries
- maintain append-only event logs
- expose failure metadata to prompts
- provide primitive assertion tools

## Operational Risks Addressed

### Dynamic run environment drift

A single static `scripts/run_<binary>.sh` is too weak for real pwn work. The same binary may need different execution profiles for raw local runs, fuzzing, debugger attachment, qemu user mode, and loader-patched replay.

### Summary race conditions

Background fuzzing or triage can update summaries while an agent is reasoning from an older state. If summaries are overwritten without an event history, the agent loses temporal context.

### Failed-tactic repetition

LLMs can repeat nearly identical failing tactics. The system should surface repeated failures strongly, but it must not hard-code a forced tactical switch.

### Primitive ambiguity

Control of PC is often easy to verify. Data leaks and write-like primitives are harder. A model should not be the final judge of whether a primitive exists.

## Run Profile Contract

### Purpose

Run profiles replace a single static run wrapper with a stable execution abstraction. The tool does not understand Cairn Intent. It only understands named execution profiles.

### Files

```text
findings/run_profiles.json
findings/connection_profiles.json
scripts/run_target.sh
```

### `findings/run_profiles.json`

This file describes local ways to execute the target.

Required profile classes:

- `raw`: minimal local execution suitable for stdin/file tests
- `debug`: debugger-friendly execution
- `fuzz`: clean execution for fuzzing harnesses
- `qemu`: qemu-user execution when native execution is not available
- `qemu-debug`: qemu-user with debug stub or debugger-ready flags

Example shape:

```json
{
  "schema": "bincain.run_profiles.v1",
  "default": "raw",
  "profiles": {
    "raw": {
      "argv": ["target/chall"],
      "env": {},
      "stdin": true,
      "notes": "Native local execution"
    },
    "debug": {
      "argv": ["gdb", "-q", "--args", "target/chall"],
      "env": {},
      "stdin": true,
      "notes": "Debugger execution"
    }
  }
}
```

### `scripts/run_target.sh`

The wrapper should prefer profile names over ad hoc command construction.

Required interface:

```bash
scripts/run_target.sh --profile raw
scripts/run_target.sh --profile debug
scripts/run_target.sh --profile fuzz
scripts/run_target.sh --profile qemu-debug
```

The wrapper may accept target-specific options, but the profile interface must remain stable.

### Remote targets

Remote validation is not a local run profile. It belongs in `connection_profiles.json`.

Example shape:

```json
{
  "schema": "bincain.connection_profiles.v1",
  "profiles": {
    "remote": {
      "host": "example.com",
      "port": 31337,
      "transport": "tcp"
    }
  }
}
```

Agent scripts should consume connection profiles explicitly rather than pretending remote execution is a local wrapper mode.

## Artifact Event Log Contract

### Purpose

The summary layer must avoid token avalanche without destroying temporal context. It must also tolerate background writers.

### Files

```text
findings/events.jsonl
findings/summary_latest.json
findings/snapshots/summary_<seq>.json
```

### Append-only events

`events.jsonl` is the canonical timeline of artifact-level changes. Each line is one JSON event.

Required fields:

```json
{
  "seq": 104,
  "created_at": "2026-05-29T12:00:00Z",
  "source": "binCain-triage",
  "kind": "crash_triaged",
  "artifact": "findings/crash_000017.json",
  "summary": "SIGSEGV with controllable rip at cyclic offset 136",
  "caused_by": "fuzz/run_000003",
  "related": ["crashes/id_000017"]
}
```

Event kinds should stay descriptive text, not server-side enums. Tools may introduce new kinds as long as the base fields remain stable.

### Latest summary

`summary_latest.json` is a compact index for Reason and bootstrap-style context loading. It must be written atomically:

1. write temporary file
2. fsync or flush when practical
3. rename into place

It should contain:

- latest event sequence
- target baseline
- active run profiles
- selected high-value crashes
- recent negative results
- primitive proof candidates
- file references for deep inspection

### Snapshots

Tools may create immutable summary snapshots:

```text
findings/snapshots/summary_000104.json
```

Facts should reference snapshots when temporal consistency matters:

```text
Summary snapshot: findings/snapshots/summary_000104.json
```

The Dispatcher does not resolve, select, or inject these snapshots. The agent reads them by path when useful.

## Summary Compression Rules

Summaries must be useful enough for Reason without forcing deep file reads.

A summary entry should include:

- what happened
- why it matters
- artifact path
- causal source when known
- confidence
- whether deeper inspection is recommended

Bad summary:

```text
Crash 17: PC controlled.
```

Good summary:

```text
Crash 17 from fuzz/run_000003 reaches SIGSEGV in target/chall; triage reports rip=0x6161616b and cyclic offset 40. Artifact: findings/crash_000017.json. Confidence: high.
```

## Falsifiable Intent Discipline

### Purpose

Repeated failures should become information. binCain should push the agent toward experiments that reduce uncertainty without changing the Cairn protocol.

### Failure metadata

The worker summary may track rough failure groups:

```json
{
  "negative_results": [
    {
      "topic": "menu edit heap overflow",
      "count": 3,
      "latest_fact": "f014",
      "summary": "Three edit-path payloads failed to cross chunk boundary; scripts hung at second prompt twice."
    }
  ]
}
```

### Prompt discipline

When a direction has repeated negative results, prompts and `AGENTS.md` should instruct the agent:

- do not repeat the same tactic with cosmetic parameter changes
- if continuing, phrase the next Intent as a falsifiable experiment
- state what hypothesis the experiment will confirm or exclude
- prefer a tactical pivot when the failed hypothesis no longer reduces uncertainty

This must be expressed inside the existing Intent `description`. No new Reason JSON fields are introduced.

Example Intent:

```text
Disprove the hypothesis that the edit action reaches a heap overflow by testing three size/content combinations against the generated menu template and recording whether any write crosses the allocated chunk boundary.
```

## Primitive Assertion Contract

### Purpose

Primitive proof claims should be backed by tool-side assertions where possible. AI may propose candidates, but tools should verify or downgrade them.

### Command shape

`binCain-primitive` should expose assertion subcommands:

```bash
binCain-primitive assert-pc --crash findings/crash_000017.json
binCain-primitive assert-offset --crash findings/crash_000017.json
binCain-primitive assert-leak --repro scripts/repro_leak.py --maps local
binCain-primitive assert-write --repro scripts/repro_write.py --watch 0xdeadbeef
```

The exact implementation may evolve, but assertion results must write structured proof artifacts.

### Proof artifact

Output path:

```text
proofs/proof_<id>.json
```

Required fields:

```json
{
  "schema": "bincain.primitive_proof.v1",
  "id": "proof_000017",
  "level": 3,
  "claim": "controllable instruction pointer",
  "status": "verified",
  "target": "target/chall",
  "reproducer": "scripts/repro_000017.sh",
  "evidence": ["findings/crash_000017.json"],
  "confidence": "high",
  "limitations": []
}
```

### Status tiers

Primitive assertion is not always binary. The status field must use one of:

- `verified`: tool-side checks confirm the primitive
- `plausible`: evidence is stable and consistent, but strong verification is unavailable
- `unverified`: claim exists but evidence is insufficient
- `rejected`: tool-side checks contradict the claim

### Level-specific expectations

Level 1, data leak:

- verify that extracted bytes are stable across runs when possible
- compare candidate addresses with process memory maps for local targets when possible
- record whether the leak maps to stack, heap, PIE, libc, or unknown memory
- downgrade to `plausible` when remote-only or map comparison is unavailable

Level 2, controlled write:

- prefer watchpoints, before/after memory snapshots, or debugger instrumentation
- record target address, controlled bytes, and limitations
- downgrade when only a secondary effect is visible

Level 3, control-flow primitive:

- prefer register control, return address overwrite, function pointer overwrite, or equivalent evidence
- include cyclic offset or mutation proof when available
- record signal and crash site

## Human Hint and Protocol Acceleration

Human Hints are powerful in CTF protocol gatekeepers, but they are not required for progress.

binCain should support:

- consuming menu topology described in Hints
- converting a trace or Hint into `scripts/base_interaction.py`
- recording the source of the protocol knowledge
- distinguishing human-provided topology from tool-observed topology

Example summary:

```text
Protocol topology from human Hint h003: 1=add(size,data), 2=delete(index), 3=edit(index,data), 4=show(index). Template: scripts/base_interaction.py. Confidence: human-provided.
```

## Updated Phase Plan

### Phase 1: Hardened evidence foundation

Deliverables:

- `findings/run_profiles.json`
- `findings/connection_profiles.json`
- `scripts/run_target.sh`
- `findings/events.jsonl`
- `findings/summary_latest.json`
- `binCain-init` updates to create baseline run profiles and summary events
- `binCain-triage` updates to append events and update summaries

Acceptance:

- a target can be run through at least `raw` and `debug` profiles
- summaries are updated atomically
- event log is append-only
- Facts can cite summary snapshots without Dispatcher support

### Phase 2: Repro and protocol affordances

Deliverables:

- `binCain-repro`
- protocol trace capture
- `scripts/base_interaction.py` generation
- summary entries linking traces, Hints, and generated scripts

Acceptance:

- a crash report can produce a replay script
- a simple menu topology can produce a reusable interaction template
- missing protocol Hints do not block generic exploration

### Phase 3: Primitive assertion

Deliverables:

- `binCain-primitive`
- `assert-pc`
- `assert-offset`
- first version of `assert-leak`
- proof artifacts under `proofs/`

Acceptance:

- at least one fixture produces a `verified` Level 3 proof
- at least one leak-like fixture produces `verified` or `plausible` Level 1 proof with clear limitations
- rejected assertions produce useful negative evidence

### Phase 4: Optional fuzz integration

Deliverables:

- fuzz campaign records
- crash selection helpers
- minimization helpers
- summary integration for background fuzzing

Acceptance:

- background fuzz output appends events without corrupting `summary_latest.json`
- triage can consume selected crashes through default artifact paths
- the agent can reason from summaries without reading entire fuzz directories

## Updated Acceptance Criteria

The operationally hardened prototype is acceptable when:

1. Cairn server and dispatcher remain pwn-agnostic.
2. No new Cairn Reason or Explore output fields are required.
3. Local execution uses run profiles instead of ad hoc wrapper edits.
4. Remote targets are represented as connection profiles, not local run modes.
5. Tool events are append-only and summaries are atomically updated.
6. Summary entries preserve enough causal context to avoid temporal confusion.
7. Repeated negative results are visible to the agent without forcing strategy.
8. Repeated directions can be continued only as meaningful falsifiable experiments or with a clear reason.
9. Primitive proof claims are backed by assertion artifacts when possible.
10. Primitive assertion results distinguish `verified`, `plausible`, `unverified`, and `rejected`.
11. Human protocol Hints accelerate exploration but are not mandatory.
12. At least one fixture demonstrates a full chain from init to triage to proof artifact to Fact-ready summary.

## Open Implementation Notes

These notes guide later implementation but are not part of the Cairn protocol:

- File writes to `summary_latest.json` should use atomic rename.
- Event sequence allocation must avoid collisions under concurrent writers.
- If file locking is unavailable, tools should use a simple lock file with timeout and stale-lock recovery.
- Summary snapshots should be created at important conclusion points, not on every event.
- Long-running fuzzers should write campaign-specific events rather than repeatedly rewriting global state.
- Assertion tools should prefer conservative downgrades over false verification.

