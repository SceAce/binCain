# binCain Pwn Worker

## Environment

This container is a CTF Pwn analysis workspace. Use the filesystem as durable memory and keep long logs in files instead of final answers.

Expected workspace layout:

```text
/home/kali/workspace/
  target/
  scripts/
  fuzz/
  crashes/
  findings/
  notes/
```

Use `binCain-init` during bootstrap when local challenge artifacts exist. Use `binCain-triage` to turn crashes into compact JSON before reasoning from debugger output.

## Run Profiles

Use `scripts/run_target.sh --profile <name>` instead of hand-writing loader, qemu, or debugger command lines when a profile exists.

Common profiles:

- `raw`: clean local execution for stdin or file-style tests.
- `debug`: debugger-friendly execution.
- `fuzz`: clean execution for fuzz harnesses.
- `qemu` and `qemu-debug`: cross-architecture execution when generated.

Remote services are connection profiles, not local run profiles. Read `findings/connection_profiles.json` before writing a pwntools `remote(host, port)` script.

## Event and Summary Artifacts

Treat `findings/events.jsonl` as the append-only artifact timeline. Treat `findings/summary_latest.json` as the compact Reason-time index.

Read `summary_latest.json` first when orienting. Only open deep artifacts such as `findings/crash_*.json`, `proofs/proof_*.json`, or full debugger logs when the summary points to a specific direction.

When writing Facts, cite the compact conclusion and the relevant artifact paths. Do not paste full JSON or logs into Facts.

## Primitive Hierarchy

Level 1: Data Leak. Stable leakage of canary, stack, heap, PIE, libc, or another useful secret.

Level 2: Controlled Write. A reliable arbitrary, partial, or shaped write primitive, including heap metadata corruption with a controllable consequence.

Level 3: Control Flow Hijack. Controlled PC/RIP, return address, function pointer, vtable, GOT target, signal frame, or equivalent control-flow primitive.

Facts must name the primitive level and reference reproduction files under `findings/`, `crashes/`, or `scripts/`.

Use `binCain-primitive` to assert primitive candidates when possible. Prefer tool-backed proof artifacts under `proofs/` over subjective claims from raw debugger output. Assertion statuses are `verified`, `plausible`, `unverified`, and `rejected`.

## Fuzz Policy

Use AFL++ QEMU mode or honggfuzz for stdin and file-style targets when practical. Use pwntools action-sequence fuzzing for menu, socket, and stateful targets.

Long-running fuzzers must have explicit time budgets. Write the command line, duration, corpus path, crash path, and negative results into Facts.

## Falsifiable Intents

Repeated negative results are signal, not noise. If a direction has failed several times, do not repeat the same tactic with cosmetic parameter changes.

If you continue that direction, phrase the next Intent as a falsifiable experiment: state what hypothesis will be confirmed or excluded by the attempt. Otherwise pivot to a direction that reduces uncertainty.

Human Hints may describe menu topology or protocol details. Use them to accelerate `scripts/base_interaction.py` generation, but do not assume a Hint is required for progress.

## Tool Guardrails

Do not invoke angr in the first triage round.

Prefer fuzzing, debugger reproduction, `binCain-triage`, and targeted static inspection before symbolic execution. If angr is used later, set an explicit timeout and path or step limit, and explain why cheaper methods were insufficient.

Do not paste full debugger logs into a Fact. Save full logs to `findings/` and summarize the confirmed evidence.
