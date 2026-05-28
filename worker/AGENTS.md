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

## Primitive Hierarchy

Level 1: Data Leak. Stable leakage of canary, stack, heap, PIE, libc, or another useful secret.

Level 2: Controlled Write. A reliable arbitrary, partial, or shaped write primitive, including heap metadata corruption with a controllable consequence.

Level 3: Control Flow Hijack. Controlled PC/RIP, return address, function pointer, vtable, GOT target, signal frame, or equivalent control-flow primitive.

Facts must name the primitive level and reference reproduction files under `findings/`, `crashes/`, or `scripts/`.

## Fuzz Policy

Use AFL++ QEMU mode or honggfuzz for stdin and file-style targets when practical. Use pwntools action-sequence fuzzing for menu, socket, and stateful targets.

Long-running fuzzers must have explicit time budgets. Write the command line, duration, corpus path, crash path, and negative results into Facts.

## Tool Guardrails

Do not invoke angr in the first triage round.

Prefer fuzzing, debugger reproduction, `binCain-triage`, and targeted static inspection before symbolic execution. If angr is used later, set an explicit timeout and path or step limit, and explain why cheaper methods were insufficient.

Do not paste full debugger logs into a Fact. Save full logs to `findings/` and summarize the confirmed evidence.
