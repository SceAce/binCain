# binCain Cairn-Compatible Binary Affordance Design

## Goal

binCain is not a pwn workflow engine and not a CRS scheduler. It is a binary-security affordance layer for Cairn: a set of worker-side helpers, artifact conventions, and evidence standards that make binary analysis easier without constraining AI exploration.

The design goal is to preserve Cairn's open-state-space model:

- Server remains ignorant of pwn semantics.
- Dispatcher remains a task orchestrator, not a pwn strategist.
- Facts, Intents, and Hints remain the only protocol primitives.
- AI agents decide their own next step.

binCain exists to reduce friction in the binary domain:

- normalize challenge artifacts
- capture reproducible crash evidence
- provide compact summaries and indexes
- standardize replay and primitive proof artifacts
- make menu/protocol discovery easier when available

The default success condition is a reproducible primitive proof, not a finished exploit.

## Design Principles

### 1. AI autonomy first

binCain must not encode a fixed pwn workflow or a mandatory sequence of actions. It may suggest likely next steps, but it must not decide the exploration path for the agent.

Reason tasks should remain free to choose among static inspection, interactive probing, fuzzing, replay, protocol discovery, or deeper analysis.

### 2. Evidence over orchestration

The system should optimize for high-quality evidence, not for rigid process control. The value of binCain is in turning binary execution into durable artifacts that can be cited, replayed, and summarized into Facts.

### 3. Artifacts are the source of truth

Complex binary-analysis state belongs in the worker filesystem, not in the Cairn server schema. The server should see compact textual Facts plus references to artifacts.

### 4. Tools are affordances

`binCain-init`, `binCain-triage`, `binCain-repro`, and future helpers are affordances. They should be easy to invoke, predictable in output, and useful even when the agent has little prior context.

### 5. Hints accelerate, not require

Human Hints, trace samples, and discovered protocol topology should speed up exploration, but the system must still function without them.

## Architecture Boundaries

### Cairn core

The Cairn core stays unchanged:

- `Project`
- `Fact`
- `Intent`
- `Hint`

No pwn-specific server objects are introduced.

### binCain worker layer

binCain lives in the worker/container side of the system. It may provide:

- binary fingerprinting
- safe local execution wrappers
- qemu or loader-aware replay helpers
- crash triage and offset proofs
- primitive proof capture
- optional protocol discovery helpers
- optional fuzz scaffolding

These tools produce files and JSON. They do not write policy into the server.

### Artifact layer

Worker artifacts are the durable state:

- `findings/` for summaries and JSON reports
- `crashes/` for repro inputs and minimized examples
- `scripts/` for generated wrappers and replay helpers
- `fuzz/` for corpus and campaign outputs
- `proofs/` for primitive evidence and final proofs

These paths are part of the contract. They are not a replacement for Cairn Facts, only a source for them.

### Prompt and policy layer

Prompts may describe:

- available tools
- common pwn heuristics
- evidence standards
- warning signs such as repeated negative results

But prompts must not force a fixed strategy or a mandatory task sequence.

## Tool Contract

### `binCain-init`

Purpose:

- discover binaries and supporting files
- detect loader/libc candidates when present
- emit a baseline workspace summary
- create run wrappers
- optionally capture a lightweight interaction trace if a safe sample exists

Outputs:

- `findings/init.json`
- `scripts/run_<binary>.sh`
- optional summary/index files

### `binCain-triage`

Purpose:

- reproduce a crash or failing interaction
- capture signal, registers, backtrace, and mappings when available
- detect cyclic offsets where possible
- write a compact crash report

Outputs:

- `findings/crash_<id>.json`
- optional debugger log
- optional gdb script

### `binCain-repro`

Purpose:

- turn a crash report into a reproducible replay script or command
- prefer manifest-driven defaults
- allow explicit overrides

Outputs:

- `scripts/repro_<id>.sh`
- `findings/repro_<id>.json`

### `binCain-seed` and protocol helpers

Purpose:

- convert known interaction traces or Hints into a usable base interaction template
- help with protocol gatekeepers
- not mandatory for every target

Outputs:

- `scripts/base_interaction.py`
- `findings/protocol_topology.json`

## Summary and Index Strategy

The main risk in real CTF work is not lack of power, but context overload. binCain should therefore maintain a compact summary/index layer.

Required behavior:

- each major tool writes a full artifact
- each major tool may also update a compact summary index
- Reason should prefer the summary index first
- deep files are only loaded when the agent chooses to inspect a specific direction

This avoids token avalanche without forcing a brittle workflow.

The summary layer is advisory, not authoritative. The detailed artifact remains the source of truth.

## Negative-Result Policy

Repeated failure is useful only if it is visible and compact.

binCain should track:

- recent negative facts
- repeated failure counts by rough direction
- whether a hypothesis has been tested and failed multiple times

This metadata should be injected as a hint to the agent, not as a command. The agent may choose to persist, pivot, or disprove a hypothesis explicitly.

The system must not hard-code forced tactical switching after a fixed number of failures.

## Protocol Discovery Policy

Many pwn targets are menu-driven or protocol-gated. binCain should support protocol discovery, but it must not assume a working protocol exists from the start.

Preferred behavior:

- inspect README, run scripts, and static strings for sample interaction clues
- record observed banners, prompts, and valid choices
- accept human Hints describing menu structure
- generate a reusable interaction template when enough evidence exists

Fallback behavior:

- if no protocol information is available, continue with generic probing and interactive exploration
- do not depend on human Hints for progress

## Primitive Proof Standard

A positive primitive proof must be reproducible and concrete. It should include:

- target binary
- architecture and input model
- reproduction command or replay script
- evidence of the primitive
- offset or control proof when applicable
- limitations and confidence level

Accepted primitive levels:

- Level 1: stable data leak
- Level 2: controlled write or write-like effect
- Level 3: control-flow primitive

## Prototype Phases

### Phase 1: Evidence foundation

Deliverables:

- `binCain-init`
- `binCain-triage`
- `binCain-repro`
- baseline workspace conventions
- compact summary/index files

Focus:

- discover binaries
- normalize execution
- capture crash evidence
- make the outputs easy to cite in Facts

### Phase 2: Exploration affordances

Deliverables:

- protocol trace capture
- base interaction template generation
- seed record helpers
- cyclic and offset proof helpers
- better replay ergonomics

Focus:

- reduce first-contact friction
- help the agent get past protocol gates
- preserve autonomy

### Phase 3: Primitive proof workflow

Deliverables:

- standard proof record format
- leak/write/control-flow proof capture
- confidence and limitation reporting
- replayable evidence bundles

Focus:

- turn analysis into stable primitive claims
- keep the system useful even when no full exploit exists

### Phase 4: Optional fuzz scaffolding

Deliverables:

- seed/corpus helpers
- optional fuzz campaign wrappers
- crash selection and minimization helpers

Focus:

- support deeper exploration
- keep fuzzing optional, not mandatory

## Acceptance Criteria

The prototype is acceptable when all of the following are true:

1. AI can explore a target without being forced into a fixed pwn workflow.
2. `binCain-init` writes a baseline summary and runnable wrapper for a target.
3. `binCain-triage` turns a failing input into a compact, reproducible crash report.
4. The worker workspace clearly separates summaries from raw artifacts.
5. Reason can operate from compact summaries and only read deep artifacts on demand.
6. Negative exploration history is visible but does not hard-code strategy.
7. At least one target can produce a reproducible Level 1, 2, or 3 primitive proof.
8. Human Hints improve protocol discovery when present, but the system still functions without them.

## Non-Goals

binCain does not aim to:

- automate full exploit generation as a required outcome
- introduce a pwn-specific server schema
- hard-code AI tactics or force a workflow graph
- require human Hints for every target
- turn the dispatcher into a vulnerability-specific orchestrator

