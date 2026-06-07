# binCain Worker Container and Real Triage Design

## Goal

This phase turns binCain from local Python helper tooling into a usable worker environment for Cairn-style binary exploration.

The worker container must be able to run the binCain tools end to end against a real pwn fixture:

```text
binCain-init
  -> binCain-triage --gdb
  -> binCain-repro
  -> binCain-primitive assert-pc
  -> Fact-ready summary artifact
```

The AI agent must be able to call these tools freely and correctly from the container without a fixed pwn workflow. Docker provides the environment. `AGENTS.md` and stable CLI contracts provide affordances. Cairn still provides only `Fact / Intent / Hint`.

## Design Principles

### 1. Container as affordance, not orchestrator

The container supplies tools and stable paths. It does not decide strategy.

### 2. Real execution before fuzzing

Before adding fuzz orchestration, the project must prove that local execution, debugger triage, replay, and primitive assertion work in the exact environment that future AI workers will use.

### 3. Failure is an artifact

If real debugger triage fails, the tool must still write a structured negative artifact and event summary. A failed reproduction is useful evidence.

### 4. AI calls tools freely

`AGENTS.md` should teach tool usage patterns, but it must not impose a mandatory pipeline. The agent can inspect, run, debug, fuzz manually, or write scripts as it sees fit.

## Non-Goals

This phase does not implement:

- full automatic exploit generation
- fuzz campaign orchestration
- distributed worker scheduling
- pwn-specific Cairn server schema
- typed pwn Intents
- automatic protocol discovery beyond existing template affordances
- remote service exploitation as a required acceptance path

## Worker Image Contract

### Image location

The worker image definition lives at:

```text
worker/Dockerfile
```

### Base expectations

The image should provide:

- Python 3.11+ or distro default Python 3 if compatible with the package
- `binCain` package installed from repository source
- console scripts:
  - `binCain`
  - `binCain-init`
  - `binCain-triage`
  - `binCain-repro`
  - `binCain-primitive`
- `gdb`
- `gdb-multiarch`
- `qemu-user`
- `qemu-user-static`
- `file`
- `readelf`
- `objdump`
- `strings`
- `patchelf`
- `python3-pip`
- `pwntools`
- `ROPgadget`
- `ropper`
- `capstone`
- `unicorn`
- `z3-solver`
- `ripgrep`
- `jq`
- `socat`
- `ncat`

The image may include AFL++, honggfuzz, angr, rizin/radare2, and seccomp-tools, but those are not required for this phase's acceptance tests.

### User and workspace

The image should create a non-root analysis user, preferably `kali`, with workspace:

```text
/home/kali/workspace/
  target/
  scripts/
  fuzz/
  crashes/
  findings/
  notes/
  proofs/
```

The default working directory should be:

```text
/home/kali/workspace
```

### Agent instructions

The image must place worker guidance at:

```text
/home/kali/AGENTS.md
```

It should describe:

- run profiles
- event and summary artifacts
- `binCain-triage --gdb`
- primitive assertion
- falsifiable Intents after repeated failures
- saving logs to files instead of Facts

## Real GDB Triage Contract

### CLI shape

`binCain-triage` should support:

```bash
binCain-triage \
  --binary target/chall \
  --input crashes/id_000001 \
  --output findings/crash_000001.json \
  --arch amd64 \
  --workspace /home/kali/workspace \
  --gdb
```

Optional:

```bash
--gdb-bin gdb
--timeout 10
```

### Required outputs on success

```text
findings/crash_000001.json
findings/crash_000001_gdb.txt
findings/crash_000001.gdb
findings/events.jsonl
findings/summary_latest.json
```

The crash JSON should include:

- schema
- id
- binary
- arch
- signal
- crash input path
- input size
- registers
- controlled registers when cyclic offsets match
- backtrace
- gdb command or script path
- gdb log path
- gdb return code

### Required outputs on failure

If GDB cannot run, cannot reproduce the crash, or times out, the tool must still write:

```text
findings/crash_000001.json
findings/crash_000001_gdb.txt
findings/events.jsonl
findings/summary_latest.json
```

The crash JSON should include:

- status: `failed`
- failure reason
- attempted command
- gdb return code if available
- stdout/stderr log path
- crash input path

The event summary should be a negative result, not a silent failure.

## Fixture Contract

### Fixture location

Test fixtures should live under:

```text
tests/fixtures/pwn/
```

The first fixture should be a minimal amd64 stack overflow target that:

- reads from stdin
- crashes on cyclic input
- can be compiled inside tests or prebuilt in a deterministic way
- does not require network access
- does not require a custom libc

Suggested source:

```c
#include <unistd.h>

int main(void) {
    char buf[32];
    read(0, buf, 256);
    return 0;
}
```

Compile settings for the fixture should favor deterministic triage:

```bash
gcc -fno-stack-protector -no-pie -z execstack -o chall overflow.c
```

If the local platform cannot compile the fixture, the test should clearly skip with a reason rather than pretending success.

## Container Smoke Test Contract

### Build command

The worker image should build with:

```bash
docker build -f worker/Dockerfile -t bincain-worker:dev .
```

### Smoke command

The smoke test should mount or copy a fixture into the container workspace and run:

```bash
binCain-init /home/kali/workspace/target --workspace /home/kali/workspace
binCain-triage --binary /home/kali/workspace/target/chall \
  --input /home/kali/workspace/crashes/id_000001 \
  --output /home/kali/workspace/findings/crash_000001.json \
  --arch amd64 \
  --workspace /home/kali/workspace \
  --gdb
binCain-repro --workspace /home/kali/workspace \
  --crash-report /home/kali/workspace/findings/crash_000001.json
binCain-primitive assert-pc --workspace /home/kali/workspace \
  --crash /home/kali/workspace/findings/crash_000001.json
```

### Expected result

The smoke test should verify:

- `binCain-init` exits 0
- `binCain-triage --gdb` exits 0 for the fixture
- crash report contains a controlled PC/register or equivalent crash-control evidence
- `binCain-repro` writes a replay script
- `binCain-primitive assert-pc` writes a proof artifact
- `summary_latest.json` references the proof candidate
- `events.jsonl` contains init, triage, repro, and primitive events

## AI Usability Contract

The container is acceptable only if an AI agent can discover and call tools without remembering hidden setup.

`AGENTS.md` must include copy-paste-safe examples:

```bash
binCain-init target --workspace /home/kali/workspace
binCain-triage --binary target/chall --input crashes/id_000001 \
  --output findings/crash_000001.json --arch amd64 --workspace /home/kali/workspace --gdb
binCain-repro --workspace /home/kali/workspace --crash-report findings/crash_000001.json
binCain-primitive assert-pc --workspace /home/kali/workspace --crash findings/crash_000001.json
```

The guidance should explicitly say:

- read `findings/summary_latest.json` first
- use `scripts/run_target.sh --profile raw` for normal local execution
- use `binCain-triage --gdb` for debugger-backed crash evidence
- use `binCain-primitive` before claiming a primitive Fact
- if a tool fails, write a negative Fact citing the artifact path

## Testing Strategy

### Unit tests

Add tests for:

- Dockerfile contains required packages and installs binCain
- `binCain-triage --gdb` writes success artifacts using a fake command runner
- `binCain-triage --gdb` writes failure artifacts using a fake failing runner
- worker docs include copy-paste tool examples

### Integration tests

Add an opt-in Docker smoke test, marked or skipped unless Docker is available.

The test should:

- build the image
- compile or copy the pwn fixture
- run the smoke command inside the container
- assert final artifacts

The test should be opt-in because Docker builds are slower than normal unit tests.

Suggested command:

```bash
PYTHONPATH=src BINCAIN_DOCKER_TEST=1 python -m pytest tests/test_worker_docker_smoke.py -q
```

## Acceptance Criteria

This phase is complete when:

1. `worker/Dockerfile` builds a usable binCain worker image.
2. The image contains binCain console scripts.
3. The image contains GDB, qemu-user, pwntools, and core pwn utilities.
4. `/home/kali/AGENTS.md` exists in the image.
5. `/home/kali/workspace` has the expected artifact directories.
6. `binCain-triage --gdb` can produce debugger-backed crash artifacts.
7. GDB triage failure produces structured negative artifacts.
8. A minimal pwn fixture can produce a proof artifact inside the container.
9. `summary_latest.json` and `events.jsonl` are updated throughout the smoke chain.
10. AI-facing docs include direct command examples and preserve autonomous exploration.

## Implementation Notes

- Keep Docker tests opt-in.
- Prefer small fixtures over large binaries.
- Do not require network during test execution after the image is built.
- If a package is unavailable in the base distro, choose a nearby tool or document the omission in the Dockerfile comments.
- Do not add pwn-specific behavior to Cairn Server or Dispatcher.

