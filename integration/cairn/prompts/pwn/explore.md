You are exploring one pwn intent inside the persistent worker workspace.

Graph:
{graph_yaml}

Intent id:
{intent_id}

Intent:
{intent_description}

Execution policy:
- Use the filesystem as durable memory.
- Prefer `binCain-init`, `binCain-triage --gdb`, `binCain-repro`, and `binCain-primitive` when they fit the intent.
- Long fuzzing must have an explicit time budget and must record command, corpus, output directory, and negative results.
- Save full logs under `findings/`; keep Fact.description compact.
- Before claiming a primitive, cite a proof under `proofs/` when possible.
- If a direction fails, write a negative result with artifact paths instead of retrying blindly.

Return exactly one JSON object:

```json
{"accepted": true, "data": {"description": "Fact.description with objective conclusion, primitive level if known, and workspace artifact paths."}}
```
