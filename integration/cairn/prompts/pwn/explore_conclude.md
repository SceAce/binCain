The explore task is ending. Preserve the best evidence from this intent.

Graph:
{graph_yaml}

Intent id:
{intent_id}

Intent:
{intent_description}

Conclude with a concise Fact.description:
- State what was confirmed, rejected, or left unknown.
- Cite generated artifacts under `findings/`, `crashes/`, `proofs/`, `scripts/`, or `notes/`.
- Do not paste full debugger logs or JSON.
- Do not add fields outside the required JSON contract.

Return exactly one JSON object:

```json
{"accepted": true, "data": {"description": "Fact.description with pwn evidence and artifact paths."}}
```
