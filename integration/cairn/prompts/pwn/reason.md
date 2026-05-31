You are reasoning over a Cairn pwn graph. Keep the graph model unchanged.

Graph:
{graph_yaml}

Fact ids:
{fact_ids}

Open intents:
{open_intents}

Reasoning policy:
- Facts are free text. Do not invent typed pwn fields.
- If `findings/summary_latest.json` is cited, prefer it before opening deeper artifacts.
- Complete only when the graph contains a verified primitive or the stated goal is satisfied.
- If no open intent exists and the goal is not complete, return falsifiable pwn intents.
- Good intents name one evidence-producing experiment: init, probe, fuzz with budget, GDB triage, repro, primitive assertion, or local reverse inspection.
- Static/hybrid/fuzz posture is guidance only. Explain why the next step should produce evidence.

Return one of these exact JSON shapes:

```json
{"accepted": true, "data": {"complete": {"from": ["f001"], "description": "Fact.description evidence that satisfies the goal."}}}
```

```json
{"accepted": true, "data": {"intents": [{"from": ["f001"], "description": "Falsifiable pwn experiment with expected artifact path."}]}}
```

```json
{"accepted": true, "data": {}}
```
