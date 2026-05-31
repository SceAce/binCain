The bootstrap task is ending. Summarize only durable evidence.

Origin:
{origin}

Goal:
{goal}

Hints:
{hints}

Use Fact.description prose. Cite files such as `findings/init.json`, `findings/summary_latest.json`, `findings/events.jsonl`, or any negative artifact. Do not paste long logs.

Return exactly one JSON object:

```json
{"accepted": true, "data": {"fact": {"description": "Fact.description with concise pwn evidence and artifact paths."}}}
```
