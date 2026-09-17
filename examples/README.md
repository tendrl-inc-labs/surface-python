# Example agents

Two host-side agents that screen proposed tool calls with `ToolGuard` before
they run, plus a Pydantic AI hook. They use the production API by default.

```bash
export SURFACE_KEY="…"                          # never commit this
# optional: SURFACE_BASE_URL=https://…          # default is production
export SURFACE_TRACE="/tmp/surface-toolguard.jsonl"

python examples/support_desk.py     # email + HTTP
python examples/treasury.py         # refund + payout
```

Each line in `SURFACE_TRACE` is one screened call: tool name, Allow/Review/Block,
which of the three context fields were set, and finding reasons. Tool arguments
are not written.

`pydantic_ai_support.py` needs Python 3.10+ and `pydantic-ai`. It uses
`TestModel` (no LLM key) and `AsyncToolGuard` in `before_tool_execute`.

Context fields are optional: pass what you have from trusted app state — not
from the tool arguments. Values that are passed are validated. Without
context, only face-dangerous actions flag.
