"""Tool-call screening for AI agents.

Surface screens the tool call your agent proposes *before* you execute it, and
returns Allow / Review / Block. This module packages the propose -> scan ->
branch pattern so you drop it into your agent loop instead of hand-wiring the
scan, the verdict check, and the branch every time.

It is deliberately framework-agnostic: a tool is ultimately a function, so
`ToolGuard.wrap` guards any callable, and `ToolGuard.screen` gives you the raw
decision to branch on yourself. Context (`principal_domains`, `allowed_egress`,
`user_request`) comes from *your* trusted request state, never from the tool
arguments — pass a callable if it varies per call.

Context fields are optional: pass only what you have from trusted request
state. A field that is omitted stays silent (outside-org email needs
``principal_domains``, undeclared hosts need ``allowed_egress``, task-fit
needs ``user_request``). Values that *are* passed are validated. Without
any context, only face-dangerous actions flag.

Wiring examples
---------------
Plain dispatch (any loop)::

    guard = ToolGuard(client)

    for call in model_tool_calls:
        d = guard.screen(call.name, call.args)
        if d.blocked:      refuse(d.reason)
        elif d.needs_review: escalate_to_human(call, d)
        else:              run(call)

    # Optional: pass trusted app state, not the tool arguments.
    guard = ToolGuard(client, context=ActionContext(
        principal_domains=["acme.io"],
        user_request=session.user_message,
    ))

LangChain / LangGraph (wrap the tool's function)::

    from langchain_core.tools import StructuredTool
    safe = StructuredTool.from_function(guard.wrap(transfer_funds))
    # or in a LangGraph pre-tool node, call guard.screen(...) and route to an
    # interrupt() on `needs_review`, to the tool node on `allowed`.

OpenAI Agents SDK (a tool guardrail / on_tool_start hook)::

    def surface_guardrail(ctx, agent, tool, arguments):
        d = guard.screen(tool.name, arguments)
        return GuardrailFunctionOutput(output_info=d.reason,
                                       tripwire_triggered=d.blocked)

Pydantic AI (``Hooks.before_tool_execute``; use AsyncToolGuard)::

    from pydantic_ai.capabilities import Hooks
    from pydantic_ai.exceptions import ApprovalRequired, ToolFailed

    hooks = Hooks()

    @hooks.on.before_tool_execute
    async def surface_guard(ctx, *, call, tool_def, args):
        d = await guard.screen(call.tool_name, args)
        if d.blocked:       raise ToolFailed(d.reason)    # tool never runs
        if d.needs_review:  raise ApprovalRequired()      # native HITL
        return args

    agent = Agent("openai:gpt-4o", capabilities=[hooks])
    # Do not wrap() the tool function: ToolBlocked aborts the whole run,
    # and Pydantic AI inspects signatures to build tool schemas.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Union

from .models import ActionContext, ScanResult, parse_action_context

# A context source: a fixed context, or a callable computing one per tool call.
ContextSource = Union[ActionContext, dict, Callable[[str, Any], Any], None]
DecisionHook = Callable[["Decision"], None]


@dataclass
class Decision:
    """The verdict on one proposed tool call."""

    action: str  # "Allow" | "Review" | "Block"
    reason: str  # human-readable, from the strongest finding
    findings: list[dict] = field(default_factory=list)  # actionScreen.findings
    result: ScanResult | None = None  # the full scan result
    tool: str = ""
    context_fields: dict[str, bool] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.action == "Allow"

    @property
    def blocked(self) -> bool:
        return self.action == "Block"

    @property
    def needs_review(self) -> bool:
        return self.action == "Review"

    @property
    def context_present(self) -> bool:
        return any(self.context_fields.values())


class ToolBlocked(Exception):
    """Raised by a wrapped tool when Surface's verdict stops it from running."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(
            f"Surface stopped a tool call ({decision.action}): {decision.reason}"
        )


def tool_call_json(name: str, args: Any) -> str:
    """Serialize a proposed tool call into the shape the scanner reads."""
    return json.dumps({"tool": name, "args": args}, default=str)


def context_fields(ctx: Any) -> dict[str, bool]:
    """Which ToolGuard context fields were actually populated."""
    if ctx is None:
        return {
            "principal_domains": False,
            "allowed_egress": False,
            "user_request": False,
        }
    if isinstance(ctx, dict):
        domains = ctx.get("principal_domains") or []
        egress = ctx.get("allowed_egress") or []
        req = ctx.get("user_request") or ""
    else:
        domains = getattr(ctx, "principal_domains", None) or []
        egress = getattr(ctx, "allowed_egress", None) or []
        req = getattr(ctx, "user_request", None) or ""
    return {
        "principal_domains": bool(domains),
        "allowed_egress": bool(egress),
        "user_request": bool(str(req).strip()),
    }


def jsonl_trace(path: str | os.PathLike) -> DecisionHook:
    """Append one JSON line per screened call: verdict and which context landed.

    Does not write tool arguments (those can be customer data). Point
    ``SURFACE_TRACE`` at a file in the example agents, or pass this as
    ``on_decision``.
    """

    def _write(d: Decision) -> None:
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tool": d.tool,
            "action": d.action,
            "reason": d.reason,
            "context_present": d.context_present,
            "context_fields": d.context_fields,
            "findings": [
                (f.get("reason") if isinstance(f, dict) else str(f))
                for f in (d.findings or [])
            ],
        }
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")

    return _write


def _decision(res: Any, tool: str = "", ctx: Any = None) -> Decision:
    ss = getattr(res, "safety_score", None)
    fields = context_fields(ctx)
    if ss is None:
        # A deferred scan carries no verdict yet; it cannot clear a live action.
        return Decision(
            "Review", "scan deferred; no verdict yet", [], res, tool, fields
        )
    findings = (getattr(res, "action_screen", None) or {}).get("findings") or []
    reason = ss.primary_threat or (findings[0].get("reason") if findings else "")
    return Decision(ss.recommended_action, reason or "", findings, res, tool, fields)


def _resolve_args(a: tuple, kw: dict) -> Any:
    """Best-effort view of the tool's arguments for screening."""
    if kw:
        return kw
    if len(a) == 1:
        return a[0]
    return list(a)


class ToolGuard:
    """Screens proposed tool calls with Surface and decides allow/review/block.

    Build once with a :class:`SurfaceClient` and a context source, then either
    call ``screen`` and branch yourself, or ``wrap`` a tool so it screens
    before it runs. ``context`` is optional; fields you pass are validated
    and must come from trusted app state — not from the tool arguments.
    """

    def __init__(
        self,
        client: Any,
        context: ContextSource = None,
        *,
        block_on_review: bool = False,
        on_decision: DecisionHook | None = None,
    ) -> None:
        self._client = client
        self._context = context
        self._block_on_review = block_on_review
        self._on_decision = on_decision

    def _ctx(self, name: str, args: Any):
        c = self._context
        raw = c(name, args) if callable(c) else c
        return parse_action_context(raw)

    def _stop(self, d: Decision) -> bool:
        return d.blocked or (self._block_on_review and d.needs_review)

    def _emit(self, d: Decision) -> Decision:
        if self._on_decision is not None:
            self._on_decision(d)
        return d

    def screen(self, name: str, args: Any) -> Decision:
        """Scan a proposed tool call and return the :class:`Decision`."""
        ctx = self._ctx(name, args)
        res = self._client.scan_payload(
            tool_call_json(name, args),
            f"{name}.toolcall.json",
            context=ctx,
        )
        return self._emit(_decision(res, name, ctx))

    def wrap(self, fn: Callable[..., Any], name: str | None = None) -> Callable[..., Any]:
        """Wrap a tool function so it screens its own call before executing.

        On Block (or Review when ``block_on_review``) it raises
        :class:`ToolBlocked` instead of running the tool.
        """
        tool_name = name or getattr(fn, "__name__", "tool")

        def wrapped(*a: Any, **kw: Any) -> Any:
            decision = self.screen(tool_name, _resolve_args(a, kw))
            if self._stop(decision):
                raise ToolBlocked(decision)
            return fn(*a, **kw)

        wrapped.__name__ = tool_name
        wrapped.__doc__ = fn.__doc__
        wrapped.__wrapped__ = fn  # type: ignore[attr-defined]
        return wrapped


class AsyncToolGuard(ToolGuard):
    """Async variant: ``screen`` and wrapped tools are awaitable."""

    async def screen(self, name: str, args: Any) -> Decision:  # type: ignore[override]
        ctx = self._ctx(name, args)
        res = await self._client.scan_payload(
            tool_call_json(name, args),
            f"{name}.toolcall.json",
            context=ctx,
        )
        return self._emit(_decision(res, name, ctx))

    def wrap(  # type: ignore[override]
        self, fn: Callable[..., Awaitable[Any]], name: str | None = None
    ) -> Callable[..., Awaitable[Any]]:
        tool_name = name or getattr(fn, "__name__", "tool")

        async def wrapped(*a: Any, **kw: Any) -> Any:
            decision = await self.screen(tool_name, _resolve_args(a, kw))
            if self._stop(decision):
                raise ToolBlocked(decision)
            return await fn(*a, **kw)

        wrapped.__name__ = tool_name
        wrapped.__doc__ = fn.__doc__
        wrapped.__wrapped__ = fn  # type: ignore[attr-defined]
        return wrapped
