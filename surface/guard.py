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

Wiring examples
---------------
Plain dispatch (any loop)::

    guard = ToolGuard(client, context=lambda name, args: ActionContext(
        principal_domains=["acme.io"],
        allowed_egress=["api.stripe.com"],
        user_request=session.user_message,
    ))

    for call in model_tool_calls:
        d = guard.screen(call.name, call.args)
        if d.blocked:      refuse(d.reason)
        elif d.needs_review: escalate_to_human(call, d)
        else:              run(call)

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
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Union

from .models import ActionContext, ScanResult

# A context source: a fixed context, or a callable computing one per tool call.
ContextSource = Union[ActionContext, dict, Callable[[str, Any], Any], None]


@dataclass
class Decision:
    """The verdict on one proposed tool call."""

    action: str  # "Allow" | "Review" | "Block"
    reason: str  # human-readable, from the strongest finding
    findings: list[dict] = field(default_factory=list)  # actionScreen.findings
    result: ScanResult | None = None  # the full scan result

    @property
    def allowed(self) -> bool:
        return self.action == "Allow"

    @property
    def blocked(self) -> bool:
        return self.action == "Block"

    @property
    def needs_review(self) -> bool:
        return self.action == "Review"


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


def _decision(res: Any) -> Decision:
    ss = getattr(res, "safety_score", None)
    if ss is None:
        # A deferred scan carries no verdict yet; it cannot clear a live action.
        return Decision("Review", "scan deferred; no verdict yet", [], res)
    findings = (getattr(res, "action_screen", None) or {}).get("findings") or []
    reason = ss.primary_threat or (findings[0].get("reason") if findings else "")
    return Decision(ss.recommended_action, reason or "", findings, res)


def _resolve_args(a: tuple, kw: dict) -> Any:
    """Best-effort view of the tool's arguments for screening."""
    if kw:
        return kw
    if len(a) == 1:
        return a[0]
    return list(a)


class ToolGuard:
    """Screens proposed tool calls with Surface and decides allow/review/block.

    Build once with a :class:`SurfaceClient`, then either call ``screen`` and
    branch yourself, or ``wrap`` a tool so it screens before it runs.
    """

    def __init__(
        self,
        client: Any,
        context: ContextSource = None,
        *,
        block_on_review: bool = False,
    ) -> None:
        self._client = client
        self._context = context
        self._block_on_review = block_on_review

    def _ctx(self, name: str, args: Any):
        c = self._context
        return c(name, args) if callable(c) else c

    def _stop(self, d: Decision) -> bool:
        return d.blocked or (self._block_on_review and d.needs_review)

    def screen(self, name: str, args: Any) -> Decision:
        """Scan a proposed tool call and return the :class:`Decision`."""
        res = self._client.scan_payload(
            tool_call_json(name, args),
            f"{name}.toolcall.json",
            context=self._ctx(name, args),
        )
        return _decision(res)

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
        res = await self._client.scan_payload(
            tool_call_json(name, args),
            f"{name}.toolcall.json",
            context=self._ctx(name, args),
        )
        return _decision(res)

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
