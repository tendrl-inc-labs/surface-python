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

Strictness (``strictness="relaxed" | "balanced" | "strict"``, default
balanced) sets how readily a judgment call becomes a verdict: balanced lets
routine work through (a support reply to a Gmail customer, an official
installer) and Blocks what is dangerous on its face or plainly exfiltration.

Context fields are optional: pass only what you have from trusted request
state. A field that is omitted stays silent (outside-org email needs
``principal_domains``, undeclared hosts need ``allowed_egress``, task-fit
needs ``user_request``). Values that *are* passed are validated. Without
any context, what is certainly malicious Blocks and irreversible actions
(deleting data, granting admin) are held for Review.

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

Pydantic AI (``surface.pydantic_ai.surface_hooks``; use AsyncToolGuard)::

    from surface.pydantic_ai import surface_hooks

    agent = Agent("openai:gpt-4o", capabilities=[surface_hooks(guard)],
                  output_type=[str, DeferredToolRequests])
    # Block fails the tool call back to the model; Review defers it for
    # approval (ApprovalRequired). The run's prompt is sent as user_request.
    # Do not wrap() the tool function: ToolBlocked aborts the whole run,
    # and Pydantic AI inspects signatures to build tool schemas.
"""
from __future__ import annotations

import inspect
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Union

from .models import STRICTNESS_LEVELS, ActionContext, ScanResult, parse_action_context

# A context source: a fixed context, or a callable computing one per tool call.
ContextSource = Union[ActionContext, dict, Callable[[str, Any], Any], None]
DecisionHook = Callable[["Decision"], None]
# What a wrapped tool does on Review: "hold" (raise ToolNeedsReview), "allow"
# (run it), or a callable that gets the Decision and returns True to run it.
ReviewPolicy = Union[str, Callable[["Decision"], Any]]


@dataclass
class Decision:
    """The verdict on one proposed tool call."""

    action: str  # "Allow" | "Review" | "Block"
    reason: str  # human-readable, from the strongest finding
    findings: list[dict] = field(default_factory=list)  # actionScreen.findings
    result: ScanResult | None = None  # the full scan result
    tool: str = ""
    context_fields: dict[str, bool] = field(default_factory=dict)
    strictness: str = "balanced"  # the level the call was screened at
    # From result.action_risk when present (informational; does not change
    # action). None / [] when the scanner returned no actionRisk.
    risk_probability: float | None = None
    risk_reasons: list[str] = field(default_factory=list)

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


class ToolNeedsReview(ToolBlocked):
    """Raised by a wrapped tool on a Review verdict: a person should confirm it.

    A subclass of :class:`ToolBlocked`, so code that already catches that
    stays safe. Catch this one first to ask the user and retry, e.g. with
    ``guard.approved()``.
    """


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
            "strictness": d.strictness,
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
    level = getattr(ctx, "strictness", None) or "balanced"
    if ss is None:
        # A deferred scan carries no verdict yet; it cannot clear a live action.
        return Decision(
            "Review", "scan deferred; no verdict yet", [], res, tool, fields, level
        )
    findings = (getattr(res, "action_screen", None) or {}).get("findings") or []
    reason = ss.primary_threat or (findings[0].get("reason") if findings else "")
    risk = getattr(res, "action_risk", None)
    return Decision(
        ss.recommended_action,
        reason or "",
        findings,
        res,
        tool,
        fields,
        level,
        risk_probability=getattr(risk, "probability", None),
        risk_reasons=list(getattr(risk, "reasons", None) or []),
    )


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

    ``strictness`` ("relaxed", "balanced", "strict") applies to every call
    unless the context sets its own; omitted, the scanner uses balanced.

    ``on_review`` decides what a *wrapped* tool does on Review, which means
    "a person should confirm this": ``"hold"`` (the default) raises
    :class:`ToolNeedsReview` instead of running it, ``"allow"`` runs it, and a
    callable gets the :class:`Decision` and returns True to run it — ask the
    user there. ``block_on_review`` is the older spelling: True is "hold",
    False is "allow".
    """

    def __init__(
        self,
        client: Any,
        context: ContextSource = None,
        *,
        strictness: str | None = None,
        on_review: ReviewPolicy = "hold",
        block_on_review: bool | None = None,
        on_decision: DecisionHook | None = None,
    ) -> None:
        if strictness is not None and strictness not in STRICTNESS_LEVELS:
            raise ValueError(f"strictness must be one of {', '.join(STRICTNESS_LEVELS)}")
        if block_on_review is not None:
            on_review = "hold" if block_on_review else "allow"
        if not callable(on_review) and on_review not in ("hold", "allow"):
            raise ValueError('on_review must be "hold", "allow", or a callable')
        self._client = client
        self._context = context
        self._strictness = strictness
        self._on_review = on_review
        self._on_decision = on_decision

    def _ctx(self, name: str, args: Any, user_request: str | None = None):
        c = self._context
        raw = c(name, args) if callable(c) else c
        ctx = parse_action_context(raw)
        # Guard-level defaults fill only what the context leaves empty.
        updates: dict[str, Any] = {}
        if self._strictness and (ctx is None or ctx.strictness is None):
            updates["strictness"] = self._strictness
        if user_request and (ctx is None or not ctx.user_request):
            updates["user_request"] = str(user_request)
        if updates:
            ctx = (ctx or ActionContext()).model_copy(update=updates)
        return ctx

    def _review_runs(self, d: Decision) -> Any:
        """Whether a Review verdict lets the tool run (may be awaitable)."""
        if callable(self._on_review):
            return self._on_review(d)
        return self._on_review == "allow"

    def _emit(self, d: Decision) -> Decision:
        if self._on_decision is not None:
            self._on_decision(d)
        return d

    def screen(self, name: str, args: Any, *, user_request: str | None = None) -> Decision:
        """Scan a proposed tool call and return the :class:`Decision`.

        ``user_request`` fills the context's request when it has none — the
        framework hooks pass the run's prompt here.
        """
        ctx = self._ctx(name, args, user_request)
        res = self._client.scan_payload(
            tool_call_json(name, args),
            f"{name}.toolcall.json",
            context=ctx,
        )
        return self._emit(_decision(res, name, ctx))

    def wrap(self, fn: Callable[..., Any], name: str | None = None) -> Callable[..., Any]:
        """Wrap a tool function so it screens its own call before executing.

        On Block it raises :class:`ToolBlocked`; on Review it follows
        ``on_review`` — by default raising :class:`ToolNeedsReview`.
        """
        tool_name = name or getattr(fn, "__name__", "tool")

        def wrapped(*a: Any, **kw: Any) -> Any:
            decision = self.screen(tool_name, _resolve_args(a, kw))
            if decision.blocked:
                raise ToolBlocked(decision)
            if decision.needs_review and not self._review_runs(decision):
                raise ToolNeedsReview(decision)
            return fn(*a, **kw)

        wrapped.__name__ = tool_name
        wrapped.__doc__ = fn.__doc__
        wrapped.__wrapped__ = fn  # type: ignore[attr-defined]
        return wrapped


class AsyncToolGuard(ToolGuard):
    """Async variant: ``screen`` and wrapped tools are awaitable.

    An ``on_review`` callable may be sync or async.
    """

    async def review_runs(self, d: Decision) -> bool:
        """Whether a Review verdict lets the tool run, awaiting the policy if needed."""
        out = self._review_runs(d)
        if inspect.isawaitable(out):
            out = await out
        return bool(out)

    async def screen(  # type: ignore[override]
        self, name: str, args: Any, *, user_request: str | None = None
    ) -> Decision:
        ctx = self._ctx(name, args, user_request)
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
            if decision.blocked:
                raise ToolBlocked(decision)
            if decision.needs_review and not await self.review_runs(decision):
                raise ToolNeedsReview(decision)
            return await fn(*a, **kw)

        wrapped.__name__ = tool_name
        wrapped.__doc__ = fn.__doc__
        wrapped.__wrapped__ = fn  # type: ignore[attr-defined]
        return wrapped
