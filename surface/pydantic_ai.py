"""Surface for Pydantic AI agents: one capability that screens every tool call.

    from pydantic_ai import Agent, DeferredToolRequests
    from surface import AsyncSurfaceClient, AsyncToolGuard
    from surface.pydantic_ai import surface_hooks

    guard = AsyncToolGuard(AsyncSurfaceClient(), strictness="balanced")
    agent = Agent("openai:gpt-4o", capabilities=[surface_hooks(guard)],
                  output_type=[str, DeferredToolRequests])

Before each tool runs, the proposed call is screened:

- Block: the call fails back to the model with the reason (``ToolFailed``),
  so the agent can explain or try something else.
- Review: the call is deferred for approval (``ApprovalRequired``), which
  ends the run with ``DeferredToolRequests`` for your app to show the user.
  Once approved and resumed, the call runs without a second scan. A guard
  built with ``on_review="allow"`` or a callable follows that instead.
- Allow: the call runs.

The run's prompt is sent as ``user_request`` whenever the guard's context
doesn't set one, which is what lets Surface tell an action the user asked for
("delete my drafts") from one that arrived through a document or web page.
If your app builds the prompt from untrusted content (retrieved documents,
emails), set ``user_request`` in the guard's context to the user's own words
instead.

Needs ``pydantic-ai``; this module is only imported when you use it.
"""
from __future__ import annotations

from typing import Any

from .guard import AsyncToolGuard


def prompt_text(prompt: Any) -> str | None:
    """The text of a Pydantic AI run prompt (a string or a list of parts)."""
    if prompt is None:
        return None
    if isinstance(prompt, str):
        return prompt
    parts = [p for p in prompt if isinstance(p, str)]
    return "\n".join(parts) or None


def surface_hooks(guard: AsyncToolGuard) -> Any:
    """A Pydantic AI ``Hooks`` capability that screens each tool call with ``guard``."""
    from pydantic_ai.capabilities import Hooks
    from pydantic_ai.exceptions import ApprovalRequired, ToolFailed

    if not isinstance(guard, AsyncToolGuard):
        raise TypeError("surface_hooks needs an AsyncToolGuard (Pydantic AI hooks are async)")

    hooks = Hooks()

    @hooks.on.before_tool_execute
    async def _surface_screen(ctx: Any, *, call: Any, tool_def: Any, args: Any) -> Any:
        if getattr(ctx, "tool_call_approved", False):
            return args  # a person already approved this held call
        d = await guard.screen(call.tool_name, args, user_request=prompt_text(getattr(ctx, "prompt", None)))
        if d.blocked:
            raise ToolFailed(f"Surface blocked this action: {d.reason}")
        if d.needs_review and not await guard.review_runs(d):
            raise ApprovalRequired()
        return args

    return hooks
