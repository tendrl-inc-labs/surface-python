"""Pydantic AI support agent with AsyncToolGuard (Python 3.10+).

Uses TestModel so it runs without an LLM key. Screens every tool through
the hosted API when SURFACE_KEY is set. Writes traces to SURFACE_TRACE.
"""
from __future__ import annotations

import asyncio
import os
import sys

from pydantic_ai import Agent, DeferredToolRequests, RunContext, ToolDefinition
from pydantic_ai.capabilities import Hooks, ValidatedToolArgs
from pydantic_ai.exceptions import ApprovalRequired, ToolFailed
from pydantic_ai.messages import ToolCallPart
from pydantic_ai.models.test import TestModel

from surface import ActionContext, AsyncSurfaceClient, AsyncToolGuard, jsonl_trace

USER_REQUEST = "Email wen@acme.io the weekly ticket summary"


async def main() -> int:
    if "SURFACE_KEY" not in os.environ:
        sys.exit("Set SURFACE_KEY. Optional: SURFACE_BASE_URL, SURFACE_TRACE.")
    base = os.environ.get("SURFACE_BASE_URL", "https://app.tendrl.com/surface/api")
    trace = os.environ.get("SURFACE_TRACE")
    client = AsyncSurfaceClient(base_url=base)
    guard = AsyncToolGuard(
        client,
        context=lambda name, args: ActionContext(
            principal_domains=["acme.io"],
            allowed_egress=["api.github.com"],
            user_request=USER_REQUEST,
        ),
        on_decision=jsonl_trace(trace) if trace else None,
    )
    hooks = Hooks()

    @hooks.on.before_tool_execute
    async def surface_guard(
        ctx: RunContext,
        *,
        call: ToolCallPart,
        tool_def: ToolDefinition,
        args: ValidatedToolArgs,
    ) -> ValidatedToolArgs:
        d = await guard.screen(call.tool_name, args)
        print(f"{d.action:6} {call.tool_name} context={d.context_fields}  {d.reason}")
        if d.blocked:
            raise ToolFailed(d.reason)
        if d.needs_review:
            raise ApprovalRequired()
        return args

    agent = Agent(
        TestModel(),
        capabilities=[hooks],
        output_type=[str, DeferredToolRequests],
    )

    @agent.tool_plain
    def send_email(to: str, body: str) -> str:
        return f"sent to {to}"

    print(f"base {base}")
    result = await agent.run(USER_REQUEST)
    await client.close()
    print(f"output {result.output!r}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
