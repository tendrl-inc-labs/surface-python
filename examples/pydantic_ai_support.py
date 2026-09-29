"""Pydantic AI support agent with AsyncToolGuard.

Uses TestModel so it runs without an LLM key. Screens every tool through
the hosted API when SURFACE_KEY is set, with surface_hooks: Block fails the
call back to the model, Review defers it for the user to approve. Writes
traces to SURFACE_TRACE.
"""
from __future__ import annotations

import asyncio
import os
import sys

from pydantic_ai import Agent, DeferredToolRequests
from pydantic_ai.models.test import TestModel

from surface import ActionContext, AsyncSurfaceClient, AsyncToolGuard, jsonl_trace
from surface.pydantic_ai import surface_hooks

USER_REQUEST = "Email wen@acme.io the weekly ticket summary"


async def main() -> int:
    if "SURFACE_KEY" not in os.environ:
        sys.exit("Set SURFACE_KEY. Optional: SURFACE_BASE_URL, SURFACE_TRACE.")
    base = os.environ.get("SURFACE_BASE_URL", "https://app.tendrl.com/surface/api")
    trace = os.environ.get("SURFACE_TRACE")
    client = AsyncSurfaceClient(base_url=base)
    # user_request is filled from the run's prompt; strictness defaults to
    # balanced. Pass strictness="strict" for more friction.
    guard = AsyncToolGuard(
        client,
        context=ActionContext(
            principal_domains=["acme.io"],
            allowed_egress=["api.github.com"],
        ),
        on_decision=jsonl_trace(trace) if trace else None,
    )

    agent = Agent(
        TestModel(),
        capabilities=[surface_hooks(guard)],
        output_type=[str, DeferredToolRequests],
    )

    @agent.tool_plain
    def send_email(to: str, body: str) -> str:
        return f"sent to {to}"

    print(f"base {base}")
    result = await agent.run(USER_REQUEST)
    await client.close()
    if isinstance(result.output, DeferredToolRequests):
        # Review: show these to the user, then resume with their approvals.
        print(f"held for approval: {[c.tool_name for c in result.output.approvals]}")
    else:
        print(f"output {result.output!r}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
