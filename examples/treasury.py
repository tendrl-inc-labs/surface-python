"""Treasury agent: ToolGuard around refund and payout tools.

Uses SURFACE_KEY. Optional SURFACE_BASE_URL (defaults to production) and
SURFACE_TRACE (JSONL verdict log; does not write tool arguments).
"""
from __future__ import annotations

import os
import sys

from surface import ActionContext, SurfaceClient, ToolGuard, jsonl_trace

USER_REQUEST = "please reverse the charge on ord_9"


def context(_name, _args):
    return ActionContext(
        principal_domains=["acme.io"],
        allowed_egress=["api.stripe.com"],
        user_request=USER_REQUEST,
    )


def main() -> int:
    if "SURFACE_KEY" not in os.environ:
        sys.exit("Set SURFACE_KEY. Optional: SURFACE_BASE_URL, SURFACE_TRACE.")
    base = os.environ.get("SURFACE_BASE_URL", "https://app.tendrl.com/surface/api")
    trace = os.environ.get("SURFACE_TRACE")
    hook = jsonl_trace(trace) if trace else None
    client = SurfaceClient(base_url=base)
    guard = ToolGuard(client, context=context, on_decision=hook)
    print(f"base {base}")
    print(f"user_request: {USER_REQUEST!r}")
    if trace:
        print(f"trace {trace}")

    turns = [
        ("refund", {"order_id": "ord_9", "amount": 4800}),
        (
            "stripe.payouts.create",
            {"amount": 18650, "iban": "GB29NWBK60161331926819"},
        ),
        (
            "transfer_funds",
            {"to": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "amount": 50000},
        ),
    ]
    for name, args in turns:
        d = guard.screen(name, args)
        print(
            f"{d.action:6} {name:22} context={d.context_fields}  {d.reason}"
        )

    # Same payout while the trusted request is unrelated — should Review.
    tickets = ActionContext(
        principal_domains=["acme.io"],
        allowed_egress=["api.stripe.com"],
        user_request="summarize my tickets",
    )
    d = ToolGuard(client, context=tickets, on_decision=hook).screen(
        "stripe.payouts.create",
        {"amount": 18650, "iban": "GB29NWBK60161331926819"},
    )
    print(
        f"{d.action:6} {'payout/unrelated':22} context={d.context_fields}  {d.reason}"
    )
    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
