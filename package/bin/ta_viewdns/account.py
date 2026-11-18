"""Account balance summary (ported from the XSOAR ``viewdns-account-balance`` command)."""

from .actions import to_int


def summarize_balance(body):
    response = body.get("response") or {}
    plan = "trial" if "trial" in response else "monthly"
    subscription = response.get(plan) or {}
    limit = to_int(subscription.get("limit"))
    usage = to_int(subscription.get("usage"))
    unlimited = limit == 0
    remaining = None
    if limit and usage is not None:
        remaining = max(limit - usage, 0)
    return {
        "plan": plan,
        "monthly_limit": "unlimited" if unlimited else limit,
        "monthly_usage": usage,
        "monthly_remaining": "unlimited" if unlimited else remaining,
        "prepaid_balance": to_int((response.get("prepaid") or {}).get("balance")),
    }
