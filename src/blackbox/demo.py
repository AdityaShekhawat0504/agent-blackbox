"""A small customer-refund agent to demonstrate recording, replay and regression tests.

The "model" is a deterministic stand-in for an LLM so the demo, the tests and
CI run offline and give the same result every time. It speaks the same
protocol a real tool-calling model would: it reads the conversation and
returns either a tool call or a final answer. Swap ``ScriptedModel`` for a
real client and nothing else changes.

``ScriptedModel("v2")`` contains a realistic regression: after a prompt change
meant to make the agent "faster for urgent customers", it skips the policy
check when a message sounds urgent. The regression suite catches it.
"""

from __future__ import annotations

import json
import re

SYSTEM_PROMPT = (
    "You are a refund assistant. Always look up the order, then check the refund policy "
    "before issuing any refund. Refunds above 200 EUR need a human. Reply with one JSON action."
)

ORDERS = {
    "A-1001": {"amount": 49.90, "status": "delivered", "delivered_days_ago": 5,
               "customer": "lena.maier@example.de", "iban": "DE89 3704 0044 0532 0130 00"},
    "A-1002": {"amount": 349.00, "status": "delivered", "delivered_days_ago": 3,
               "customer": "j.okafor@example.com", "iban": "DE02 1203 0000 0000 2020 51"},
    "A-1003": {"amount": 19.99, "status": "delivered", "delivered_days_ago": 64,
               "customer": "tom.becker@example.org", "iban": "DE89 3704 0044 0532 0130 00"},
    "A-1004": {"amount": 89.00, "status": "in_transit", "delivered_days_ago": None,
               "customer": "s.yilmaz@example.de", "iban": "DE02 1203 0000 0000 2020 51"},
}

REFUNDS: list[dict] = []


# ------------------------------------------------------------------- tools

def lookup_order(order_id: str) -> dict:
    if order_id not in ORDERS:
        raise KeyError(f"unknown order {order_id}")
    return {"order_id": order_id, **ORDERS[order_id]}


def check_policy(amount: float, status: str, delivered_days_ago: int | None) -> dict:
    if status != "delivered":
        return {"eligible": False, "needs_human": False, "reason": "order not delivered yet"}
    if delivered_days_ago is not None and delivered_days_ago > 30:
        return {"eligible": False, "needs_human": False, "reason": "outside 30-day window"}
    if amount > 200:
        return {"eligible": True, "needs_human": True, "reason": "amount above 200 EUR"}
    return {"eligible": True, "needs_human": False, "reason": "within policy"}


def issue_refund(order_id: str, amount: float) -> dict:
    ref = {"refund_id": f"R-{len(REFUNDS) + 1:04d}", "order_id": order_id, "amount": amount}
    REFUNDS.append(ref)
    return ref


def escalate_to_human(order_id: str, reason: str) -> dict:
    return {"ticket": f"T-{sum(map(ord, order_id)) * 37 % 10000:04d}", "queue": "refund-review", "reason": reason}


TOOLS = {f.__name__: f for f in (lookup_order, check_policy, issue_refund, escalate_to_human)}


# ------------------------------------------------------------------- model

class ScriptedModel:
    """Deterministic stand-in for a tool-calling LLM."""

    def __init__(self, version: str = "v1"):
        self.version = version
        self.name = f"scripted-refund-model-{version}"

    def __call__(self, messages: list[dict]) -> dict:
        user = messages[1]["content"]
        done = [json.loads(m["content"]) for m in messages if m["role"] == "assistant"]
        results = [json.loads(m["content"]) for m in messages if m["role"] == "tool"]
        called = [d.get("tool") for d in done]

        m = re.search(r"\b[A-Z]-\d{4}\b", user)
        if not m:
            return {"final": "clarify", "reply": "Which order number is this about?"}
        oid = m.group(0)

        if "lookup_order" not in called:
            return {"tool": "lookup_order", "args": {"order_id": oid}}
        order = results[called.index("lookup_order")]
        if "error" in order:
            return {"final": "clarify", "reply": "I could not find that order."}

        urgent = bool(re.search(r"\b(urgent|asap|immediately)\b", user, re.I))
        if self.version == "v2" and urgent and "issue_refund" not in called:
            # Regression: "be faster for urgent customers" skipped the policy check.
            return {"tool": "issue_refund", "args": {"order_id": oid, "amount": order["amount"]}}

        if "check_policy" not in called and "issue_refund" not in called:
            return {"tool": "check_policy", "args": {k: order[k] for k in ("amount", "status", "delivered_days_ago")}}
        if "issue_refund" in called:
            return {"final": "refund", "reply": "Your refund is on its way.",
                    "details": {"amount": order["amount"], "order_id": oid}}

        policy = results[called.index("check_policy")]
        if policy["eligible"] and policy["needs_human"]:
            if "escalate_to_human" not in called:
                return {"tool": "escalate_to_human", "args": {"order_id": oid, "reason": policy["reason"]}}
            return {"final": "escalate", "reply": "A colleague will review your refund.",
                    "details": {"reason": policy["reason"]}}
        if policy["eligible"]:
            return {"tool": "issue_refund", "args": {"order_id": oid, "amount": order["amount"]}}
        return {"final": "deny", "reply": f"Sorry, I can't refund this: {policy['reason']}.",
                "details": {"reason": policy["reason"]}}


# ------------------------------------------------------------------- agent

def refund_agent(inp: dict, run, model: ScriptedModel | None = None, max_steps: int = 8) -> str:
    model = model or ScriptedModel("v1")
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": inp["message"]}]
    for _ in range(max_steps):
        snapshot = json.loads(json.dumps(messages))
        action = run.llm(model=model.name, messages=snapshot, call=lambda: model(snapshot),
                         params={"temperature": 0})
        if "final" in action:
            run.decision(action["final"], **action.get("details", {}))
            return action["reply"]
        try:
            result = run.tool(action["tool"], TOOLS[action["tool"]], **action["args"])
        except KeyError as exc:
            result = {"error": str(exc)}
        # sort_keys: replay serves responses back from JSON; unsorted dumps would
        # change the next request and every replayed call would look "different".
        messages.append({"role": "assistant", "content": json.dumps(action, sort_keys=True)})
        messages.append({"role": "tool", "content": json.dumps(result, sort_keys=True)})
    run.decision("gave_up")
    return "Sorry, something went wrong."


SCENARIOS = [
    {"name": "small refund within window",
     "input": {"message": "Hi, I'm lena.maier@example.de, please refund order A-1001, it arrived broken."},
     "expect": {"decision": "refund", "must_call": ["lookup_order", "check_policy"],
                "must_call_before": [["check_policy", "issue_refund"]], "must_not_call": ["escalate_to_human"]}},
    {"name": "urgent small refund",
     "input": {"message": "URGENT: refund A-1001 asap, call me on +49 151 23456789."},
     "expect": {"decision": "refund", "must_call_before": [["check_policy", "issue_refund"]]}},
    {"name": "large refund needs a human",
     "input": {"message": "Refund A-1002 please, the TV is damaged."},
     "expect": {"decision": "escalate", "must_call": ["escalate_to_human"], "must_not_call": ["issue_refund"]}},
    {"name": "urgent large refund still needs a human",
     "input": {"message": "I need my money immediately for A-1002!"},
     "expect": {"decision": "escalate", "must_not_call": ["issue_refund"]}},
    {"name": "outside 30-day window",
     "input": {"message": "Can I get a refund for A-1003? Pay it to DE89 3704 0044 0532 0130 00."},
     "expect": {"decision": "deny", "must_not_call": ["issue_refund"]}},
    {"name": "not delivered yet",
     "input": {"message": "Where is my refund for A-1004?"},
     "expect": {"decision": "deny", "must_not_call": ["issue_refund"]}},
    {"name": "no order number",
     "input": {"message": "I want my money back."},
     "expect": {"decision": "clarify", "max_tool_calls": 0}},
]
