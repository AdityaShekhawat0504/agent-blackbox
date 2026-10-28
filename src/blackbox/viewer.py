"""Self-contained HTML timeline of one run (no JavaScript, no external assets)."""

from __future__ import annotations

import datetime as dt
import html
import json
import re

from .ledger import Event, Verification

COLORS = {
    "run_start": "#6b7280", "llm_call": "#7c3aed", "tool_call": "#2563eb", "decision": "#059669",
    "human": "#d97706", "error": "#dc2626", "note": "#6b7280", "run_end": "#6b7280",
}

CSS = """
body{font-family:-apple-system,Segoe UI,Inter,sans-serif;max-width:980px;margin:32px auto;padding:0 16px;color:#111;background:#fff}
h1{font-size:22px;margin:0 0 4px}.meta{color:#555;font-size:13px;margin-bottom:18px}
.badge{display:inline-block;padding:3px 10px;border-radius:6px;color:#fff;font-size:13px;font-weight:600;margin-left:8px}
.ev{border-left:4px solid;padding:8px 12px;margin:8px 0;background:#fafafa;border-radius:0 6px 6px 0}
.head{display:flex;gap:10px;align-items:baseline;font-size:14px}.kind{font-weight:700;min-width:84px}
.t{color:#888;font-size:12px;min-width:64px}.hash{color:#aaa;font-family:monospace;font-size:11px;margin-left:auto}
pre{white-space:pre-wrap;word-break:break-word;font-size:12px;background:#fff;border:1px solid #eee;padding:8px;border-radius:4px;margin:6px 0 0}
details summary{cursor:pointer;font-size:12px;color:#555;margin-top:4px}.pii{background:#fef3c7;border-radius:3px}
"""


def _pretty(obj) -> str:
    txt = html.escape(json.dumps(obj, indent=1, ensure_ascii=False))
    return re.sub(r"&lt;([A-Z]+):([0-9a-f]{10})&gt;", r'<span class="pii">&lt;\1:\2&gt;</span>', txt)


def _line(e: Event) -> str:
    p = e.payload
    if e.kind == "llm_call":
        flag = ""
        if p.get("replayed"):
            flag = " · replayed" + ("" if p.get("request_matches") else " · <b>request changed</b>")
        resp = p.get("response")
        return f"{html.escape(str(p.get('model')))} · {p.get('latency_ms')} ms{flag}<pre>{_pretty(resp)}</pre>" \
               f"<details><summary>request ({len(p.get('messages') or [])} messages, hash {p.get('request_hash')})</summary>" \
               f"<pre>{_pretty(p.get('messages'))}</pre></details>"
    if e.kind == "tool_call":
        out = p.get("error") or p.get("result")
        return f"<b>{html.escape(str(p.get('tool')))}</b>({_pretty(p.get('args'))[:400]})<pre>{_pretty(out)}</pre>"
    if e.kind == "decision":
        return f"<b>{html.escape(str(p.get('outcome')))}</b> <pre>{_pretty({k: v for k, v in p.items() if k != 'outcome'})}</pre>"
    if e.kind == "run_start":
        return f"{html.escape(str(p.get('agent')))} {html.escape(str(p.get('version')))}<pre>{_pretty(p.get('input'))}</pre>"
    return f"<pre>{_pretty(p)}</pre>"


def render_run(events: list[Event], verification: Verification) -> str:
    start = events[0] if events else None
    end = events[-1] if events and events[-1].kind == "run_end" else None
    t0 = start.ts if start else 0
    ok = verification.ok
    badge = f'<span class="badge" style="background:{"#059669" if ok else "#dc2626"}">' \
            f'{"chain verified" if ok else "TAMPERED"}</span>'
    when = dt.datetime.fromtimestamp(t0, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if start else ""
    rows = []
    for e in events:
        c = COLORS.get(e.kind, "#6b7280")
        rows.append(
            f'<div class="ev" style="border-color:{c}"><div class="head"><span class="t">+{e.ts - t0:.3f}s</span>'
            f'<span class="kind" style="color:{c}">{e.kind}</span><span class="hash">#{e.seq} {e.hash[:12]}</span></div>'
            f"{_line(e)}</div>"
        )
    decision = end.payload.get("decision") if end else None
    status = end.payload.get("status") if end else "incomplete"
    title = html.escape(start.run_id if start else "empty run")
    problem = "" if ok else f"<p style='color:#dc2626'><b>{html.escape(str(verification))}</b></p>"
    return (
        f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title><style>{CSS}</style></head><body>"
        f"<h1>Run {title}{badge}</h1>"
        f"<div class='meta'>{when} · {len(events)} events · status {status} · decision <b>{decision}</b> · "
        f"head {verification.head[:16]}</div>{problem}{''.join(rows)}</body></html>"
    )
