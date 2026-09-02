"""One HTML file, opened locally. No CDN, no font, no script that phones home.

Everything is inline on purpose: a page about not leaking anything should not
fetch a stylesheet from somebody else's server, because that request carries a
referrer and an IP and arrives the moment the report is opened.

Order is by DEPTH, not by a severity guess. A thing one hop from the inbox needs
no cleverness from anybody, and that is the fact worth putting first.

The page ends on the moves rather than the danger. The fear is not the product.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from . import chain, policy

CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d0f12;color:#e7e3dc;
     font:16px/1.55 ui-sans-serif,system-ui,-apple-system,sans-serif;
     padding:2rem 1.1rem 4rem;display:flex;justify-content:center}
main{width:100%;max-width:47rem}
h1{font-size:1.5rem;letter-spacing:-.01em;margin-bottom:.15rem}
.sub{color:#8b9199;font-size:.85rem;margin-bottom:1.4rem}
.caveat{border:1px solid #2b3038;border-left:3px solid #6b7178;background:#12151a;
        border-radius:.4rem;padding:.7rem .85rem;margin-bottom:1.6rem;
        color:#a8b0b8;font-size:.85rem;line-height:1.5}
.headline{font-size:1.32rem;line-height:1.4;margin:0 0 .35rem;font-weight:600}
.headline b{color:#e0b45f}
.headline.clear b{color:#6fbf8b}
h2{font-size:.72rem;letter-spacing:.15em;text-transform:uppercase;color:#6b7178;
   margin:2.2rem 0 .7rem;font-weight:700}
.row{border:1px solid #23272e;border-radius:.55rem;background:#14171c;
     padding:.75rem .85rem;margin-bottom:.5rem}
.row.d1{border-left:3px solid #b4463f}
.row.d2{border-left:3px solid #c8a24a}
.row.safe{border-left:3px solid #3a6b4a;background:#111713}
.row.cond{border-left:3px dashed #5a6b7a}
.nm{font-weight:600;font-size:1rem}
.nm .dom{color:#6b7178;font-weight:400;font-size:.8rem;
         font-family:ui-monospace,monospace;margin-left:.4rem}
.tag{float:right;font:11px/1.7 ui-monospace,monospace;letter-spacing:.06em;
     padding:0 .45rem;border-radius:.25rem;background:#24282f;color:#a8b0b8}
.tag.OPEN,.tag.UNKNOWN{background:#3a1a1a;color:#e8a0a0}
.tag.THEATRE{background:#3a2a12;color:#e8c98a}
.tag.PHONE{background:#2a2f3a;color:#a8c0e0}
.tag.APP,.tag.HARDWARE{background:#16301f;color:#8ed6a8}
.d{color:#8b9199;font-size:.82rem;margin-top:.2rem}
.path{margin-top:.5rem;padding-left:.15rem;border-left:1px solid #2a3038}
.hop{color:#9aa2ab;font-size:.79rem;padding:.12rem 0 .12rem .7rem;position:relative}
.hop b{color:#cfd6dd;font-weight:600}
.hop .k{font:10.5px ui-monospace,monospace;letter-spacing:.06em;color:#6b7178;
        text-transform:uppercase;margin-right:.35rem}
.move{border:1px solid #2a3a4a;background:#111820;border-radius:.55rem;
      padding:.8rem .9rem;margin-bottom:.55rem}
.move .n{font-weight:600}
.move .n span{float:right;font:11.5px ui-monospace,monospace;color:#7fb0d8}
.move .a{margin-top:.3rem;font-size:.9rem}
.move .r{margin-top:.25rem;color:#8b9199;font-size:.81rem}
.foot{margin-top:2.6rem;padding-top:1rem;border-top:1px solid #1e222a;
      color:#6b7178;font-size:.78rem;line-height:1.6}
code{font-family:ui-monospace,monospace;font-size:.85em;color:#c8a24a}
.big{font-size:2.6rem;font-weight:700;line-height:1;color:#e0b45f}
.big.clear{color:#6fbf8b}
"""

TOP_CAVEAT = (
    "This shows what each service <b>offers</b>, not what you have switched on. "
    "If a service supports an authenticator app but you never turned it on, it "
    "appears here as safe and is not. So this is a map of your best possible "
    "defence &mdash; the real one is at best this good, and probably worse."
)


def _e(s) -> str:
    return html.escape(str(s or ""))


def _hop_line(edge, nodes) -> str:
    dst = nodes.get(edge.dst)
    dstname = dst.name if dst else edge.dst
    src = nodes.get(edge.src)
    srcname = src.name if src else edge.src
    kind = {chain.RESET: "resets", chain.SIM: "sim swap",
            chain.MX: "mx", chain.VAULT: "if in vault",
            chain.AUTHBACKUP: "if app syncs"}.get(edge.kind, edge.kind)
    return (f'<div class=hop><span class=k>{_e(kind)}</span>'
            f'<b>{_e(srcname)}</b> -&gt; <b>{_e(dstname)}</b><br>{_e(edge.why)}</div>')


def _row(n, nodes) -> str:
    cls = "row"
    if n.reachable:
        cls += f" d{min(n.depth, 2)}"
        if n.only_conditional:
            cls += " cond"
    else:
        cls += " safe"
    out = [f'<div class="{cls}">',
           f'<div class=nm><span class="tag {_e(n.klass)}">{_e(n.klass)}</span>'
           f'{_e(n.name)}<span class=dom>{_e(n.domain)}</span></div>',
           f'<div class=d>{_e(policy.EXPLAIN.get(n.klass, ""))}</div>']
    if n.reachable:
        hops = "".join(_hop_line(e, nodes) for e in n.path)
        out.append(f'<div class=path>{hops}</div>')
        if n.only_conditional:
            out.append('<div class=d style="margin-top:.4rem;color:#7f8fa0">'
                       'Dashed: this path needs the stated assumption to be true. '
                       'If it is not, this account is not reachable this way.</div>')
    out.append("</div>")
    return "".join(out)


def render(g: chain.Graph, moves: list, stats: dict) -> str:
    nodes = g.nodes
    reached = sorted(g.reached(), key=lambda n: (n.depth, not _money(n), n.name.lower()))
    safe = sorted((n for n in nodes.values() if not n.reachable), key=lambda n: n.name.lower())
    one_hop = len(g.at_depth(1))
    total, hit = len(nodes), len(reached)

    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    clear = "" if hit else " clear"

    if hit:
        head = (f'<b>{hit} of your {total} accounts</b> can be reached from your '
                f'inbox. <b>{one_hop}</b> of them in one hop.')
    else:
        head = (f'<b>None of your {total} accounts</b> can be reached from your '
                f'inbox alone. That is the good answer and it is rare.')

    parts = [
        "<!doctype html><html lang=en><meta charset=utf-8>",
        '<meta name=viewport content="width=device-width,initial-scale=1">',
        "<title>downstream &mdash; what your email opens</title>",
        f"<style>{CSS}</style><body><main>",
        "<h1>downstream</h1>",
        f'<p class=sub>What your email opens. Generated locally {when}. '
        f'Nothing on this page left your machine.</p>',
        f'<div class=caveat>{TOP_CAVEAT}</div>',
        f'<div class="big{clear}">{hit}</div>',
        f'<p class="headline{clear}">{head}</p>',
        f'<p class=sub>Read from {stats.get("messages", 0):,} message headers &mdash; '
        f'{stats.get("domains", 0):,} sender domains, {total} of them look like '
        f'accounts. No message body was opened.</p>',
    ]

    if moves:
        parts.append(f"<h2>the {len(moves)} moves &mdash; do these first</h2>")
        covered = len({d for m in moves for d in m.covers})
        parts.append(f'<p class=sub>These {len(moves)} changes disconnect '
                     f'<b>{covered} of {hit}</b>. They are ordered by how much '
                     f'each one removes, not by how frightening it is.</p>')
        for i, m in enumerate(moves, 1):
            parts.append(
                f'<div class=move><div class=n>{i}. {_e(m.name)}'
                f'<span>removes {len(m.covers)}</span></div>'
                f'<div class=a>{_e(m.action)}</div>'
                f'<div class=r>{_e(m.reason)}</div></div>')

    if reached:
        parts.append("<h2>what falls, nearest first</h2>")
        parts += [_row(n, nodes) for n in reached]
    if safe:
        parts.append("<h2>already out of reach</h2>")
        parts += [_row(n, nodes) for n in safe]

    parts.append(
        '<div class=foot>'
        '<b>What this cannot see.</b> Services that have never emailed you. '
        'Accounts opened before your mailbox history starts. Whether you actually '
        'switched on the second factor a service offers. Anything whose mail is in '
        'a language other than English. And an account you signed up for with a '
        'different address.<br><br>'
        'Second-factor data from <code>2fa.directory</code>, MIT licensed, fetched '
        'once and cached. It is never asked anything about you.<br><br>'
        'Run <code>downstream --forget</code> to delete everything this tool has '
        'written about you.'
        '</div></main></body></html>')
    return "".join(parts)


def _money(n) -> bool:
    return bool(n.service and n.service.holds_money)
