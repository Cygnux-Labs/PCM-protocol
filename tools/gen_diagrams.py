"""Draw the README's diagrams as docs/img/{flow,judge,grants}-{light,dark}.svg, in the chart's palette and type."""
import os

FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
THEMES = {
    "light": {"text": "#0b0b0b", "muted": "#52514e", "line": "#8d8c85", "box": "#f4f4f1", "edge": "#d9d8d2",
              "accent": "#2a78d6", "ok": "#008300", "maybe": "#b97c00", "bad": "#d33a39", "on": "#ffffff"},
    "dark": {"text": "#f2f1ec", "muted": "#c3c2b7", "line": "#8d8c85", "box": "#1f2328", "edge": "#3a3a37",
             "accent": "#3987e5", "ok": "#2fa84f", "maybe": "#d79a1a", "bad": "#e66767", "on": "#0d1117"},
}
ARROWS = ("line", "accent", "ok", "maybe", "bad")


def esc(t):
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def head(w, h, c, title, desc):
    marks = "".join(f'<marker id="{k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                    f'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{c[k]}"/></marker>' for k in ARROWS)
    return [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'font-family="{FONT}" role="img" aria-labelledby="t d">', f'<title id="t">{esc(title)}</title>',
            f'<desc id="d">{esc(desc)}</desc>', f"<defs>{marks}</defs>"]


def text(x, y, t, c, size=12, color="muted", anchor="middle", weight=400):
    return (f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" text-anchor="{anchor}" '
            f'fill="{c[color]}">{esc(t)}</text>')


def box(x, y, w, h, c, title, subs=(), edge="edge"):
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{c["box"]}" stroke="{c[edge]}" '
           f'stroke-width="1.5"/>']
    n = 1 + len(subs)
    top = y + h / 2 - (n - 1) * 9 + 5
    out.append(text(x + w / 2, top, title, c, 14, "text", weight=600))
    out += [text(x + w / 2, top + 18 * (i + 1), s, c) for i, s in enumerate(subs)]
    return out


def arrow(x1, y1, x2, y2, c, kind="line", dash=False):
    d = ' stroke-dasharray="5 4"' if dash else ""
    return [f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{c[kind]}" stroke-width="1.8"{d} '
            f'marker-end="url(#{kind})"/>']


def pill(cx, y, t, kind, c, w=88):
    return [f'<rect x="{cx - w / 2}" y="{y}" width="{w}" height="26" rx="13" fill="{c[kind]}"/>',
            text(cx, y + 18, t, c, 13, "on", weight=600)]


def flow(c):
    """How a claim travels: the agent acts through a signer it can't control; the receiver checks offline."""
    w, h, bw, bh, by = 960, 178, 160, 76, 44
    gap = (w - 4 * bw) / 3
    xs = [i * (bw + gap) for i in range(4)]
    out = head(w, h, c, "How a PCM claim travels",
               "Agent A acts through an attesting signer that records and signs every event; the signed message "
               "carries records and inclusion proofs; agent B checks them offline against a pinned key.")
    nodes = [("Agent A", ["runs tests, fetches, asks"], "edge"),
             ("Attesting signer", ["records and signs", "every event"], "accent"),
             ("PCM message", ["claims + records", "+ inclusion proofs"], "edge"),
             ("Agent B", ["checks it offline", "against a pinned key"], "accent")]
    for x, (t, subs, edge) in zip(xs, nodes):
        out += box(x + 1, by, bw - 2, bh, c, t, subs, edge)
    for i, lab in enumerate(["every tool call", "signs the message", "A2A · MCP · HTTP"]):
        x1, x2 = xs[i] + bw + 6, xs[i + 1] - 8
        out += arrow(x1, by + bh / 2, x2, by + bh / 2, c)
        out.append(text((x1 + x2) / 2, by + bh / 2 - 10, lab, c, 12))
    out.append(text(xs[1] + bw / 2, by - 14, "the agent never holds its key", c, 12, "accent"))
    out.append(text(xs[3] + bw / 2, by - 14, "no call to anyone", c, 12, "accent"))
    py, right = by + bh + 18, w - 2
    out.append(text(right - 254, py + 18, "each claim comes out", c, 12, anchor="end"))
    for cx, t, kind, pw in ((right - 206, "proven", "ok", 80), (right - 118, "unproven", "maybe", 80),
                            (right - 35, "failed", "bad", 70)):
        out += pill(cx, py, t, kind, c, pw)
    out.append("</svg>\n")
    return "\n".join(out)


def judge(c):
    """How a verifier judges one claim (SPEC 6.1)."""
    w, h, bw, bh, by, pw = 960, 214, 140, 64, 20, 84
    gap = (w - 5 * bw - pw) / 5
    xs = [i * (bw + gap) for i in range(5)]
    out = head(w, h, c, "How a verifier judges one claim",
               "A claim with no evidence is unproven; evidence that fails to verify is failed; a record the agent "
               "wrote itself (T1) is unproven; records that say what the claim says are proven, records that "
               "contradict it are failed, and records that say less or can't be matched are unproven.")
    nodes = [("Claim", [], "accent"), ("Evidence?", [], "edge"), ("Proofs verify?", ["under the pinned key"], "edge"),
             ("Who wrote it?", ["signer or T2 gateway"], "edge"), ("Records say it?", [], "edge")]
    for x, (t, subs, edge) in zip(xs, nodes):
        out += box(x + 1, by, bw - 2, bh, c, t, subs, edge)
    for i in range(1, 6):
        x1 = xs[i - 1] + bw + 4
        x2 = (xs[i] if i < 5 else w - pw) - 6
        out += arrow(x1, by + bh / 2, x2, by + bh / 2, c, "ok" if i == 5 else "line")
        if i > 1:
            out.append(text((x1 + x2) / 2, by + bh / 2 - 8, "yes", c, 12))
    out += pill(w - pw / 2 - 1, by + bh / 2 - 13, "proven", "ok", c, pw)
    ey, ty = by + bh + 66, by + bh + 32
    exits = [(1, "none", "unproven", "maybe"), (2, "no", "failed", "bad"),
             (3, "the agent itself (T1)", "unproven", "maybe"), (4, "no", "failed", "bad")]
    for i, why, res, kind in exits:
        cx = xs[i] + bw / 2
        out += arrow(cx, by + bh + 4, cx, ey - 6, c, kind)
        out.append(text(cx + 8, ty, why, c, 12, anchor="start"))
        out += pill(cx, ey, res, kind, c)
    out.append(text(xs[4] + bw / 2, ey + 48, "says less, or can't tell: unproven", c, 12))
    out.append("</svg>\n")
    return "\n".join(out)


def grants(c):
    """A chain of grants only narrows."""
    w, h = 960, 196
    out = head(w, h, c, "A PCM grant chain only narrows",
               "Alice approves a pcm.grant call, which issues a root grant (refund.request, amount at most 20000, "
               "order 81, one hour). A child grant may narrow it to amount at most 5000; a child that widens it to "
               "50000 is rejected.")
    out += box(0, 61, 180, 70, c, "alice approves", ["a pcm.grant call"], "accent")
    out += box(290, 49, 290, 94, c, "Root grant", ["refund.request · amount ≤ 20000", "order 81 · for 1 hour"])
    out += arrow(186, 96, 282, 96, c)
    out.append(text(234, 86, "issues", c, 12))
    out += box(700, 12, 258, 66, c, "Child grant", ["amount ≤ 5000"], "ok")
    out += box(700, 116, 258, 66, c, "Child grant", ["amount ≤ 50000"], "bad")
    out += arrow(586, 80, 692, 48, c, "ok")
    out.append(text(640, 48, "narrows: signed", c, 12, "ok"))
    out += arrow(586, 114, 692, 146, c, "bad", dash=True)
    out.append(text(640, 160, "widens: rejected", c, 12, "bad"))
    out.append("</svg>\n")
    return "\n".join(out)


if __name__ == "__main__":
    here = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "img")
    for name, fn in (("flow", flow), ("judge", judge), ("grants", grants)):
        for t, c in THEMES.items():
            with open(os.path.join(here, f"{name}-{t}.svg"), "w", encoding="utf-8") as f:
                f.write(fn(c))
