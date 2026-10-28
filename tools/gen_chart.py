"""Draw docs/img/lies-accepted-{light,dark}.svg, the README's PCM-Lies chart (numbers from bench/lies/RESULTS.md)."""
import os

ROWS = [  # label, accepted, lies, group
    ("Plain A2A (no proof)", 712, 712, "base"),
    ("Sender's signature only", 643, 712, "base"),
    ("PCM 0.1, before the fixes", 23, 687, "pcm"),
    ("PCM 0.1", 10, 712, "pcm"),
]
THEMES = {  # validated with dataviz validate_palette.js (light on #fcfcfb, dark on #1a1a19): all checks pass
    "light": {"text": "#0b0b0b", "muted": "#52514e", "grid": "#d9d8d2", "base": "#eb6834", "pcm": "#2a78d6"},
    "dark": {"text": "#f2f1ec", "muted": "#c3c2b7", "grid": "#3a3a37", "base": "#d95926", "pcm": "#3987e5"},
}
W, LABEL_W, BAR_W, ROW_H, BAR_H, TOP = 760, 220, 360, 40, 20, 92
FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"


def bar(x, y, w, h, r, fill):
    """A bar anchored at x with only its data end (right) rounded."""
    r = min(r, w / 2, h / 2)
    return (f'<path d="M{x},{y} h{w - r:.2f} a{r},{r} 0 0 1 {r},{r} v{h - 2 * r} a{r},{r} 0 0 1 {-r},{r} '
            f'h{-(w - r):.2f} z" fill="{fill}"/>')


def svg(t):
    c = THEMES[t]
    h = TOP + ROW_H * len(ROWS) + 46
    x0 = LABEL_W
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{h}" viewBox="0 0 {W} {h}" '
           f'font-family="{FONT}" role="img" aria-labelledby="t d">',
           '<title id="t">Lies a receiver accepts</title>',
           '<desc id="d">PCM-Lies benchmark. Plain A2A accepts 712 of 712 lies, a sender-signature check 643 of 712, '
           'PCM 0.1 before the fixes 23 of 687, and PCM 0.1 10 of 712, all stale evidence.</desc>',
           f'<text x="0" y="26" font-size="18" font-weight="600" fill="{c["text"]}">Lies a receiver accepts</text>',
           f'<text x="0" y="48" font-size="13" fill="{c["muted"]}">PCM-Lies benchmark: false claims accepted as true, '
           f'of 712 lies (687 before the fixes). Lower is better.</text>']
    for k in range(5):  # recessive grid at 0, 25, 50, 75, 100 %
        gx = x0 + BAR_W * k / 4
        out.append(f'<line x1="{gx}" y1="{TOP - 14}" x2="{gx}" y2="{TOP + ROW_H * len(ROWS) - 8}" '
                   f'stroke="{c["grid"]}" stroke-width="1"/>')
        out.append(f'<text x="{gx}" y="{TOP + ROW_H * len(ROWS) + 10}" font-size="11" text-anchor="middle" '
                   f'fill="{c["muted"]}" style="font-variant-numeric: tabular-nums">{25 * k}%</text>')
    for i, (label, acc, lies, group) in enumerate(ROWS):
        y = TOP + i * ROW_H
        share = acc / lies
        w = max(4, BAR_W * share)
        out.append(f'<text x="{x0 - 12}" y="{y + BAR_H / 2 + 5}" font-size="13" text-anchor="end" '
                   f'fill="{c["text"]}">{label}</text>')
        out.append(bar(x0, y, w, BAR_H, 4, c[group]))
        pct = f"{100 * share:.1f}".rstrip("0").rstrip(".")
        note = " · all stale evidence, a stated limit" if (group, acc) == ("pcm", 10) else ""
        out.append(f'<text x="{x0 + w + 8}" y="{y + BAR_H / 2 + 5}" font-size="12" fill="{c["text"]}" '
                   f'style="font-variant-numeric: tabular-nums"><tspan font-weight="600">{pct}%</tspan>'
                   f'<tspan fill="{c["muted"]}">  {acc} / {lies}{note}</tspan></text>')
    ly = TOP + ROW_H * len(ROWS) + 34  # legend: identity is never color alone (the labels name each row too)
    for j, (name, key) in enumerate([("baseline receivers", "base"), ("PCM", "pcm")]):
        lx = x0 + j * 170
        out.append(f'<rect x="{lx}" y="{ly - 10}" width="12" height="12" rx="3" fill="{c[key]}"/>')
        out.append(f'<text x="{lx + 18}" y="{ly}" font-size="12" fill="{c["muted"]}">{name}</text>')
    out.append("</svg>\n")
    return "\n".join(out)


if __name__ == "__main__":
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for t in THEMES:
        with open(os.path.join(here, "docs", "img", f"lies-accepted-{t}.svg"), "w", encoding="utf-8") as f:
            f.write(svg(t))
