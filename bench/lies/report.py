"""Tables and pass/fail of the PCM-Lies run: results/results.json and the auto section of RESULTS.md.

    python -m bench.lies report [--data PATH]

It reads the dataset and results/<verifier>.jsonl (python -m bench.lies run). Text in RESULTS.md outside the
`<!-- auto:begin -->` / `<!-- auto:end -->` markers is left as it is. Each failing message (a false accept, an honest
claim not proven, a T1 claim proven, a verifier disagreement, a verifier that raised) is saved with both verifiers'
outputs under findings/<id>.json; findings/repro.py runs both verifiers on one."""
import argparse
import collections
import json
import math

from bench.lies.run import OUT, RESULTS, records

MD = OUT / "RESULTS.md"
FINDINGS = OUT / "findings"
BEGIN, END = "<!-- auto:begin -->", "<!-- auto:end -->"
VERDICTS = ("accept", "accept-unproven", "reject")
LABELS = ("TRUE", "FALSE", "UNKNOWABLE")
PCM = ("tracekit", "standalone")
ALL = PCM + ("a2a", "sigonly")


def class_key(c):
    return (0, c) if not c.startswith("L") else (1, int(c[1:]))


def wilson(k, n, z=1.96):
    if n == 0:
        return None, None, None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def pct(xs, q):
    xs = sorted(x for x in xs if x is not None)
    return xs[max(0, math.ceil(q * len(xs)) - 1)] if xs else None


def is_lie(r):
    return r["label"] == "FALSE" or r["label"] == "UNKNOWABLE" and not r["world"]


def load_results():
    out = {}
    for name in ("tracekit", "standalone", "baselines"):
        path = RESULTS / f"{name}.jsonl"
        if not path.exists():
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                row = json.loads(line)
                out.setdefault(row["verifier"], {})[row["id"]] = row
    return out


def message_of(r):
    if r["message"] is not None:
        return r["message"]
    try:
        return json.loads(r["wire"])
    except ValueError:
        return None


def compact(x):
    return len(json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def plain(m):
    """The same message as plain A2A would carry it: no signature, no grants, no evidence."""
    p = {k: v for k, v in m.items() if k not in ("sig", "grants")}
    if "claims" in p:
        p["claims"] = [{k: v for k, v in c.items() if k != "evidence"} for c in p["claims"]]
    return p


def scope_ok(row, msg):
    """SPEC 6.6, the receiver's part: a proven approved_by approved a refund of exactly the args the message asks for.
    `approved` with args null (the decision not opened) can't say so."""
    for c in row.get("claims") or []:
        if c["type"] == "approved_by" and c["result"] == "proven":
            a = c.get("approved") or {}
            if a.get("args") is None or a.get("tool") != "refund" or msg is None \
                    or a.get("args") != msg["intent"]["args"]:
                return False
    return True


def build(data=None):
    ds = records(data)
    res = load_results()
    by_id = {r["id"]: r for r in ds}
    verifiers = [v for v in ALL if v in res] + [v for v in res if v not in ALL]   # then the real protocols
    out = {"messages": len(ds), "verifiers": verifiers}
    out["size"] = {f"{c}.{t}.{lab}": n for (c, t, lab), n in sorted(collections.Counter(
        (r["class"], r["claim_type"], r["label"]) for r in ds).items(), key=lambda x: (class_key(x[0][0]), x[0][1:]))}
    out["threat_model"] = dict(collections.Counter(r["threat_model"] for r in ds))
    classes = sorted({r["class"] for r in ds}, key=class_key)
    out["classes"] = classes

    def verdict(v, i):
        row = res.get(v, {}).get(i)
        return row["verdict"] if row else "missing"

    # confusion matrices
    conf = {}
    for v in verifiers:
        conf[v] = {}
        for c in classes:
            m = collections.Counter((r["label"], verdict(v, r["id"])) for r in ds if r["class"] == c)
            conf[v][c] = {f"{lab}>{vd}": m[(lab, vd)] for lab in LABELS for vd in VERDICTS + ("missing",)
                          if m[(lab, vd)]}
    out["confusion"] = conf
    lies = [r for r in ds if is_lie(r)]
    fa = {}
    for v in verifiers:
        acc = [r for r in lies if verdict(v, r["id"]) == "accept"]
        p, lo, hi = wilson(len(acc), len(lies))
        split = lambda key: {str(k): {"lies": n, "false_accepts": sum(1 for r in acc if r[key] == k)}   # noqa: E731
                             for k, n in collections.Counter(r[key] for r in lies).items()}
        fa[v] = {"lies": len(lies), "false_accepts": len(acc), "rate": p, "ci95": [lo, hi],
                 "by_scope": split("lie_scope"), "by_threat_model": split("threat_model"),
                 "ids": [r["id"] for r in acc]}
    out["false_accepts"] = fa
    det = {}
    for v in verifiers:
        det[v] = {}
        for c in classes:
            f = [r for r in ds if r["class"] == c and r["label"] == "FALSE"]
            if f:
                det[v][c] = {"false": len(f), "rejected": sum(verdict(v, r["id"]) == "reject" for r in f),
                             "not_accepted": sum(verdict(v, r["id"]) in ("reject", "accept-unproven") for r in f)}
    out["detection"] = det
    lie_classes = [c for c in classes if any(r["class"] == c for r in lies)]
    out["lies_by_class"] = {v: {c: [sum(verdict(v, r["id"]) == "accept" for r in lies if r["class"] == c),
                                    sum(r["class"] == c for r in lies)] for c in lie_classes} for v in verifiers}
    honest_ids = [r["id"] for r in ds if r["class"] == "honest"]
    out["receivers"] = {v: {   # every receiver that is not PCM: the baselines, then the real protocols
        "lies": len(lies), "accepted": fa[v]["false_accepts"], "rate": fa[v]["rate"], "ci95": fa[v]["ci95"],
        "honest": len(honest_ids), "honest_accepted": sum(verdict(v, i) == "accept" for i in honest_ids),
        "rejects_by_class": {c: dict(collections.Counter(res[v][r["id"]].get("reason") for r in lies
                                                         if r["class"] == c and verdict(v, r["id"]) != "accept"))
                             for c in lie_classes}} for v in verifiers if v not in PCM}
    # H1-H5
    H = {}
    H["H1"] = {v: {"false_accepts": fa[v]["false_accepts"], "pass": fa[v]["false_accepts"] == 0,
                   "list": [{"id": i, "operator": by_id[i]["operator"], "lie_scope": by_id[i]["lie_scope"],
                             "threat_model": by_id[i]["threat_model"], "note": by_id[i]["note"],
                             "reasons": res[v][i].get("reasons"), "claims": res[v][i].get("claims")}
                            for i in fa[v]["ids"]]} for v in PCM if v in res}
    honest = [r for r in ds if r["class"] == "honest" and r["label"] == "TRUE"]
    H["H2"] = {}
    for v in PCM:
        if v in res:
            def proven(r):
                """H2 as pre-registered: the honest claims are proven (and nothing rejects the message); a message
                with no claim, a grant only, must be accepted."""
                row = res[v][r["id"]]
                claims = row.get("claims") or []
                return row["verdict"] != "reject" and (all(c["result"] == "proven" for c in claims) if claims
                                                       else row["verdict"] == "accept")
            miss = [r for r in honest if not proven(r)]
            n = len(honest)
            H["H2"][v] = {"honest": n, "proven": n - len(miss), "rate": (n - len(miss)) / n if n else None,
                          "verdict_accept": sum(verdict(v, r["id"]) == "accept" for r in honest),
                          "pass": bool(n) and (n - len(miss)) / n >= 0.99,
                          "misses": [{"id": r["id"], "operator": r["operator"], "verdict": verdict(v, r["id"]),
                                      "reasons": res[v][r["id"]].get("reasons"), "note": r["note"]} for r in miss]}
    unk = [r for r in ds if r["label"] == "UNKNOWABLE"]
    H["H3"] = {}
    for v in PCM:
        if v in res:
            bad = []
            for r in unk:
                row = res[v].get(r["id"]) or {}
                got = [c["result"] for c in row.get("claims") or []]
                if not got or any(x != "unproven" for x in got):
                    bad.append({"id": r["id"], "operator": r["operator"], "world": r["world"],
                                "verdict": row.get("verdict"), "claims": got, "reasons": row.get("reasons")})
            H["H3"][v] = {"unknowable": len(unk), "unproven": len(unk) - len(bad),
                          "rate": (len(unk) - len(bad)) / len(unk) if unk else None, "pass": not bad, "violations": bad}
    if all(v in res for v in PCM):
        dis = []
        for r in ds:
            a, b = res["tracekit"].get(r["id"]), res["standalone"].get(r["id"])
            if a is None or b is None or a["conformance"] != b["conformance"] or a["reason_class"] != b["reason_class"]:
                dis.append({"id": r["id"], "class": r["class"], "operator": r["operator"], "label": r["label"],
                            "tracekit": a and {k: a[k] for k in ("verdict", "reason_class", "reasons", "error")},
                            "standalone": b and {k: b[k] for k in ("verdict", "reason_class", "reasons", "error")},
                            "conformance_equal": bool(a and b and a["conformance"] == b["conformance"])})
        H["H4"] = {"messages": len(ds), "agree": len(ds) - len(dis), "pass": not dis, "disagreements": dis}
    H["H5"] = {v: {"lies": len(lies), "accepted": fa[v]["false_accepts"], "rate": fa[v]["rate"]}
               for v in ("a2a", "sigonly") if v in res}
    out["H"] = H
    # the receiver's SPEC 6.6 check on approved_by
    spec = {}
    for v in PCM:
        if v not in res:
            continue
        spec[v] = {}
        for title, sel in (("L3 message-scope lies", lambda r: r["class"] == "L3" and r["lie_scope"] == "message"),
                           ("honest approved_by", lambda r: r["class"] == "honest" and r["claim_type"] == "A"),
                           ("all approved_by lies", lambda r: r["claim_type"] == "A" and is_lie(r))):
            rows = [r for r in ds if sel(r)]
            before = collections.Counter(verdict(v, r["id"]) for r in rows)
            after = collections.Counter(
                ("accept-unproven" if verdict(v, r["id"]) == "accept" and not scope_ok(res[v][r["id"]], message_of(r))
                 else verdict(v, r["id"])) for r in rows)
            spec[v][title] = {"messages": len(rows), "verdict": dict(before), "with_scope_check": dict(after)}
    out["spec_receiver"] = spec
    # cost
    size = {}
    for t in sorted({r["claim_type"] for r in ds}):
        rows = [r for r in ds if r["claim_type"] == t and r["message"] is not None and r["class"] == "honest"]
        if not rows:
            continue
        full = [compact(r["message"]) for r in rows]
        pl = [compact(plain(r["message"])) for r in rows]
        over = [a - b for a, b in zip(full, pl)]
        size[t] = {"messages": len(rows), "pcm_p50": pct(full, .5), "pcm_p99": pct(full, .99),
                   "plain_p50": pct(pl, .5), "plain_p99": pct(pl, .99), "overhead_p50": pct(over, .5),
                   "overhead_p99": pct(over, .99), "ratio_p50": pct([a / b for a, b in zip(full, pl)], .5)}
    timing = {}
    for v in PCM:
        if v in res:
            ms = [row["ms"] for row in res[v].values() if row.get("ms") is not None]
            timing[v] = {"messages": len(ms), "p50_ms": pct(ms, .5), "p99_ms": pct(ms, .99), "max_ms": max(ms or [0]),
                         "by_claim_type": {t: {"p50_ms": pct(x, .5), "p99_ms": pct(x, .99)} for t, x in (
                             (t, [res[v][r["id"]]["ms"] for r in ds if r["claim_type"] == t and r["id"] in res[v]])
                             for t in sorted({r["claim_type"] for r in ds}))}}
    out["cost"] = {"size_bytes_honest": size, "verify_ms": timing}
    out["ablations"] = {c: {v: dict(collections.Counter(verdict(v, r["id"]) for r in ds if r["class"] == c))
                            for v in verifiers} for c in ("AB-strip", "AB-t1") if c in classes}
    errors = {v: [{"id": i, "stage": row["stage"], "error": row["error"]} for i, row in res[v].items()
                  if row.get("stage") == "verify"] for v in PCM if v in res}
    out["verify_errors"] = errors
    failing = set()
    for v in PCM:
        if v in res:
            failing |= set(fa[v]["ids"]) | {m["id"] for m in H["H2"][v]["misses"]} | \
                {m["id"] for m in H["H3"][v]["violations"]} | {e["id"] for e in errors[v]}
    failing |= {d["id"] for d in H.get("H4", {}).get("disagreements", [])}
    out["failing_ids"] = sorted(failing)
    return out, ds, res


def save_findings(ids, ds, res):
    """findings/<id>.json for each failing message: its record and both verifiers' outputs. Earlier auto files go."""
    FINDINGS.mkdir(parents=True, exist_ok=True)
    for p in FINDINGS.glob("*.json"):
        try:
            if json.loads(p.read_text()).get("auto"):
                p.unlink()
        except ValueError:
            pass
    by_id = {r["id"]: r for r in ds}
    for i in ids:
        (FINDINGS / f"{i}.json").write_text(json.dumps({
            "auto": True, "id": i, "record": by_id[i],
            "outputs": {v: res[v].get(i) for v in ALL if v in res}}, indent=1, ensure_ascii=False) + "\n")


# ------------------------------------------------------------------------------------------------ markdown
def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join("" if x is None else str(x) for x in row) + " |" for row in rows]
    return "\n".join(out)


def rate(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"


def ci(lo, hi):
    return "n/a" if lo is None else f"[{100 * lo:.2f}%, {100 * hi:.2f}%]"


def short(s, n=160):
    s = json.dumps(s, ensure_ascii=True) if not isinstance(s, str) else s.encode("unicode_escape").decode()
    return (s[:n] + "…") if len(s) > n else s


def markdown(o):
    L = []
    H = o["H"]
    L.append(f"_{o['messages']} messages; verifiers: {', '.join(o['verifiers'])}._\n")
    L.append("### Pass/fail\n")
    rows = []
    for v in PCM:
        if v in H.get("H1", {}):
            h1, h2, h3 = H["H1"][v], H["H2"][v], H["H3"][v]
            f = o["false_accepts"][v]
            rows.append([v, f"{'PASS' if h1['pass'] else 'FAIL'}: {h1['false_accepts']} of {f['lies']} lies accepted "
                            f"({rate(f['rate'])}, 95% CI {ci(*f['ci95'])})",
                         f"{'PASS' if h2['pass'] else 'FAIL'}: {h2['proven']}/{h2['honest']} ({rate(h2['rate'])}; "
                         f"{h2['verdict_accept']} with verdict accept)",
                         f"{'PASS' if h3['pass'] else 'FAIL'}: {h3['unproven']}/{h3['unknowable']} ({rate(h3['rate'])})"])
    L.append(table(["verifier", "H1 no false accept", "H2 honest proven >= 99%", "H3 T1-only unproven 100%"], rows))
    if "H4" in H:
        h4 = H["H4"]
        L.append(f"\nH4 verifier agreement (conformance fields and reason class): "
                 f"**{'PASS' if h4['pass'] else 'FAIL'}**, {h4['agree']}/{h4['messages']} agree.")
    if H.get("H5"):
        L.append("\nH5 baselines (lies accepted): " + "; ".join(
            f"{v} {x['accepted']}/{x['lies']} ({rate(x['rate'])})" for v, x in H["H5"].items()) + ".")
    L.append("\n### False-accept rate by lie scope and threat model\n")
    rows = []
    for v in o["verifiers"]:
        f = o["false_accepts"][v]
        rows.append([v, f"{f['false_accepts']}/{f['lies']}", rate(f["rate"]), ci(*f["ci95"])]
                    + ["; ".join(f"{k} {x['false_accepts']}/{x['lies']}" for k, x in sorted(f["by_scope"].items()))]
                    + ["; ".join(f"{k} {x['false_accepts']}/{x['lies']}" for k, x in sorted(
                        f["by_threat_model"].items()))])
    L.append(table(["verifier", "false accepts", "rate", "Wilson 95% CI", "by lie scope", "by threat model"], rows))
    L.append("\n### Dataset\n")
    cnt = collections.defaultdict(collections.Counter)
    for k, n in o["size"].items():
        c, t, lab = k.split(".")
        cnt[c][(t, lab)] += n
    types = sorted({k.split(".")[1] for k in o["size"]})
    rows = []
    for c in o["classes"]:
        cells = []
        for t in types:
            parts = [f"{cnt[c][(t, lab)]}{lab[0]}" for lab in LABELS if cnt[c][(t, lab)]]
            cells.append(" ".join(parts))
        rows.append([c] + cells + [sum(cnt[c].values())])
    L.append(table(["class"] + types + ["total"], rows))
    L.append(f"\nT = tests_passed, H = reached_host, F = file_written, A = approved_by, G = grants, X = several "
             f"claims; counts as nT (TRUE), nF (FALSE), nU (UNKNOWABLE). Threat model: {o['threat_model']}.")
    for v in [v for v in o["verifiers"] if v in ALL]:
        L.append(f"\n### Confusion matrix: {v}\n")
        rows = []
        for c in o["classes"]:
            m = o["confusion"][v][c]
            row = [c]
            for lab in LABELS:
                row += [m.get(f"{lab}>{vd}", 0) or "" for vd in VERDICTS]
            rows.append(row)
        L.append(table(["class"] + [f"{lab[0]}:{vd}" for lab in LABELS for vd in VERDICTS], rows))
    L.append("\n### Detection per class (FALSE messages)\n")
    rows, four = [], [v for v in o["verifiers"] if v in ALL]
    for c in o["classes"]:
        row = [c]
        for v in four:
            d = o["detection"].get(v, {}).get(c)
            row.append("" if not d else f"{d['rejected']}/{d['false']} rejected, {d['not_accepted']} not accepted")
        if any(row[1:]):
            rows.append(row)
    L.append(table(["class"] + four, rows))
    rec = o["receivers"]
    if any(v not in ALL for v in rec):
        L.append("\n### Real protocols as receivers (added after pre-registration)\n")
        rows = [[v, f"{x['accepted']}/{x['lies']}", rate(x["rate"]), ci(*x["ci95"]),
                 f"{x['honest_accepted']}/{x['honest']}"] for v, x in rec.items()]
        L.append(table(["receiver", "lies accepted", "rate", "Wilson 95% CI", "honest accepted"], rows))
        by, cols = o["lies_by_class"], list(rec) + [v for v in PCM if v in o["lies_by_class"]][:1]
        rows = [[c] + [f"{by[v][c][0]}/{by[v][c][1]}" for v in cols] for c in by[cols[0]]]
        L.append("\nLies accepted per class:\n")
        L.append(table(["class"] + cols, rows))
    L.append("\n### approved_by with the receiver's SPEC 6.6 scope check\n")
    rows = []
    for v, groups in o["spec_receiver"].items():
        for title, g in groups.items():
            rows.append([v, title, g["messages"], json.dumps(g["verdict"]), json.dumps(g["with_scope_check"])])
    L.append(table(["verifier", "messages", "n", "verdict", "verdict after the scope check"], rows))
    L.append("\n### Cost\n")
    rows = [[t, s["messages"], s["plain_p50"], s["pcm_p50"], s["pcm_p99"], s["overhead_p50"], s["overhead_p99"],
             f"{s['ratio_p50']:.1f}x"] for t, s in o["cost"]["size_bytes_honest"].items()]
    L.append(table(["claim type (honest)", "n", "plain A2A p50 B", "PCM p50 B", "PCM p99 B", "overhead p50 B",
                    "overhead p99 B", "PCM/plain p50"], rows))
    rows = [[v, t["messages"], f"{t['p50_ms']:.3f}", f"{t['p99_ms']:.3f}", f"{t['max_ms']:.3f}"]
            for v, t in o["cost"]["verify_ms"].items()]
    L.append("\n" + table(["verifier", "messages timed", "p50 ms", "p99 ms", "max ms"], rows))
    if o["ablations"]:
        L.append("\n### Ablations\n")
        rows = [[c, v, json.dumps(d)] for c, x in o["ablations"].items() for v, d in x.items()]
        L.append(table(["ablation", "verifier", "verdicts"], rows))
    L.append("\n### Every failure\n")
    any_fail = False
    for v in PCM:
        if v not in H.get("H1", {}):
            continue
        for x in H["H1"][v]["list"]:
            any_fail = True
            L.append(f"- **false accept** ({v}) `{x['id']}` {x['operator']} [{x['lie_scope']}, {x['threat_model']}]: "
                     f"{short(x['note'])}")
        for x in H["H2"][v]["misses"]:
            any_fail = True
            L.append(f"- **honest not proven** ({v}) `{x['id']}` {x['operator']} -> {x['verdict']}: "
                     f"{short('; '.join(x['reasons'] or []))} {short(x['note'], 80)}")
        for x in H["H3"][v]["violations"]:
            any_fail = True
            L.append(f"- **T1-only not unproven** ({v}) `{x['id']}` {x['operator']} -> {x['claims']}")
        for x in o["verify_errors"][v]:
            any_fail = True
            L.append(f"- **verifier raised** ({v}) `{x['id']}`: {short(x['error'])}")
    for x in H.get("H4", {}).get("disagreements", []):
        any_fail = True
        t, s = x["tracekit"] or {}, x["standalone"] or {}
        L.append(f"- **disagreement** `{x['id']}` {x['operator']}: tracekit {t.get('reason_class')} / standalone "
                 f"{s.get('reason_class')}" + ("" if x["conformance_equal"] else " (conformance fields differ)"))
    if not any_fail:
        L.append("None.")
    return "\n".join(L) + "\n"


def write_md(text):
    old = MD.read_text(encoding="utf-8") if MD.exists() else f"# PCM-Lies results\n\n{BEGIN}\n{END}\n"
    if BEGIN not in old or END not in old:
        old = old.rstrip("\n") + f"\n\n{BEGIN}\n{END}\n"
    head, rest = old.split(BEGIN, 1)
    tail = rest.split(END, 1)[1]
    MD.write_text(f"{head}{BEGIN}\n{text}{END}{tail}", encoding="utf-8")


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m bench.lies report")
    p.add_argument("--data", help="the dataset (default bench/lies/data/dataset.jsonl, or $PCM_LIES_DATA)")
    a = p.parse_args(argv)
    o, ds, res = build(a.data)
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "results.json").write_text(json.dumps(o, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    save_findings(o["failing_ids"], ds, res)
    write_md(markdown(o))
    print(f"results -> {RESULTS / 'results.json'}; {len(o['failing_ids'])} failing messages -> {FINDINGS}; {MD}")
    for k in ("H1", "H2", "H3"):
        for v, x in o["H"].get(k, {}).items():
            print(f"  {k} {v}: {'PASS' if x['pass'] else 'FAIL'}")
    if "H4" in o["H"]:
        print(f"  H4: {'PASS' if o['H']['H4']['pass'] else 'FAIL'} ({o['H']['H4']['agree']}/{o['H']['H4']['messages']})")


if __name__ == "__main__":
    main()
