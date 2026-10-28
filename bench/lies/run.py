"""Run every message of the PCM-Lies dataset through a verifier and record its verdict.

    PYTHONPATH=<tracekit checkout> python -m bench.lies run --verifier tracekit|standalone|baselines|all [--data PATH]

Verifiers: `tracekit` (tracekit.pcm.verify, the reference implementation), `standalone` (pcm_verify in
verifier/python, which imports no Tracekit code), `baselines` (two receivers with nothing to check: `a2a` accepts any
message it can parse, `sigonly` accepts any message whose signature verifies). `all` runs each in its own process, so
the standalone verifier never shares a process with Tracekit. A message given as `wire` text is parsed by the
verifier's own command-line loader (SPEC 3.3); a message the loader refuses is rejected as `unreadable`."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "verifier" / "python"))
DATA = HERE / "data" / "dataset.jsonl"
OUT = Path(os.environ.get("PCM_LIES_OUT") or HERE)   # results, findings and RESULTS.md go here
RESULTS = OUT / "results"
VERIFIERS = ("tracekit", "standalone", "baselines")


def records(path=None):
    with open(path or os.environ.get("PCM_LIES_DATA") or DATA, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def conformance(out):
    """The fields a verifier must match (SPEC 13.2)."""
    part = lambda name, key: None if out.get(name) is None else out[name].get(key)   # noqa: E731
    return {"verdict": out["verdict"], "signature": part("signature", "ok"), "replay": part("replay", "ok"),
            "schema": part("schema", "ok"), "grants": part("grants", "result"),
            "claims": None if out.get("claims") is None else [[c["result"], c.get("approved")] for c in out["claims"]],
            "skipped": out.get("skipped")}


def reason_class(out):
    if out.get("signature") is None:
        return f"{out['verdict']}|envelope"
    if not out["signature"]["ok"]:
        return f"{out['verdict']}|signature"
    parts = []
    r = out.get("replay") or {}
    if r.get("ok") is False:
        parts.append("recipient" if str(r.get("detail", "")).startswith("addressed to") else "replay")
    if out.get("schema") and not out["schema"]["ok"]:
        parts.append("schema")
    if out.get("grants") and out["grants"].get("result") == "failed":
        parts.append("grant")
    parts += [f"{c['type']}:{c['result']}" for c in out.get("claims") or []]
    return f"{out['verdict']}|{','.join(sorted(parts))}"


def _wire_file(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    with f:
        f.write(text)
    return f.name


class Tracekit:
    name = "tracekit"

    def __init__(self):
        from tracekit import pcm
        from tracekit.pcm import cli
        self.pcm, self.cli = pcm, cli

    def load(self, path):
        return self.cli._load(path)

    def check(self, rec, msg):
        pcm, o = self.pcm, rec["options"]
        now, rp = pcm._epoch(o["now"]), o["replay"]
        replay = rp and pcm.Replay(rp["window_s"], rp["per_sender"], now=pcm._epoch(rp["started"]))
        kw = dict(replay=replay, me=o["me"], strict=o["strict"], now=now)
        for m in (rp or {}).get("seen", []):
            pcm.verify(m, rec["trust"], rec["schemas"], **kw)
        t = time.perf_counter()
        out = pcm.verify(msg, rec["trust"], rec["schemas"], **kw)
        return out, (time.perf_counter() - t) * 1000


class Standalone:
    name = "standalone"

    def __init__(self):
        import pcm_verify
        import pcm_verify.__main__ as main
        self.v, self.main = pcm_verify, main

    def load(self, path):
        return self.main.load(path)

    def check(self, rec, msg):
        v, o = self.v, rec["options"]
        rp = o["replay"]
        replay = rp and v.Replay(rp["window_s"], rp["per_sender"], started=rp["started"])
        kw = dict(me=o["me"], strict=o["strict"], now=o["now"], replay=replay)
        for m in (rp or {}).get("seen", []):
            v.verify(m, rec["trust"], rec["schemas"], **kw)
        t = time.perf_counter()
        out = v.verify(msg, rec["trust"], rec["schemas"], **kw)
        return out, (time.perf_counter() - t) * 1000


def verify_one(verifier, rec):
    row = {"id": rec["id"], "verifier": verifier.name}
    msg = rec["message"]
    if rec.get("wire") is not None:
        path = _wire_file(rec["wire"])
        try:
            msg = verifier.load(path)
        except Exception as e:   # the verifier's own CLI exits 2: it can't read the message
            return {**row, "verdict": "reject", "reason_class": "reject|unreadable", "stage": "load",
                    "error": f"{type(e).__name__}: {str(e)[:300]}", "conformance": None, "claims": None,
                    "reasons": [], "ms": None}
        finally:
            os.unlink(path)
    try:
        out, ms = verifier.check(rec, msg)
    except Exception as e:   # SPEC 14.12: a verifier returns a verdict for every message; this one raised
        return {**row, "verdict": "reject", "reason_class": f"reject|error:{type(e).__name__}", "stage": "verify",
                "error": f"{type(e).__name__}: {str(e)[:300]}", "conformance": None, "claims": None, "reasons": [],
                "ms": None}
    return {**row, "verdict": out["verdict"], "reason_class": reason_class(out), "stage": None, "error": None,
            "conformance": conformance(out), "claims": out.get("claims"), "reasons": out.get("reasons", []),
            "ms": round(ms, 4)}


def baselines(rec):
    """a2a: accept whatever parses; sigonly: accept whatever carries a valid signature by a pinned key."""
    import pcm_verify
    try:
        msg = json.loads(rec["wire"]) if rec.get("wire") is not None else rec["message"]
        parsed = True
    except ValueError:
        msg, parsed = None, False
    rows = [{"id": rec["id"], "verifier": "a2a", "verdict": "accept" if parsed else "reject"}]
    try:
        ok = parsed and pcm_verify.check_sig(msg, pcm_verify.MESSAGE_TAG, rec["trust"]) is None
    except Exception:
        ok = False
    rows.append({"id": rec["id"], "verifier": "sigonly", "verdict": "accept" if ok else "reject"})
    return rows


def run(name, data=None):
    RESULTS.mkdir(parents=True, exist_ok=True)
    recs = records(data)
    out = []
    if name == "baselines":
        for rec in recs:
            out += baselines(rec)
    else:
        verifier = Tracekit() if name == "tracekit" else Standalone()
        out = [verify_one(verifier, rec) for rec in recs]
        if name == "standalone":
            assert not [m for m in sys.modules if m.split(".")[0] == "tracekit"], "the standalone run imported tracekit"
    with open(RESULTS / f"{name}.jsonl", "w", encoding="utf-8") as f:
        for row in out:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"{name}: {len(out)} results -> {RESULTS / f'{name}.jsonl'}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m bench.lies run")
    p.add_argument("--verifier", choices=VERIFIERS + ("all",), default="all")
    p.add_argument("--data", help="the dataset (default bench/lies/data/dataset.jsonl, or $PCM_LIES_DATA)")
    a = p.parse_args(argv)
    if a.verifier != "all":
        return run(a.verifier, a.data)
    for name in VERIFIERS:   # each in its own process
        cmd = [sys.executable, "-m", "bench.lies", "run", "--verifier", name] + (["--data", a.data] if a.data else [])
        subprocess.run(cmd, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
