"""python -m pcm_verify MESSAGE --trust TRUST --schema SCHEMA [--schema ...] [--me ID] [--strict] [--json]. Exit 0
accept, 3 accept-unproven, 1 reject, 2 a usage error or an input it can't read."""
import argparse
import json
import math
import sys

from pcm_verify import MAX_SAFE_INT, epoch, verify

EXIT = {"accept": 0, "accept-unproven": 3, "reject": 1}


def _refuse(s):
    raise ValueError(f"{s} is not JSON")


def _dup(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("a key repeats")
    return dict(pairs)


def _strict(value):
    """SPEC 3.3: nesting at most 128 deep, integers within +-(2^53 - 1), no lone surrogates."""
    todo = [(value, 1)]
    while todo:
        v, depth = todo.pop()
        if isinstance(v, (dict, list)) and depth > 128:
            raise ValueError("nesting deeper than 128")
        if type(v) is int and abs(v) > MAX_SAFE_INT:
            raise ValueError("an integer past 2^53 - 1")
        for s in [v] + (list(v) if isinstance(v, dict) else []):
            if isinstance(s, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in s):
                raise ValueError("a lone surrogate")
        todo += [(x, depth + 1) for x in (v.values() if isinstance(v, dict) else v if isinstance(v, list) else ())]
    return value


def _finite(s):
    """SPEC 3.3: a number that rounds to no finite IEEE 754 double (1e400) does not parse."""
    if not math.isfinite(f := float(s)):
        raise ValueError(f"{s[:64]} is past the IEEE 754 double range")
    return f


def loads(text):
    """Strict JSON: no NaN or Infinity, no repeated keys (each JSON reader would pick a different one), and SPEC 3.3."""
    return _strict(json.loads(text, parse_constant=_refuse, parse_float=_finite, object_pairs_hook=_dup))


def load(path):
    with open(path, encoding="utf-8") as f:
        return loads(f.read())


def freshness(msg, out):
    """SPEC 14.13: what the receiver checks itself after a proven tests_passed or file_written claim, how long before
    the message the oldest record of its evidence is. None without one, or when a ts is no date."""
    try:
        ages = [epoch(msg["ts"]) - min(epoch(r["event"]["ts"]) for r in c["evidence"]["records"])
                for c, r in (zip(msg["claims"], out["claims"]) if out["claims"] else ())
                if r["result"] == "proven" and r["type"] in ("tests_passed", "file_written")]
    except ValueError:   # a hostile pinned log can write a ts in month 13
        return None
    return ages and (f"evidence {max(ages):.0f} s before the message: a claim proves a call happened, not that nothing "
                     "changed since: check its age (SPEC 14.13)")


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m pcm_verify", description="Verify a PCM 0.1 message offline. Replay "
                                "is not checked: a receiver that acts on a message keeps a pcm_verify.Replay.")
    p.add_argument("message", help="the message (application/vnd.pcm+json)")
    p.add_argument("--trust", required=True, help='{"logs": [vkey], "witnesses": [{"name", "vkey"}], '
                                                  '"witnesses_required": n}')
    p.add_argument("--schema", required=True, action="append",
                   help="a schema document, or a JSON list of them; repeat for more")
    p.add_argument("--me", help="this receiver's identity: a message to another agent is rejected")
    p.add_argument("--strict", action="store_true", help="every claim type the schema lists must be proven")
    p.add_argument("--json", action="store_true", help="print the whole result as JSON")
    a = p.parse_args(argv)
    try:
        schemas = []
        for path in a.schema:
            doc = load(path)
            schemas += doc if isinstance(doc, list) else [doc]
        trust = load(a.trust)
        if not isinstance(trust, dict):
            raise ValueError("the trust file is a JSON object")
        msg = load(a.message)
        out = verify(msg, trust, schemas, me=a.me, strict=a.strict)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as e:
        print(f"pcm_verify: can't check: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(out, indent=2))
    else:
        print(out["verdict"])
        for r in out["reasons"]:   # the sender chose parts of them: escape controls, non-ASCII and lone surrogates
            print(f"  {json.dumps(r)[1:-1]}")
        for c in out["claims"] or []:   # SPEC 6.6: what the person approved, which the receiver reads
            if "approved" in c:
                print(f"  approved_by: {json.dumps(c['approved'])}")
        if note := freshness(msg, out):
            print(f"  {note}")
        if out["skipped"]:
            print(f"  not checked: {', '.join(out['skipped'])}")
    return EXIT[out["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
