"""python -m pcm_verify MESSAGE --trust TRUST --schema SCHEMA [--schema ...] [--tools TOOLS] [--me ID] [--strict]
[--json]. Exit 0 accept, 3 accept-unproven, 1 reject, 2 a usage error or an input it can't read."""
import argparse
import json
import sys

from pcm_verify import verify

EXIT = {"accept": 0, "accept-unproven": 3, "reject": 1}


def _refuse(s):
    raise ValueError(f"{s} is not JSON")


def _dup(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("a key repeats")
    return dict(pairs)


def load(path):
    """Strict JSON: no NaN or Infinity, no repeated keys (each JSON reader would pick a different one)."""
    with open(path, encoding="utf-8") as f:
        return json.load(f, parse_constant=_refuse, object_pairs_hook=_dup)


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m pcm_verify", description="Verify a PCM 0.1 message offline.")
    p.add_argument("message", help="the message (application/vnd.pcm+json)")
    p.add_argument("--trust", required=True, help='{"logs": [vkey], "witnesses": [{"name", "vkey"}], '
                                                  '"witnesses_required": n}')
    p.add_argument("--schema", required=True, action="append",
                   help="a schema document, or a JSON list of them; repeat for more")
    p.add_argument("--tools", help="the tool placement table {tool: class}; without it no tool is placed, so a claim "
                                   "through a shell or http call is at best unproven")
    p.add_argument("--me", help="this receiver's identity: a message to another agent is rejected")
    p.add_argument("--strict", action="store_true", help="every claim type the schema lists must be proven")
    p.add_argument("--json", action="store_true", help="print the whole result as JSON")
    a = p.parse_args(argv)
    try:
        schemas = []
        for path in a.schema:
            doc = load(path)
            schemas += doc if isinstance(doc, list) else [doc]
        trust, tools = load(a.trust), load(a.tools) if a.tools else {}
        if not isinstance(trust, dict) or not isinstance(tools, dict):
            raise ValueError("the trust file and the tool table are JSON objects")
        out = verify(load(a.message), trust, schemas, tools, me=a.me, strict=a.strict)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as e:
        print(f"pcm_verify: can't check: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(out, indent=2))
    else:
        print(out["verdict"])
        for r in out["reasons"]:
            print(f"  {r}")
    return EXIT[out["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
