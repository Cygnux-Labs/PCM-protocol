"""Run both verifiers on one saved finding and print what each says.

    PYTHONPATH=<tracekit checkout> python bench/lies/findings/repro.py bench/lies/findings/<id>.json

A finding file holds a dataset record (`record`, or the file itself is one); it is checked as `python -m bench.lies
run` checks it: the same wire loaders, replay state and clock."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from bench.lies.run import Standalone, Tracekit, verify_one  # noqa: E402


def main(path):
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    rec = doc.get("record", doc)
    print(f"{rec['id']}: class {rec['class']}, operator {rec['operator']}, label {rec['label']}, world {rec['world']}")
    if rec.get("note"):
        print(f"  note: {rec['note']}")
    for verifier in (Tracekit(), Standalone()):
        row = verify_one(verifier, rec)
        print(f"  {verifier.name:<10} {row['verdict']:<16} {row['reason_class']}")
        for r in row["reasons"] or ([row["error"]] if row["error"] else []):
            print(f"      {json.dumps(r)[1:-1]}")
        for c in row["claims"] or []:
            print(f"      {c['type']}: {c['result']} ({json.dumps(c['detail'])[1:-1]})"
                  + (f" approved {json.dumps(c['approved'])}" if "approved" in c else ""))


if __name__ == "__main__":
    for p in sys.argv[1:]:
        main(p)
