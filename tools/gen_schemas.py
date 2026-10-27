"""Write schemas/*.schema.json (JSON Schema 2020-12) and registry/tools.json from Tracekit, the reference
implementation of PCM. The shapes are Tracekit's own (tracekit/signer/rpc_schema.py and tracekit/pcm), translated
as they are, so the two can't drift by hand. From the repo root, with Tracekit importable:

    PYTHONPATH=<tracekit checkout> python tools/gen_schemas.py
"""
import json
import os

from tracekit.pcm import SCHEMA_DOC
from tracekit.pcm.claims import placed
from tracekit.signer.rpc_schema import _CLAIM, _EVIDENCE, PCM_GRANT, PCM_MESSAGE

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = "urn:pcm:0.1:schema:"
INTS = ("Integers are written without a fraction or exponent: a verifier rejects 0.0 where JSON Schema's integer "
        "would take it.")
PATTERNS = "Every pattern matches the whole value, with ASCII classes."
FILES = {
    "message": (PCM_MESSAGE, "PCM 0.1 message", "A message one agent sends another (media type "
                "application/vnd.pcm+json). The signature covers every field but sig. " + INTS + " " + PATTERNS),
    "grant": (PCM_GRANT, "PCM 0.1 grant", "Who may ask for which intent, within which caveats, until when. "
              "A caveat's value is checked against the intent's schema document, not here. " + INTS + " " + PATTERNS),
    "claim": (_CLAIM, "PCM 0.1 claim", "Something the sender says happened in its run. Its args are checked per "
              "claim type by the verifier; a claim whose args don't fit fails, it does not break the envelope."),
    "evidence": (_EVIDENCE, "PCM 0.1 evidence", "Records of the sender's run, each with its inclusion proof under a "
                 "signed checkpoint note. A record's salt and args open a policy.decision's args commitment; a record "
                 "with only one of them fails its claim. " + PATTERNS),
    "schema-document": (SCHEMA_DOC, "PCM 0.1 schema document", "The typed fields of an intent, the claim types it "
                        "needs and whether it needs a grant. Its name on the wire is name@sha256:<hex of SHA-256 of "
                        "its JCS>. Beyond this schema a verifier also rejects an int field whose min is above its "
                        "max, and an id field whose pattern does not compile. " + PATTERNS),
}


def convert(s, top):
    """`s` with every other file's shape replaced by a $ref to that file."""
    for name, (shape, *_) in FILES.items():
        if s is shape and s is not top:
            return {"$ref": BASE + name}
    if isinstance(s, dict):   # [0-9] for \d: Tracekit matches ASCII, and not every validator's \d is ASCII
        return {k: v.replace("\\d", "[0-9]") if k == "pattern" and isinstance(v, str) else convert(v, top)
                for k, v in s.items()}
    if isinstance(s, list):
        return [convert(v, top) for v in s]
    return s


def write(path, value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def main():
    for name, (shape, title, description) in FILES.items():
        out = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": BASE + name, "title": title,
               "description": description, **convert(shape, shape)}
        if name == "schema-document":   # check_schema's repeat checks, which JSON Schema can say
            out["properties"]["claims"]["uniqueItems"] = True
            for alt in out["properties"]["fields"]["additionalProperties"]["oneOf"]:
                if alt["properties"]["type"] == {"const": "enum"}:
                    alt["properties"]["values"]["uniqueItems"] = True
        write(os.path.join(ROOT, "schemas", f"{name}.schema.json"), out)
    write(os.path.join(ROOT, "registry", "tools.json"), dict(sorted(placed().items())))


if __name__ == "__main__":
    main()
