"""PCM 0.1 reference verifier: checks a proof-carrying message offline, with only the receiver's trust file (pinned
log and witness keys), the schema documents it agreed on and the tool placement table.

It needs the standard library, rfc8785 and cryptography, nothing else. Tracekit is the reference implementation; the
vectors in ../../vectors pin where the two must agree."""
import base64
import collections
import datetime
import hashlib
import hmac
import json
import posixpath
import re
import shlex
import struct
import time

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = ["MEDIA_TYPE", "Replay", "check_schema", "schema_ref", "verify"]

MEDIA_TYPE = "application/vnd.pcm+json"
MESSAGE_TAG, GRANT_TAG = "pcm.message.v0", "pcm.grant.v0"
MAX_SAFE_INT = 2 ** 53 - 1
CLAIM_TYPES = ["tests_passed", "approved_by", "reached_host", "file_written"]


class NotJCS(ValueError):
    pass


def jcs(value):
    """RFC 8785 bytes of a JSON value; NotJCS for one JCS can't encode (an integer past 2^53, a lone surrogate)."""
    try:
        return rfc8785.dumps(value)
    except (ValueError, TypeError, RecursionError) as e:
        raise NotJCS(str(e)) from None


def record_hash(value):
    return "sha256:" + hashlib.sha256(jcs(value)).hexdigest()


# ---------------------------------------------------------------------------------------------------- envelope
# A JSON Schema subset. Every object is closed, every pattern matches the whole value with ASCII classes, and an
# integer is an int: 0.0 and false are not 0.
def _str(n, **kw):
    return {"type": "string", "maxLength": n, **kw}


def _obj(required, **props):
    return {"type": "object", "additionalProperties": False, "required": required, "properties": props}


ANY, BOOL, ZERO = {}, {"type": "boolean"}, {"type": "integer", "const": 0}
ID = _str(128, minLength=1, pattern=r"[A-Za-z0-9._:-]+")
IDENTITY = _str(256, pattern=r"[a-z0-9_]+:.+")
TS = _str(27, pattern=r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
DIGEST = _str(71, pattern=r"sha256:[0-9a-f]{64}")
HEX32 = _str(32, pattern=r"[0-9a-f]{32}")
SCHEMA_REF = _str(136, pattern=r"[a-z][a-z0-9_.-]{0,63}@sha256:[0-9a-f]{64}")
SIG = _obj(["key", "sig"], key=_str(300, minLength=1), sig=_str(88))
CAVEATS = {"type": "array", "maxItems": 16, "items": _obj(
    ["field", "op", "value"], field=_str(64, pattern=r"[a-z][a-z0-9_]*"),
    op={"enum": ["==", "<=", ">=", "<", ">", "in"]}, value=ANY)}
RECORD = _obj(["event", "hash", "proof"], event=ANY, hash=DIGEST,
              proof={"type": "array", "maxItems": 64, "items": _str(44)},
              salt=_str(64, pattern=r"[0-9a-f]{64}"), args=ANY)
CLAIM = _obj(["type", "args"], type={"enum": CLAIM_TYPES}, args=ANY, evidence=_obj(
    ["checkpoint", "records"], checkpoint=_str(16384, minLength=1),
    records={"type": "array", "minItems": 1, "maxItems": 16, "items": RECORD}))
GRANT = _obj(["pcm_grant", "ts", "issuer", "subject", "intent", "caveats", "expires_at", "delegable", "parent", "sig"],
             pcm_grant=ZERO, ts=TS, subject=IDENTITY, intent=SCHEMA_REF, caveats=CAVEATS, expires_at=TS,
             delegable=BOOL, parent={"oneOf": [DIGEST, {"type": "null"}]}, sig=SIG,
             issuer=_obj(["kind", "id", "run", "tenant"], kind={"enum": ["person", "agent"]}, id=_str(256),
                         person=_str(256), run=ID, tenant=ID, approval_id=ID))
MESSAGE = _obj(["pcm", "id", "ts", "nonce", "sig", "from", "to", "intent"],
               pcm=ZERO, id=HEX32, ts=TS, nonce=HEX32, sig=SIG, to=_obj(["agent"], agent=IDENTITY),
               intent=_obj(["type", "args"], type=SCHEMA_REF, args=ANY),
               claims={"type": "array", "maxItems": 8, "items": CLAIM},
               grants={"type": "array", "maxItems": 8, "items": GRANT},
               payload={"oneOf": [_obj(["kind", "text"], kind={"const": "text"}, text=_str(65536)),
                                  _obj(["kind", "data"], kind={"const": "data"}, data=ANY)]},
               **{"from": _obj(["agent", "run", "tenant"], agent=IDENTITY, run=ID, tenant=ID)})
SAFE = {"type": "integer", "minimum": -MAX_SAFE_INT, "maximum": MAX_SAFE_INT}
OPT = {"optional": BOOL}
FIELD = {"oneOf": [
    _obj(["type", "max"], type={"const": "string"}, max={"type": "integer", "minimum": 1, "maximum": 65536}, **OPT),
    _obj(["type", "min", "max"], type={"const": "int"}, min=SAFE, max=SAFE, **OPT),
    _obj(["type", "currency", "max"], type={"const": "money"}, currency=_str(3, pattern=r"[A-Z]{3}"),
         max=dict(SAFE, minimum=0), **OPT),
    _obj(["type", "pattern"], type={"const": "id"}, pattern=_str(256, minLength=1), **OPT),
    _obj(["type", "values"], type={"const": "enum"},
         values={"type": "array", "minItems": 1, "maxItems": 256, "items": {"type": "string"}}, **OPT),
    _obj(["type"], type={"const": "bool"}, **OPT),
    _obj(["type"], type={"const": "time"}, **OPT)]}
SCHEMA_DOC = _obj(["pcm_schema", "name", "fields"], pcm_schema=ZERO, name=_str(64, pattern=r"[a-z][a-z0-9_.-]*"),
                  fields={"type": "object", "additionalProperties": FIELD,
                          "propertyNames": {"type": "string", "pattern": r"[a-z][a-z0-9_]{0,63}"}},
                  claims={"type": "array", "maxItems": len(CLAIM_TYPES), "items": {"enum": CLAIM_TYPES}}, grant=BOOL)

_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def _is(v, t):
    if t == "integer":
        return type(v) is int
    if t == "number":
        return type(v) in (int, float)
    return isinstance(v, _TYPES[t])


def errors(schema, v, path="$"):
    """The ways `v` breaks `schema` (empty when it fits)."""
    out, s = [], schema
    if "type" in s and not _is(v, s["type"]):
        return [f"{path}: expected {s['type']}, got {type(v).__name__}"]
    if "const" in s and v != s["const"]:
        out.append(f"{path}: must be {s['const']!r}")
    if "enum" in s and v not in s["enum"]:
        out.append(f"{path}: {str(v)[:64]!r} not in {s['enum']}")
    if isinstance(v, str):
        if "pattern" in s and not re.fullmatch(s["pattern"], v, re.ASCII):
            out.append(f"{path}: does not match {s['pattern']}")
        if len(v) < s.get("minLength", 0):
            out.append(f"{path}: shorter than {s['minLength']}")
        if len(v) > s.get("maxLength", len(v)):
            out.append(f"{path}: longer than {s['maxLength']}")
    if _is(v, "number"):
        if "minimum" in s and v < s["minimum"]:
            out.append(f"{path}: below {s['minimum']}")
        if "maximum" in s and v > s["maximum"]:
            out.append(f"{path}: above {s['maximum']}")
    if isinstance(v, list):
        if len(v) > s.get("maxItems", len(v)):
            out.append(f"{path}: more than {s['maxItems']} items")
        if len(v) < s.get("minItems", 0):
            out.append(f"{path}: fewer than {s['minItems']} items")
        if "items" in s:
            for i, x in enumerate(v):
                out += errors(s["items"], x, f"{path}[{i}]")
    if isinstance(v, dict):
        out += [f"{path}: missing required '{k}'" for k in s.get("required", []) if k not in v]
        props, more = s.get("properties", {}), s.get("additionalProperties", True)
        for k, x in v.items():
            if k in props:
                out += errors(props[k], x, f"{path}.{k}")
            elif more is False:
                out.append(f"{path}: unexpected field {k[:64]!r}")
            elif isinstance(more, dict):
                out += errors(more, x, f"{path}.{k}")
            if "propertyNames" in s:
                out += errors(s["propertyNames"], k, f"{path}.{k}")
    if "oneOf" in s:
        n = sum(not errors(alt, v, path) for alt in s["oneOf"])
        if n != 1:
            out.append(f"{path}: must match exactly one alternative (matched {n})")
    return out


# ---------------------------------------------------------------------------------------------------- schema language
# value rules: nothing is converted, so true, 120.0 and "120" are not ints. An `id` pattern runs with Python `re` in
# its default (Unicode) mode, as Tracekit runs it.
FITS = {"string": lambda f, v: type(v) is str and len(v) <= f["max"],
        "int": lambda f, v: type(v) is int and f["min"] <= v <= f["max"],
        "money": lambda f, v: type(v) is int and 0 <= v <= f["max"],
        "id": lambda f, v: type(v) is str and len(v) <= 128 and re.fullmatch(f["pattern"], v) is not None,
        "enum": lambda f, v: type(v) is str and v in f["values"],
        "bool": lambda f, v: type(v) is bool,
        "time": lambda f, v: not errors(TS, v)}
OPS = {"int": "== <= >= < >", "money": "== <= >= < >", "time": "== <= >=", "string": "== in", "id": "== in",
       "enum": "== in", "bool": "=="}
CLAIM_ARGS = {"tests_passed": {"suite": {"type": "string", "max": 4096}},
              "approved_by": {"person": {"type": "string", "max": 256},
                              "call": {"type": "id", "pattern": ID["pattern"]}},
              "reached_host": {"host": {"type": "id", "pattern": r"[a-z0-9._:-]+"}},
              "file_written": {"path": {"type": "string", "max": 4096},
                               "digest": {"type": "id", "pattern": DIGEST["pattern"]}}}


def check_schema(doc):
    """The problems of a schema document (empty when it is well-formed)."""
    errs = errors(SCHEMA_DOC, doc)
    if errs:
        return errs
    for name, f in doc["fields"].items():
        if f["type"] == "int" and f["min"] > f["max"]:
            errs.append(f"$.fields.{name}: min above max")
        if f["type"] == "enum" and len(set(f["values"])) != len(f["values"]):
            errs.append(f"$.fields.{name}: values repeat")
        if f["type"] == "id":
            try:
                re.compile(f["pattern"])
            except re.error as e:
                errs.append(f"$.fields.{name}: bad pattern ({e})")
    if len(set(doc.get("claims", []))) != len(doc.get("claims", [])):
        errs.append("$.claims: types repeat")
    return errs


def schema_ref(doc):
    return f"{doc['name']}@{record_hash(doc)}"


def _shown(v):
    return json.dumps(v)[:64]


def check_args(fields, args):
    if not isinstance(args, dict):
        return ["args: not an object"]
    errs = [f"args.{k[:64]}: not in the schema" for k in args if k not in fields]
    for k, f in fields.items():
        if k not in args:
            if not f.get("optional"):
                errs.append(f"args.{k}: missing")
        elif not FITS[f["type"]](f, args[k]):
            errs.append(f"args.{k}: {_shown(args[k])} is not a valid {f['type']}")
    return errs


# ---------------------------------------------------------------------------------------------------- caveats
def _show(c):
    return f"{c['field']} {c['op']} {_shown(c['value'])}"


def check_caveats(fields, name, caveats):
    """Caveats that name no field, use an op the field's type has not, or carry a value the field can't hold."""
    out = []
    for c in caveats:
        f = fields.get(c["field"])
        if f is None:
            out.append(f"{_show(c)}: no field {c['field']} in {name}")
        elif c["op"] not in OPS[f["type"]].split():
            out.append(f"{_show(c)}: {c['op']} does not apply to a {f['type']} field")
        else:
            vals = c["value"] if c["op"] == "in" else [c["value"]]
            if not (isinstance(vals, list) and 1 <= len(vals) <= 64 and all(FITS[f["type"]](f, x) for x in vals)
                    and len(set(vals)) == len(vals)):
                out.append(f"{_show(c)}: not a valid {f['type']} value")
    return out


def _norm(c):
    """A caveat as ("==", v), ("in", set of strings), ("<=", b) or (">=", b); `< b` is `<= b-1` and `> b` is `>= b+1`.
    None when it means nothing (a bound that is no int or time, an `in` that is no set of distinct strings)."""
    op, v = c["op"], c["value"]
    if op in ("<", ">"):
        return None if type(v) is not int else ("<=", v - 1) if op == "<" else (">=", v + 1)
    if op in ("<=", ">="):
        return (op, v) if type(v) in (int, str) else None
    if op == "in":
        ok = isinstance(v, list) and v and all(type(x) is str for x in v) and len(set(v)) == len(v)
        return ("in", set(v)) if ok else None
    return (op, v) if type(v) in (int, str, bool) else None


def _implies(c, p):
    """Whether every value that passes normalised caveat `c` passes `p`."""
    (cop, cv), (pop, pv) = c, p
    if pop == "==":
        return cop == "==" and type(cv) is type(pv) and cv == pv or cop == "in" and cv == {pv}
    if pop == "in":
        return cop == "==" and type(cv) is str and cv in pv or cop == "in" and cv <= pv
    if pop == "<=":
        return cop in ("==", "<=") and type(cv) is type(pv) and cv <= pv
    return cop in ("==", ">=") and type(cv) is type(pv) and cv >= pv


def narrows(parent, child):
    """[] when each parent caveat is implied by a child caveat on its field; a dropped caveat is a widening."""
    kids = [(c["field"], _norm(c)) for c in child]
    out = [f"{_show(c)}: not a valid caveat" for c, (_, n) in zip(child, kids) if n is None]
    for p in parent:
        n = _norm(p)
        if n is None:
            out.append(f"{_show(p)}: not a valid caveat")
        elif not any(f == p["field"] and k is not None and _implies(k, n) for f, k in kids):
            out.append(f"{_show(p)}: dropped or widened")
    return out


def satisfies(args, c):
    n = _norm(c)
    return isinstance(args, dict) and c["field"] in args and n is not None and _implies(("==", args[c["field"]]), n)


# ---------------------------------------------------------------------------------------------------- keys and notes
ED25519, COSIGNATURE, HYBRID = 0x01, 0x04, 0xff
SLH_DSA = b"tracekit/slh-dsa-sha2-128s"
DASH = "\u2014 "


class NoteError(ValueError):
    pass


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _unb64(s):
    """Canonical base64 only."""
    try:
        raw = base64.b64decode(s, validate=True)
    except ValueError:   # binascii.Error, or a non-ASCII character
        raise NoteError("bad base64") from None
    if _b64(raw) != s:
        raise NoteError("non-canonical base64")
    return raw


def _check_name(name):
    if not name or "+" in name or len(name.encode("utf-8")) > 255 \
            or any(c.isspace() or ord(c) < 0x20 for c in name):
        raise NoteError(f"bad key name {name[:64]!r}")


def _key_id(name, type_, public):
    return hashlib.sha256(name.encode("utf-8") + b"\n" + bytes([type_]) + public).digest()[:4]


def parse_vkey(text):
    """(name, key id, type, public key) of a C2SP signed-note verifier key, name+hex8+base64(type || key)."""
    if not isinstance(text, str):
        raise NoteError("a vkey is a string")
    parts = text.split("+", 2)   # the base64 key may itself hold a '+'
    if len(parts) != 3:
        raise NoteError("a vkey is name+id+key")
    name, hid, key = parts
    _check_name(name)
    raw = _unb64(key)
    if not (len(raw) == 33 and raw[0] in (ED25519, COSIGNATURE)
            or len(raw) == 1 + len(SLH_DSA) + 32 and raw[0] == HYBRID and raw[1:].startswith(SLH_DSA)):
        raise NoteError("not an Ed25519 log, cosignature or SLH-DSA log vkey")
    if hid != _key_id(name, raw[0], raw[1:]).hex():
        raise NoteError("vkey id does not match the key")
    return name, bytes.fromhex(hid), raw[0], raw[1:]


def _ed25519(public, msg, sig):
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def check_sig(obj, tag, trust):
    """None when `obj` carries a valid signature, under domain tag `tag`, by an Ed25519 log key trust pins; else why
    not. A trust file with a malformed vkey raises NoteError."""
    for vk in trust.get("logs", []):
        name, kid, type_, public = parse_vkey(vk)
        if type_ != ED25519 or f"{name}+{kid.hex()}" != obj["sig"]["key"]:
            continue
        try:
            text = jcs({**{k: v for k, v in obj.items() if k != "sig"}, "t": tag})
        except NotJCS as e:
            return f"not JSON that RFC 8785 can encode ({e})"
        try:
            sig = base64.b64decode(obj["sig"]["sig"], validate=True)
        except ValueError:
            return "bad signature"
        return None if _ed25519(public, text, sig) else "bad signature"
    return f"signed by {obj['sig']['key']}, a key trust does not pin"


def _cosigned(text, ts):
    return f"cosignature/v1\ntime {ts}\n{text}".encode("utf-8")


def open_note(note, log_keys, witness_keys):
    """(origin, tree size, root, [(witness vkey, time)]) of a C2SP tlog-checkpoint signed note. A pinned Ed25519 log
    key named after the origin must sign it; lines of keys not pinned are skipped; a bad pinned signature fails it."""
    if len(note) > 1 << 20 or not note.endswith("\n") or any(ord(c) < 0x20 and c != "\n" for c in note):
        raise NoteError("malformed note")
    text, sep, sigs = note.partition("\n\n")
    if not sep:
        raise NoteError("no signature block")
    text += "\n"
    lines = sigs[:-1].split("\n")
    if len(lines) > 64:
        raise NoteError("too many signatures")
    head = text[:-1].split("\n")
    if len(head) != 3:
        raise NoteError("a checkpoint is origin, size and root")
    origin, size, root = head
    _check_name(origin)
    if not re.fullmatch(r"0|[1-9][0-9]{0,19}", size):
        raise NoteError("bad tree size")
    root = _unb64(root)
    if len(root) != 32:
        raise NoteError("bad root hash")
    pinned = {}
    for keys, want in ((log_keys, (ED25519, HYBRID)), (witness_keys, (COSIGNATURE,))):
        for k in keys:
            name, kid, type_, public = parse_vkey(k)
            if type_ not in want:
                raise NoteError(f"pinned key {name} has the wrong signature type")
            # lean: no SLH-DSA in the cryptography package; check hybrid lines when a pure SLH-DSA verify is added
            if type_ == HYBRID:
                raise NoteError(f"pinned key {name} is SLH-DSA, which this verifier can't check")
            pinned[(name, kid)] = (k, type_, public)
    data, seen, logged, cosigs = text.encode("utf-8"), set(), False, []
    for line in lines:
        if not line.startswith(DASH) or len(line[len(DASH):].split(" ")) != 2:
            raise NoteError("malformed signature line")
        name, blob = line[len(DASH):].split(" ")
        _check_name(name)
        raw = _unb64(blob)
        if len(raw) < 5:
            raise NoteError("short signature")
        if (name, raw[:4]) in seen:
            raise NoteError("two signatures from one key")
        seen.add((name, raw[:4]))
        if (name, raw[:4]) not in pinned:
            continue
        k, type_, public = pinned[(name, raw[:4])]
        sig = raw[4:]
        if type_ == ED25519:
            if not _ed25519(public, data, sig):
                raise NoteError(f"bad signature from pinned key {name}")
            logged = logged or name == origin
        else:
            ts = struct.unpack(">Q", sig[:8])[0] if len(sig) == 72 else None
            if ts is None or not _ed25519(public, _cosigned(text, ts), sig[8:]):
                raise NoteError(f"bad cosignature from pinned witness {name}")
            cosigs.append((k, ts))
    if not logged:
        raise NoteError(f"no signature from a pinned log key for origin {origin}")
    return origin, int(size), root, cosigs


def _node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion(index, size, leaf, proof, root):
    """RFC 9162 section 2.1.3.2."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _node(p, r)
            while not fn & 1 and fn:
                fn, sn = fn >> 1, sn >> 1
        else:
            r = _node(r, p)
        fn, sn = fn >> 1, sn >> 1
    return sn == 0 and r == root


# ---------------------------------------------------------------------------------------------------- evidence
class EvidenceError(ValueError):
    pass


def evidence(ev, msg, trust):
    """[(event, its opened args or None)] of a claim's evidence; EvidenceError when it does not verify against trust,
    or comes from another log than the one whose key signed `msg`, or from another run than the sender's."""
    try:
        origin, size, root, cosigs = open_note(ev["checkpoint"], trust.get("logs", []),
                                               [w["vkey"] for w in trust.get("witnesses", [])])
    except NoteError as e:
        raise EvidenceError(f"checkpoint: {e}") from None
    if origin != msg["sig"]["key"].rpartition("+")[0]:
        raise EvidenceError(f"checkpoint: of log {origin[:128]}, not the one that signed the message")
    need = trust.get("witnesses_required", 0)
    if len(cosigs) < need:
        raise EvidenceError(f"checkpoint: {len(cosigs)} pinned cosignature(s), {need} required")
    out = []
    for i, r in enumerate(ev["records"], 1):
        e = r["event"]
        if not isinstance(e, dict) or record_hash(e) != r["hash"]:
            raise EvidenceError(f"record {i}: hash does not match the event")
        try:
            proof = [base64.b64decode(p, validate=True) for p in r["proof"]]
        except ValueError:   # bad base64, or a non-ASCII entry
            proof = None
        leaf = hashlib.sha256(b"\x00" + bytes.fromhex(r["hash"][7:])).digest()
        if type(e.get("seq")) is not int or proof is None or not verify_inclusion(e["seq"], size, leaf, proof, root):
            raise EvidenceError(f"record {i}: not in the checkpoint")
        if (e.get("tenant"), e.get("run_id")) != (msg["from"]["tenant"], msg["from"]["run"]):
            raise EvidenceError(f"record {i}: from run {str(e.get('run_id'))[:128]}, not the sender's")
        args = None
        if "salt" in r or "args" in r:
            d = _data(e)
            digest = record_hash({"tool": d.get("tool"), "args": r.get("args")}).encode("ascii")
            want = d.get("args_commitment")
            if not (e.get("type") == "policy.decision" and "salt" in r and "args" in r and type(want) is str
                    and want.isascii() and hmac.compare_digest("hmac-sha256:" + hmac.new(bytes.fromhex(r["salt"]), digest,
                                                                      "sha256").hexdigest(), want)):
                raise EvidenceError(f"record {i}: the args do not open its decision's commitment")
            args = r["args"]
        out.append((e, args))
    return out


def _data(e):
    d = e.get("data")
    return d if isinstance(d, dict) else {}


# ---------------------------------------------------------------------------------------------------- claims
_RANK = {"proven": 0, "unproven": 1, "failed": 2}


def _ran(recs, match, what, tools, cls=None):
    """(result, detail) of "a call whose opened args match ran and succeeded": proven by a result the signer recorded
    as T2, unproven by the agent's own (T1) result or by a tool the table does not place as `cls`."""
    best = ("failed", f"no call in the evidence {what}")
    for e, args in recs:
        d = _data(e)
        if not isinstance(args, dict) or type(d.get("tool")) is not str or d.get("decision") == "deny" \
                or not match(d["tool"], args):
            continue
        if cls and tools.get(d["tool"]) != cls:
            best = min(("unproven", f"a tool the verifier can't place as a {cls} tool"), best, key=lambda o: _RANK[o[0]])
            continue
        for x, _ in recs:
            r = _data(x)
            if x.get("type") != "tool.result" or (r.get("decision_id"), r.get("tool_use_id")) != (
                    d.get("decision_id"), d.get("tool_use_id")):
                continue
            if r.get("ok") is not True:
                got = ("failed", f"call {d.get('tool_use_id')} {what}, and failed")
            elif (x.get("source"), x.get("tier")) == ("gateway", "T2"):
                return "proven", f"call {d.get('tool_use_id')} {what}, run by {r.get('via')} (T2)"
            else:
                got = ("unproven", "the result is the agent's own report (T1)")
            best = min(got, best, key=lambda o: _RANK[o[0]])
    return best


def _first(args, *keys):
    return next((args[k] for k in keys if args.get(k) is not None), None)


# What runs tests: the reference recognizer, Tracekit's "test" family of findings_text.command_facts.
SEPARATORS = frozenset((";", ";;", "&&", "||", "|", "|&", "&", "(", ")"))
PREFIXES = frozenset(("sudo", "doas", "env", "time", "nice", "nohup", "command", "exec", "npx", "bunx", "pnpx",
                      "timeout", "stdbuf", "xargs"))
RUNNERS = {"uv": "run", "poetry": "run", "pipenv": "run", "pdm": "run", "hatch": "run", "rye": "run",
           "bundle": "exec", "npm": "exec"}
PYTHONS = re.compile(r"python(?:3(?:\.\d+)?)?|py|pypy3?")
TEST_PROGS = frozenset(("pytest", "py.test", "jest", "vitest", "mocha", "rspec", "tox", "nox", "phpunit", "ctest",
                        "ava", "karma", "nose2", "trial", "behave", "cucumber", "unittest"))


def simple_commands(cmd):
    """The simple commands of a shell command line, each a list of words: split at line breaks and the operators
    ; ;; && || | |& & ( )."""
    out = []
    for line in cmd.split("\n"):
        if not line.strip():
            continue
        try:
            lex = shlex.shlex(line, posix=True, punctuation_chars=True)
            lex.whitespace_split = True
            words = list(lex)
        except ValueError:   # unbalanced quotes: the words whitespace leaves
            words = line.split()
        cur = []
        for w in words + [";"]:
            if w in SEPARATORS:
                out += [cur] if cur else []
                cur = []
            else:
                cur.append(w)
    return out


def runs_tests(words):
    """Whether one simple command runs tests: past variable assignments and wrappers (sudo, env, timeout, uv run...),
    and `python -m <module>`, the program is a test runner or a build tool's test subcommand."""
    i = 0
    while i < len(words):
        w, base = words[i], posixpath.basename(words[i])
        if "=" in w and w.split("=", 1)[0].isidentifier():
            i += 1
        elif base in PREFIXES:
            i += 1
            while i < len(words) and (words[i].startswith("-") or words[i][:1].isdigit()):
                i += 1
        elif RUNNERS.get(base) and i + 1 < len(words) and words[i + 1] == RUNNERS[base]:
            i += 2
        else:
            break
    if i >= len(words):
        return False
    prog, args = posixpath.basename(words[i]).lower(), words[i + 1:]
    plain = [a for a in args if not a.startswith("-")]
    sub, nxt = [a.lower() for a in (plain + ["", ""])[:2]]
    if PYTHONS.fullmatch(prog) and "-m" in args:   # `nxt` stays the one before -m, as in the reference
        j = args.index("-m") + 1
        prog, args = (args[j].lower() if j < len(args) else ""), args[j + 1:]
        plain = [a for a in args if not a.startswith("-")]
        sub = plain[0].lower() if plain else ""
    return (prog in TEST_PROGS or prog == "playwright" and sub == "test"
            or prog in ("npm", "yarn", "pnpm", "bun") and (sub in ("test", "t") or sub == "run" and nxt.startswith(
                "test"))
            or prog in ("go", "cargo", "dotnet", "deno", "swift", "mix", "bazel") and sub in ("test", "nextest")
            or prog in ("make", "gmake") and sub in ("test", "tests", "check")
            or prog in ("mvn", "mvnw", "gradle", "gradlew") and bool(
                {a.lower().rsplit(":", 1)[-1] for a in plain} & {"test", "verify", "check"}))


def tests_passed(a, recs, tools):
    # one simple command: in `pytest || true` or `pytest; true` the call's status is not the tests'
    cmds = simple_commands(a["suite"])
    if len(cmds) != 1 or not runs_tests(cmds[0]):
        return "failed", f"{a['suite'][:64]!r} is not a single test command"
    return _ran(recs, lambda tool, args: _first(args, "command", "cmd", "commands") == a["suite"],
                f"ran {a['suite'][:64]!r}", tools, "shell")


def approved_by(a, recs, tools):
    for e, _ in recs:
        d = _data(e)
        if e.get("type") == "approval" and d.get("decision") == "approve" and d.get("tool_use_id") == a["call"] \
                and a["person"] in (d.get("person"), d.get("approver")) \
                and d.get("approver_kind", "person") == "person" and d.get("self_approved") is not True:
            return "proven", f"approval seq {e.get('seq')} by {a['person']} of {a['call']}"
    return "failed", f"no approval of {a['call']} by the person {a['person']}"


SCHEMES = ("http", "https", "ws", "wss", "ftp")


def url_host(url):
    """The host of an http, https, ws, wss or ftp URL (http when it has no scheme), lower case, when it is a plain DNS
    name or a dotted-quad IPv4 address; else None."""
    # lean: a URL with %, \, spaces, controls, non-ASCII, IPv6 or a numeric host in another notation (0x7f.1) is no
    # match, where the WHATWG reading canonicalises it; widen when an http tool's records need it
    if not isinstance(url, str) or not url.isascii() or re.search(r"[\x00-\x20\\%\x7f]", url):
        return None
    if not re.match(r"(?i)((https?|wss?|ftp|file):|[a-z][a-z0-9+.-]*:(?![0-9])|//)", url):
        url = "http://" + url
    m = re.match(r"([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)", url)
    if not m or m.group(1).lower() not in SCHEMES:
        return None
    host = m.group(2).rpartition("@")[2]
    if host.startswith("["):
        return None
    host = host.partition(":")[0].lower()
    if re.fullmatch(r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}",
                    host):
        return host
    if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)*\.?", host) and not re.fullmatch(
            r"0x[0-9a-f]*|[0-9]+", host.rstrip(".").rpartition(".")[2]):
        return host
    return None


def reached_host(a, recs, tools):
    for e, _ in recs:
        d = _data(e)
        if e.get("type") == "effect.observed" and d.get("host") == a["host"] and d.get("kind") in ("net", "connect") \
                and not d.get("denied"):
            return "proven", f"effect.observed seq {e.get('seq')}: {d.get('observer')} saw the run reach {a['host']}"
    return _ran(recs, lambda tool, args: url_host(_first(args, "url")) == a["host"], f"reached {a['host']}",
                tools, "http")


def fs_path(raw):
    """The path a file rule compares: `\\` is `/`; an absolute path (/x, C:/x) without `..` is normalised; otherwise
    only what follows the last `..`, without empty and `.` segments."""
    raw = raw.replace("\\", "/")
    parts = raw.split("/")
    if (raw.startswith("/") or re.match(r"[A-Za-z]:/", raw)) and ".." not in parts:
        return posixpath.normpath(raw)
    tail = parts[len(parts) - parts[::-1].index(".."):] if ".." in parts else parts
    return "/".join(p for p in tail if p not in ("", "."))


WRITE_TOOLS = ("Write",)   # the tools whose name says they write a whole file; an `op` in the args is the agent's word


def file_written(a, recs, tools):
    if ".." in a["path"].replace("\\", "/").split("/"):
        return "failed", f"{a['path'][:64]} has a `..`: name the file's own path"

    def match(tool, args):
        path, content = _first(args, "file_path", "notebook_path", "path"), args.get("content")
        return tool in WRITE_TOOLS and isinstance(path, str) and fs_path(path) == fs_path(a["path"]) \
            and isinstance(content, str) \
            and "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest() == a["digest"]
    return _ran(recs, match, f"wrote {a['path'][:64]} with {a['digest']}", tools)


CHECKERS = {"tests_passed": tests_passed, "approved_by": approved_by, "reached_host": reached_host,
            "file_written": file_written}


def check_claim(c, msg, trust, tools):
    errs = check_args(CLAIM_ARGS[c["type"]], c["args"])
    if errs:
        result, detail = "failed", "; ".join(errs)
    elif "evidence" not in c:
        result, detail = "unproven", "no evidence"
    else:
        try:
            result, detail = CHECKERS[c["type"]](c["args"], evidence(c["evidence"], msg, trust), tools)
        except EvidenceError as e:
            result, detail = "failed", str(e)
    return {"type": c["type"], "result": result, "detail": detail}


# ---------------------------------------------------------------------------------------------------- grants
def verify_grants(msg, doc, trust):
    """The grant chain (root first) of a message whose envelope and signature passed."""
    grants, args, out = msg.get("grants", []), msg["intent"]["args"], []
    if not grants:
        need = bool(doc.get("grant"))
        return {"result": "failed" if need else "none", "steps": 0, "root": None,
                "problems": ["the intent needs a grant"] if need else []}
    for i, g in enumerate(grants):
        at = f"grant {i}"
        if e := check_sig(g, GRANT_TAG, trust):
            out.append(f"{at}: {e}")
        if g["intent"] != msg["intent"]["type"]:
            out.append(f"{at}: for {g['intent']}, not this intent")
        out += [f"{at}: {e}" for e in check_caveats(doc["fields"], doc["name"], g["caveats"])]
        if msg["ts"] > g["expires_at"]:
            out.append(f"{at}: expired at {g['expires_at']}")
        if g["issuer"]["tenant"] != msg["from"]["tenant"]:
            out.append(f"{at}: issued in tenant {g['issuer']['tenant']}, not the sender's {msg['from']['tenant']}")
        for c in g["caveats"]:   # every caveat of every grant, not only through narrowing
            if not satisfies(args, c):
                got = _shown(args[c["field"]]) if isinstance(args, dict) and c["field"] in args else "missing"
                out.append(f"{at}: {c['field']} {got} breaks {_show(c)}")
        if i == 0:
            if g["parent"] is not None:
                out.append(f"{at}: the root grant has a parent")
            if g["issuer"]["kind"] != "person":
                out.append(f"{at}: the root grant must come from a person's approval")
            if g["issuer"]["id"] == g["subject"]:
                out.append(f"{at}: the root grant's issuer is its own subject")
            continue
        p = grants[i - 1]
        if g["parent"] != record_hash(p):
            out.append(f"{at}: its parent is not grant {i - 1}")
        if not p["delegable"]:
            out.append(f"{at}: grant {i - 1} can't be passed on")
        if (g["issuer"]["kind"], g["issuer"]["id"]) != ("agent", p["subject"]):
            out.append(f"{at}: issued by {g['issuer']['id']}, not grant {i - 1}'s subject {p['subject']}")
        if g["expires_at"] > p["expires_at"]:
            out.append(f"{at}: outlives its parent")
        out += [f"{at}: {e}" for e in narrows(p["caveats"], g["caveats"])]
    if grants[-1]["subject"] != msg["from"]["agent"]:
        out.append(f"the last grant is for {grants[-1]['subject']}, not the sender {msg['from']['agent']}")
    root = grants[0]["issuer"]
    return {"result": "failed" if out else "ok", "steps": len(grants),
            "root": {k: root[k] for k in ("kind", "id", "person") if k in root}, "problems": out}


# ---------------------------------------------------------------------------------------------------- replay
def epoch(ts):
    """Unix seconds of a TS string."""
    return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc).timestamp()


def _secs(t):
    return time.time() if t is None else epoch(t) if isinstance(t, str) else float(t)


class Replay:
    """One receiver's replay state, in memory. A message passes once: within `window_s` of the receiver's clock, not
    sent before it started, newer than the sender's floor and with a new nonce. Past `per_sender` nonces the oldest
    is forgotten and raises the floor. `window_s=None` skips the clocks (an auditor of a saved conversation).
    `started` and a check's `now` are unix seconds or TS strings; None is the current time."""

    def __init__(self, window_s=300, per_sender=4096, started=None):
        self.window_s, self.per_sender, self.started = window_s, per_sender, _secs(started)
        self.seen, self.floor = {}, {}

    def check(self, msg, now=None):
        """(ok, detail) for a message whose signature passed; a passing one is remembered."""
        now, sender = _secs(now), msg["from"]["agent"]
        try:
            t = epoch(msg["ts"])
        except ValueError:
            return False, f"sent at {msg['ts']}, which is no real time"
        if self.window_s is not None:
            if abs(now - t) > self.window_s:
                return False, f"sent at {msg['ts']}, more than {self.window_s:g} s from this receiver's clock"
            if t < self.started:
                return False, "sent before this receiver started: ask for it again"
        if t <= self.floor.get(sender, float("-inf")):
            return False, "older than the messages this receiver remembers from the sender"
        seen = self.seen.setdefault(sender, collections.OrderedDict())
        if msg["nonce"] in seen:
            return False, "replayed: this nonce was seen before"
        seen[msg["nonce"]] = t
        while seen and self.window_s is not None and next(iter(seen.values())) < now - self.window_s:
            seen.popitem(last=False)   # the window refuses it now
        while len(seen) > self.per_sender:
            self.floor[sender] = max(self.floor.get(sender, float("-inf")), seen.popitem(last=False)[1])
        return True, "fresh"


# ---------------------------------------------------------------------------------------------------- verify
def _verdict(out, doc, strict):
    claims = out["claims"] or []
    bad = [f"replay: {out['replay']['detail']}"] if out["replay"]["ok"] is False else []
    bad += [f"schema: {e}" for e in out["schema"]["errors"]]
    bad += [f"grant: {p}" for p in (out["grants"] or {}).get("problems", [])]
    bad += [f"{c['type']}: failed ({c['detail']})" for c in claims if c["result"] == "failed"]
    proven = {c["type"] for c in claims if c["result"] == "proven"}
    missing = [f"{t}: required, not proven" for t in (doc or {}).get("claims", []) if t not in proven]
    if bad or strict and missing:
        return "reject", bad + (missing if strict else [])
    soft = [f"{c['type']}: unproven ({c['detail']})" for c in claims if c["result"] == "unproven"] + missing
    return ("accept-unproven", soft) if soft else ("accept", [])


def verify(message, trust, schemas, tools, me=None, strict=False, now=None, replay=None):
    """Check a PCM message: envelope, signature, replay (a Replay, or None to skip) and recipient (`me`, or None to
    skip), the intent's args against its schema document among `schemas`, its grants and its claims. `tools` maps a
    tool name to its class ("shell", "http", ...). `strict`: every claim type the schema lists must be proven.

    Returns {verdict: accept | accept-unproven | reject, signature, replay, schema, grants, claims, reasons}; a part is
    None when the check stopped before it. Raises ValueError for a bad schema document or trust file (the receiver's
    configuration), never for a bad message."""
    out = {"signature": None, "replay": None, "schema": None, "grants": None, "claims": None, "verdict": "reject",
           "reasons": []}
    errs = errors(MESSAGE, message)
    if errs:
        out["reasons"] = [f"envelope: {e}" for e in errs[:8]]
        return out
    e = check_sig(message, MESSAGE_TAG, trust)
    out["signature"] = {"ok": e is None, "key": message["sig"]["key"]}
    if e:
        out["reasons"] = [f"signature: {e}"]
        return out
    ok, detail = replay.check(message, now) if replay is not None else (None, "not checked")
    if me is not None and message["to"]["agent"] != me:
        ok, detail = False, f"addressed to {message['to']['agent']}, not {me}"
    out["replay"] = {"ok": ok, "detail": detail}
    docs = {}
    for i, d in enumerate(schemas):
        if errs := check_schema(d):
            raise ValueError(f"schema document {i}: {'; '.join(errs)}")
        docs[schema_ref(d)] = d
    ref = message["intent"]["type"]
    doc = docs.get(ref)
    errs = [f"unknown schema {ref}"] if doc is None else check_args(doc["fields"], message["intent"]["args"])
    out["schema"] = {"ok": not errs, "ref": ref, "errors": errs}
    if doc is not None:
        out["grants"] = verify_grants(message, doc, trust)
    out["claims"] = [check_claim(c, message, trust, tools) for c in message.get("claims", [])]
    out["verdict"], out["reasons"] = _verdict(out, doc, strict)
    return out
