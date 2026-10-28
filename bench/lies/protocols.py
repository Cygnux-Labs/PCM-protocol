"""Real agent protocols as PCM-Lies receivers, added after the pre-registration (RESULTS.md, "Real protocols as
receivers"). Each receiver is a model of the checks one protocol gives a receiver, built from its specification (the
sections cited below), not a run of its SDK.

Who holds which key decides most rows. A real protocol signs with the sending agent's own key, or its platform's, so a
lying sender signs its own lie. Each receiver first builds, on the sender's side, the message the sender would send in
that protocol: from the dataset message, with the keys the sender holds and the artifacts that really exist (`World`).
The receiver's checks then see only that message and the receiver's own configuration. Every key is Ed25519, derived
from its holder's name and the seed; a receiver finds a public key as the protocol does (a DID document, an Almanac
entry, a JWKS)."""
import functools
import hashlib
import hmac
import json
import operator

import pcm_verify as pv
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SEED = 20261028
WINDOW = 300   # s: ANP-02's widest created/expires window; also the KB-JWT iat window for AP2 and VI


@functools.lru_cache(maxsize=None)
def _key(holder):
    seed = hashlib.sha256(f"pcm-lies {SEED} protocols: {holder}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def sign(holder, data):
    return _key(holder).sign(data)


def signed_by(holder, data, sig):
    try:
        _key(holder).public_key().verify(sig, data)
        return True
    except InvalidSignature:
        return False


def _bytes(obj):
    return json.dumps(obj, sort_keys=True).encode()


def _uri(agent):
    return f"https://agents.example/{agent}"


def _note(ev, logs):
    """(origin, size, root) of a claim's checkpoint when one of `logs` signed it, else None."""
    try:
        return tuple(pv.open_note(ev["checkpoint"], logs, [])[:3])
    except (ValueError, KeyError, TypeError):   # NoteError is a ValueError
        return None


def _in(r, size, root):
    """Whether record `r` is in the tree of `size` with `root`: its content hash, and its inclusion proof at its index
    (RFC 9162 SHA-256)."""
    try:
        return pv.record_hash(r["event"]) == r["hash"] and pv.verify_inclusion(
            r["event"]["seq"], size, hashlib.sha256(b"\x00" + bytes.fromhex(r["hash"][7:])).digest(),
            [pv._unb64(p) for p in r["proof"]], root)
    except (ValueError, KeyError, TypeError):
        return False


def receipts(ev, logs):
    """[(record, origin of the log it is in, or None)] by SCITT's check of a statement: its content hash, and its
    inclusion receipt against the tree head the claim carries, signed by one of `logs`."""
    note = _note(ev, logs)
    return [(r, note[0] if note and _in(r, *note[1:]) else None) for r in ev.get("records") or []]


def _hash(event):
    try:
        return pv.record_hash(event)
    except ValueError:
        return None


def _opened(r):
    """A policy.decision record's opened args, when the salt and args open its commitment (SPEC 6.2)."""
    d = r["event"].get("data") or {}
    want = d.get("args_commitment")
    try:
        digest = pv.record_hash({"tool": d.get("tool"), "args": r["args"]}).encode("ascii")
        mac = "hmac-sha256:" + hmac.new(bytes.fromhex(r["salt"]), digest, "sha256").hexdigest()
    except (KeyError, ValueError):   # not opened, or args JCS can't encode
        return None
    return r["args"] if type(want) is str and hmac.compare_digest(mac, want) else None


class World:
    """What really exists, read from the whole dataset: the logs' keys, and the records really in a log, that is in a
    tree a log signed, by any checkpoint the dataset holds. Only the sender's side uses it."""

    def __init__(self, recs):
        self.logs = sorted({vk for r in recs for vk in r["trust"]["logs"]})
        self.events, notes, rest = {}, set(), []   # events: record hash -> origin of its log
        for r in recs:
            for m in [parse(r)] + (r["options"].get("replay") or {}).get("seen", []):
                for c in (m or {}).get("claims") or []:
                    ev = c.get("evidence") or {}
                    notes.add(_note(ev, self.logs))
                    for rec, origin in receipts(ev, self.logs):
                        if origin:
                            self.events[rec["hash"]] = origin
                        else:
                            rest.append(rec)
        notes.discard(None)
        for r in rest:   # e.g. records sent under an older checkpoint than their proof's (L10)
            if isinstance(r, dict) and _hash(r.get("event")) not in self.events:
                self.events.update({r["hash"]: o for o, size, root in notes if _in(r, size, root)})

    def grant_log(self, g):
        """The origin of the log whose key signed grant `g`; None for a grant no log signed as it stands."""
        try:
            return g["sig"]["key"].rpartition("+")[0] if pv.check_sig(g, pv.GRANT_TAG, {"logs": self.logs}) is None \
                else None
        except (KeyError, TypeError, ValueError):
            return None

    def approvals(self, claim):
        """[(origin, approval data, checkout)] of the real approvals (decision "approve") in a claim's evidence. The
        checkout is {tool, args} of the call approved, through its approval.request and policy.decision; args is
        None when the evidence doesn't open them, and the checkout None when the evidence lacks either record."""
        real = []
        for r in (claim.get("evidence") or {}).get("records") or []:
            if isinstance(r, dict) and isinstance(r.get("event"), dict) and self.events.get(_hash(r["event"])):
                real.append((r, r["event"].get("data") or {}, self.events[_hash(r["event"])]))
        out = []
        for r, d, origin in real:
            if r["event"].get("type") != "approval" or d.get("decision") != "approve":
                continue
            asked = {x.get("decision_id") for y, x, _ in real if y["event"].get("type") == "approval.request"
                     and x.get("approval_id") == d.get("approval_id")}
            dec = [y for y, x, _ in real
                   if y["event"].get("type") == "policy.decision" and x.get("decision_id") in asked]
            out.append((origin, d, {"tool": dec[0]["event"]["data"].get("tool"), "args": _opened(dec[0])} if dec
                        else None))
        return out


def parse(rec):
    """The message as a receiver reads it (the same as plain A2A: Python's json, the last duplicate wins); None when it
    can't be read."""
    try:
        return json.loads(rec["wire"]) if rec.get("wire") is not None else rec["message"]
    except ValueError:
        return None


# ------------------------------------------------------------------------------------------------ the receivers
def a2a_card(world, msg, body, rec, state):
    """A2A 1.0 with a signed Agent Card. A server authenticates each request by a scheme its card declares (spec 7.3,
    7.4), and a card may carry a JWS over its RFC 8785 form, which a client verifies (8.4). Messages, tasks and
    artifacts carry no signature (3-8), and duplicate detection by messageId is a MAY (off here). The sender's card
    and credentials are its own and genuine, so the receiver verifies the card and reads the message."""
    card = {"name": msg["from"]["agent"], "url": _uri(msg["from"]["agent"]), "protocolVersion": "1.0"}
    jws = sign(f"agent:{card['name']}", pv.jcs(card))
    # the receiver
    return ("accept", None) if signed_by(f"agent:{card['name']}", pv.jcs(card), jws) else ("reject", "card")


def _uagents_digest(env):
    h = hashlib.sha256()
    for k in ("sender", "target", "session", "schema_digest", "payload", "expires", "nonce"):
        h.update(str(env[k]).encode())
    return h.digest()


def uagents(world, msg, body, rec, state):
    """Fetch.ai uAgents (uagents_core/envelope.py, uagents/asgi.py): the sender signs a SHA-256 digest of the envelope's
    sender, target, session, schema_digest, payload, expires and nonce with its own key; the receiver verifies it for
    an agent sender and refuses a target it does not host. `expires` is a reply timeout there, and there is no nonce
    cache."""
    env = {"sender": msg["from"]["agent"], "target": msg["to"]["agent"], "session": msg.get("id"),
           "schema_digest": msg["intent"]["type"], "payload": body, "expires": int(pv.epoch(msg["ts"])) + WINDOW,
           "nonce": msg.get("nonce")}
    env["signature"] = sign(f"agent:{env['sender']}", _uagents_digest(env))
    # the receiver
    if env["target"] != rec["options"]["me"]:
        return "reject", "target"
    return ("accept", None) if signed_by(f"agent:{env['sender']}", _uagents_digest(env), env["signature"]) \
        else ("reject", "signature")


def _signature_base(target, digest, p):
    params = (f'("@method" "@target-uri" "content-digest");created={p["created"]};expires={p["expires"]};'
              f'nonce="{p["nonce"]}";keyid="{p["keyid"]}";alg="ed25519"')
    return (f'"@method": POST\n"@target-uri": {target}\n"content-digest": {digest}\n'
            f'"@signature-params": {params}').encode()


def _content_digest(body):
    return "sha-256=:" + pv._b64(hashlib.sha256(body.encode("utf-8", "surrogatepass")).digest()) + ":"


def rfc9421(world, msg, body, rec, state):
    """RFC 9421 HTTP message signatures with replay checks, as ANP-02 (its origin proof), Visa TAP and Web Bot Auth use
    them. The sender signs @method, @target-uri and the RFC 9530 content-digest, with created, expires, nonce and
    keyid (9421 sections 2.3, 2.5, 3.1). The receiver checks the digest, rebuilds the signature base from the request
    it got (so a request sent to another receiver fails), verifies it with the key keyid names, refuses a created
    time more than 300 s from its clock (ANP-02: 1 to 5 minutes; TAP allows 8) and a (keyid, nonce) it has seen
    (ANP-02's replay cache; TAP's nonce cache). The cache is in memory, so a restart empties it."""
    p = {"created": int(pv.epoch(msg["ts"])), "nonce": msg.get("nonce"), "keyid": msg["from"]["agent"]}
    p["expires"] = p["created"] + WINDOW
    digest = _content_digest(body)
    req = {"body": body, "content-digest": digest, "params": p,
           "signature": sign(f"agent:{p['keyid']}", _signature_base(_uri(msg["to"]["agent"]), digest, p))}
    # the receiver
    p, now, me = req["params"], pv.epoch(rec["options"]["now"]), rec["options"]["me"]
    if _content_digest(req["body"]) != req["content-digest"]:
        return "reject", "digest"
    if not signed_by(f"agent:{p['keyid']}", _signature_base(_uri(me), req["content-digest"], p),
                     req["signature"]):
        return "reject", "signature"
    if abs(now - p["created"]) > WINDOW or now > p["expires"]:
        return "reject", "window"
    if (p["keyid"], p["nonce"]) in state:
        return "reject", "nonce"
    state.add((p["keyid"], p["nonce"]))
    return "accept", None


def scitt(world, msg, body, rec, state):
    """SCITT (RFC 9943, with RFC 9942 receipts) as a gate on claims: each claim must carry statements, and each must
    be in a log the receiver pins: its content hash, and its inclusion receipt against a tree head that log signed.
    The records have no signature of their own (the log signs its tree head), so the receipt stands for the issuer's
    signature too. SCITT has no rule tying a claim to a statement, no message signature, no run or tenant binding, no
    tiers, and no freshness, replay or grant rules."""
    for c in msg.get("claims") or []:
        ev = c.get("evidence") if isinstance(c, dict) else None
        if not isinstance(ev, dict) or not ev.get("records"):
            return "reject", "no statement"
        if not all(origin for _, origin in receipts(ev, rec["trust"]["logs"])):
            return "reject", "receipt"
    return "accept", None


# AP2 v0.2 and Verifiable Intent v0.1 ------------------------------------------------------------------------------
OPS = {"==": operator.eq, "<=": operator.le, ">=": operator.ge, "<": operator.lt, ">": operator.gt,
       "in": lambda a, b: a in b}


def _holds(args, c):
    """AP2 evaluates each constraint on the closed mandate's values; an unknown one fails."""
    try:
        return isinstance(args, dict) and c["field"] in args and OPS[c["op"]](args[c["field"]], c["value"])
    except (KeyError, TypeError):
        return False


def _mandate(by, body, l1=None):
    return {"by": by, "body": body, "sig": sign(by, _bytes(body)), "l1": l1}


def _l1(person):
    """VI's L1: the credential provider certifies the person's device key."""
    return sign("issuer", _bytes({"person": person}))


def present(world, msg, model):
    """The AP2 artifacts the sender can present, for `model` "ap2" (the Trusted Agent Provider model) or "vi"
    (Verifiable Intent's layers, AP2's User Credential model made concrete).
    - The root grant is an open mandate: its caveats are constraints, expires_at is exp, its subject's key is cnf.
      Under "ap2" the platform whose log records the person's consent signs it; under "vi" the person's device key,
      which L1 certifies. A child grant has no AP2 form (agent-to-agent delegation is outside v0.2), so it is dropped.
    - A person's approval is a Human Present checkout mandate of the call approved, signed the same way: by the
      platform, stating who approved ("ap2"), or by that person's device key ("vi").
    - The presentation is a KB-JWT the sender signs: aud, nonce, iat.
    A mandate no real grant or approval stands behind is one the sender signs with its own key."""
    me, out = f"agent:{msg['from']['agent']}", {"sender": msg["from"]["agent"], "open": None, "approvals": []}
    grants = msg.get("grants") or []
    if grants:
        g, issuer = grants[0], grants[0].get("issuer") or {}
        log = world.grant_log(g) if issuer.get("kind") == "person" else None   # a person's consent, really signed
        body = {k: g.get(k) for k in ("intent", "caveats", "expires_at")} | {"cnf": f"agent:{g.get('subject')}"}
        if model == "ap2" and log:
            out["open"] = _mandate(f"provider:{log}", body)
        elif model == "vi" and log and issuer.get("person"):
            out["open"] = _mandate(f"person:{issuer['person']}", body, _l1(issuer["person"]))
        else:
            out["open"] = _mandate(me, body)
    for c in msg.get("claims") or []:
        if not isinstance(c, dict) or c.get("type") != "approved_by":
            continue
        mandates = []
        for log, d, checkout in world.approvals(c):
            who = d.get("person") or d.get("approver")
            if model == "ap2":
                mandates.append(_mandate(f"provider:{log}", {"person": who, "checkout": checkout}))
            elif d.get("person"):
                mandates.append(_mandate(f"person:{who}", {"person": who, "checkout": checkout}, _l1(who)))
            else:
                mandates.append(_mandate(f"approver:{who}", {"person": who, "checkout": checkout}))
        if not mandates:   # nothing real: the sender signs one itself
            mandates = [_mandate(me, {"person": (c.get("args") or {}).get("person"),
                                      "checkout": {"tool": None, "args": msg["intent"]["args"]}})]
        out["approvals"].append(((c.get("args") or {}).get("person"), mandates))
    if out["open"] or out["approvals"]:
        kb = {"aud": msg["to"]["agent"], "nonce": msg.get("nonce"), "iat": msg["ts"]}
        out["kb"] = {"body": kb, "sig": sign(me, _bytes(kb))}
    return out


def _trusted(m, person, model, trust):
    """Whether mandate `m` is signed by a key the model trusts, for `person` (None: any person)."""
    if not signed_by(m["by"], _bytes(m["body"]), m["sig"]):
        return False
    if model == "ap2":   # the receiver trusts the platforms whose logs it pins
        return m["by"] in {f"provider:{vk.split('+')[0]}" for vk in trust["logs"]} \
            and person in (None, m["body"].get("person"))
    kind, _, who = m["by"].partition(":")   # vi: a device key L1 certifies, of the person named
    return kind == "person" and m["l1"] is not None and signed_by("issuer", _bytes({"person": who}), m["l1"]) \
        and person in (None, who)


def _authorizes(body, msg, now):
    """An open mandate's checks on this request: its intent, each constraint and exp."""
    return body.get("intent") == msg["intent"]["type"] and all(
        _holds(msg["intent"]["args"], c) for c in body.get("caveats") or []) and now < pv.epoch(body["expires_at"])


def mandates(world, msg, body, rec, state, model):
    """AP2 v0.2 (agent_authorization.md, specification.md) or, with model "vi", Mastercard Verifiable Intent v0.1.
    A message with no mandate rides on A2A unsigned, as AP2 does, and passes: claims about tests, hosts and files
    carry none. Otherwise the receiver checks the KB-JWT (signed by cnf, aud is this receiver, a nonce not seen,
    iat within 300 s), the open mandate (signed by a trusted key, intent, every constraint, exp) and each checkout
    mandate (signed by a trusted key for the person the claim names, and of this request: the same args, and the tool
    the intent's schema names if it names one). The values of a checkout must be disclosed; an approval of a
    pcm.grant call is the consent to an open mandate and is checked as one."""
    env = present(world, msg, model)
    # the receiver
    if not env["open"] and not env["approvals"]:
        return "accept", None
    opts, trust, now, kb = rec["options"], rec["trust"], pv.epoch(rec["options"]["now"]), env["kb"]
    cnf = env["open"]["body"]["cnf"] if env["open"] else f"agent:{env['sender']}"
    if not signed_by(cnf, _bytes(kb["body"]), kb["sig"]):
        return "reject", "cnf"
    if kb["body"]["aud"] != opts["me"]:
        return "reject", "aud"
    if abs(now - pv.epoch(kb["body"]["iat"])) > WINDOW:
        return "reject", "iat"
    if (env["sender"], kb["body"]["nonce"]) in state:
        return "reject", "nonce"
    if env["open"]:
        if not _trusted(env["open"], None, model, trust):
            return "reject", "open mandate signer"
        if not _authorizes(env["open"]["body"], msg, now):
            return "reject", "open mandate"
    doc = {pv.schema_ref(d): d for d in rec["schemas"]}.get(msg["intent"]["type"]) or {}
    for person, ms in env["approvals"]:
        for m in ms:
            if not _trusted(m, person, model, trust):
                return "reject", "checkout signer"
            co = m["body"]["checkout"]
            if co is not None and doc.get("tool", co["tool"]) != co["tool"]:
                return "reject", "checkout"
            if co is None or co["args"] is None:
                return "reject", "checkout not disclosed"
            if co["tool"] == "pcm.grant":
                a = co["args"]
                if not (isinstance(a, dict) and a.get("subject") == env["sender"] and _authorizes(a, msg, now)):
                    return "reject", "open mandate"
            elif co["args"] != msg["intent"]["args"]:
                return "reject", "checkout"
    state.add((env["sender"], kb["body"]["nonce"]))
    return "accept", None


RECEIVERS = {
    "a2a-card": a2a_card,
    "uagents": uagents,
    "rfc9421": rfc9421,
    "ap2": functools.partial(mandates, model="ap2"),
    "vi": functools.partial(mandates, model="vi"),
    "scitt": scitt,
}


def rows(world, rec):
    """One row per receiver for a dataset record: its verdict and, for a reject, the first check that failed. Each
    receiver starts fresh and first takes the messages the record says it saw before (L11)."""
    msg, out = parse(rec), []
    body = rec["wire"] if rec.get("wire") is not None else json.dumps(rec["message"], ensure_ascii=False)
    for name, fn in RECEIVERS.items():
        state = set()
        try:
            for m in (rec["options"].get("replay") or {}).get("seen", []):
                fn(world, m, json.dumps(m, ensure_ascii=False), rec, state)
            verdict, reason = fn(world, msg, body, rec, state) if msg is not None else ("reject", "unreadable")
        except Exception as e:   # every message gets a verdict; this receiver raised
            verdict, reason = "reject", f"error:{type(e).__name__}: {e}"[:200]
        out.append({"id": rec["id"], "verifier": name, "verdict": verdict, "reason": reason})
    return out
