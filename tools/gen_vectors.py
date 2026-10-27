"""Write the PCM 0.1 test vectors (vectors/<name>.json and vectors/index.json) from Tracekit, the reference
implementation. A real Tracekit signer runs in-process in a temp dir and signs every message and grant; each vector's
`expected` is what tracekit.pcm.verify returns for its input. A case the signer refuses to make is a valid output
edited, and re-signed with the test log key only where the case needs a valid signature; its description says so.

    cd <this repo> && PYTHONPATH=<tracekit checkout> python tools/gen_vectors.py

The log, other-log and witness keys come from a fixed seed, so trust is the same on every run. Run ids, message ids,
nonces and timestamps come from the signer's clock and randomness, so they and the signatures change on every run."""
import glob
import hashlib
import itertools
import json
import os
import shutil
import tempfile
import time
from unittest import mock

from tracekit import pcm
from tracekit.crypto import public_from_secret
from tracekit.format import checkpoint
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.pcm.claims import placed
from tracekit.policy2.engine import Engine
from tracekit.signer import logkey, service as svc
from tracekit.signer.rpc_schema import REQUESTS

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vectors")
A, B, M, ALICE, CAROL = (CallerIdentity("uid", u, True) for u in ("990101", "990102", "990107", "990001", "990008"))
C = "uid:990103"
GW = CallerIdentity("mtls", "spiffe://example/executor", True)   # a tool executor: its results are T2
SUITE = "pytest -q tests/test_refund.py"
FIELDS = {"amount": {"type": "money", "currency": "USD", "max": 1000000},
          "order": {"type": "int", "min": 1, "max": 999999999}}
DOC = {"pcm_schema": 0, "name": "refund.request", "fields": FIELDS, "claims": ["approved_by"], "grant": True}
QUOTE = {"pcm_schema": 0, "name": "refund.quote", "fields": FIELDS}   # no grant, no claims: one cause per vector
PASSED = {"pcm_schema": 0, "name": "refund.passed", "fields": FIELDS, "grant": True}   # for delegated grants
ARGS = {"amount": 12000, "order": 81}


def cv(field, op, value):
    return {"field": field, "op": op, "value": value}


CAVEATS = [cv("amount", "<=", 20000), cv("order", "==", 81)]
NARROWER = [cv("amount", "<=", 15000), cv("order", "==", 81)]


def seed(label):
    return hashlib.sha256(f"pcm 0.1 test vectors: {label}".encode()).digest()


LOG, OTHER = logkey.FileKey(seed("log")), logkey.FileKey(seed("other log"))
WITNESS = {"name": "example.com/pcm-test-witness", "vkey": checkpoint.vkey(
    "example.com/pcm-test-witness", checkpoint.COSIGNATURE, public_from_secret(seed("witness")))}


class Signer:
    """A Tracekit signer in a temp dir: alice approves, the executor GW runs tools; M and carol are in tenant acme."""

    def __init__(self, origin, key):
        self.dir = tempfile.mkdtemp(prefix="pcm-vec-", dir="/tmp" if os.path.isdir("/tmp") else None)
        self.ids = itertools.count()
        self.s = svc.SignerService(
            self.dir, policy=Engine({"ask": [{"id": "PCM-GRANT", "tool": "pcm.grant", "pattern": "^"}]}),
            approvals={"approvers": ["uid:990001", "uid:990008"],
                       "persons": {"uid:990001": "alice", "uid:990008": "carol"}}, origin=origin, log_key=key,
            gateways=[f"mtls:{GW.subject}"], authorize={f"mtls:{GW.subject}": ["decide", "complete"]},
            tenants={"uid:990107": "acme", "uid:990008": "acme"}, fsck_every_s=0)
        self.vkey = self.s.vkey

    def call(self, who, method, **req):
        if "request_id" in REQUESTS[method]["properties"]:
            req = {"request_id": f"r{next(self.ids)}", **req}
        return self.s.call(who, method, req)

    def close(self):
        self.s.close()
        shutil.rmtree(self.dir, ignore_errors=True)


class Run:
    def __init__(self, signer, who):
        self.signer, self.who, self.seqs, self.gw = signer, who, itertools.count(), itertools.count()
        r = signer.call(who, "register_run", agent={"name": "agent"})
        self.creds = {"run_id": r["run_id"], "run_token": r["run_token"]}
        self.agent = f"{who.scheme}:{who.subject}"
        self.frm = {"agent": self.agent, "run": r["run_id"], "tenant": r["tenant"]}

    def call(self, method, who=None, **req):
        return self.signer.call(who or self.who, method, **self.creds, **req)

    def ran(self, tool, args, t2=True):
        """(decision run_seq, result run_seq) of a call of `tool` that succeeded: run by the executor (T2), else
        reported by the agent's own process (T1)."""
        tcid = f"call-{next(self.signer.ids)}"
        who, via, seqs = (GW, {"stream": "gw", "caller": self.agent}, self.gw) if t2 else (self.who, {"stream": "s"},
                                                                                         self.seqs)
        d = self.call("decide", who, client_seq=next(seqs), tool_call_id=tcid, tool=tool, args_source="parsed",
                      args=args, **via)
        r = self.call("complete", who, client_seq=next(seqs), tool_call_id=tcid, decision_id=d["decision_id"],
                      args_digest=event_hash({"tool": tool, "args": args}), status="ok", **via)
        return d["run_seq"], r["run_seq"]

    def grant(self, tcid, intent, subject=None, delegable=False, expires_s=3600, approver=ALICE):
        """(root grant `approver` approved, run_seq of her approval), as the SDK's pcm_grant makes it."""
        args = {"subject": subject or self.agent, "intent": intent, "caveats": CAVEATS,
                "expires_at": svc._iso(time.time() + expires_s), "delegable": delegable}
        d = self.call("decide", stream="s", client_seq=next(self.seqs), tool_call_id=tcid, tool="pcm.grant",
                      args_source="parsed", args=args)
        aid = self.call("approval_request", tool_call_id=tcid)["approval_id"]
        self.signer.call(approver, "approval_decide", approval_id=aid, decision="approve")
        self.call("approval_consume", tool_call_id=tcid, tool="pcm.grant", args_source="parsed", args=args)
        grant = self.call("pcm_grant", tool_call_id=tcid, args=args)["grant"]
        self.call("complete", stream="s", client_seq=next(self.seqs), tool_call_id=tcid, decision_id=d["decision_id"],
                  args_digest=event_hash({"tool": "pcm.grant", "args": args}), status="ok",
                  result={"grant": event_hash(grant)})
        seq = next(e["run_seq"] for e in self.call("read", limit=1000)["events"]
                   if e["type"] == "approval" and e["data"]["tool_use_id"] == tcid)
        return grant, seq

    def evidence(self, seqs, opened=None):
        """Evidence of records `seqs` under a fresh checkpoint; `opened` {decision run_seq: its args}."""
        self.signer.s.checkpoint()
        out, opened = self.call("pcm_evidence", run_seqs=seqs), opened or {}
        assert not out["pending"], out
        return {"checkpoint": out["checkpoint"], "records": [
            {**{k: r[k] for k in ("event", "hash", "proof")},
             **({"salt": r["salt"], "args": opened[r["run_seq"]]} if r["run_seq"] in opened else {})}
            for r in out["records"]]}

    def send(self, to, intent, args=ARGS, claims=(), grants=()):
        body = {"from": self.frm, "to": {"agent": to}, "intent": {"type": intent, "args": args},
                **({"claims": list(claims)} if claims else {}), **({"grants": list(grants)} if grants else {})}
        return self.call("pcm_sign", message=body)["message"]


def at(msg, dt):
    return svc._iso(pcm._epoch(msg["ts"]) + dt)


def fresh(msg, seen=()):
    """Replay state of a receiver that started a minute before `msg` was signed."""
    return {"window_s": 300, "started": at(msg, -60), "per_sender": 4096, "seen": list(seen)}


def check(inp):
    """What tracekit.pcm.verify returns for a vector's input: the `seen` messages go first through the same receiver."""
    assert inp["tools"] == placed(), "tracekit.pcm.verify places tools with its own table"
    o, now, rp = inp["options"], pcm._epoch(inp["options"]["now"]), inp["options"]["replay"]
    r = rp and pcm.Replay(rp["window_s"], rp["per_sender"], now=pcm._epoch(rp["started"]))
    for m in (rp or {}).get("seen", []):
        pcm.verify(m, inp["trust"], inp["schemas"], replay=r, me=o["me"], strict=o["strict"], now=now)
    return pcm.verify(inp["message"], inp["trust"], inp["schemas"], replay=r, me=o["me"], strict=o["strict"], now=now)


def build():
    """[(name, description, input, the reason text the verdict must give)]."""
    s, s2 = Signer("example.com/pcm-test-log", LOG), Signer("example.com/pcm-other-log", OTHER)
    try:
        return cases(s, s2)
    finally:
        s.close()
        s2.close()


def cases(s, s2):
    out = []
    trust = {"logs": [s.vkey], "witnesses": [], "witnesses_required": 0}

    def vector(name, description, msg, schemas, want="", trust=trust, me="uid:990102", strict=False, replay=None,
               now=None):
        out.append((name, description, {
            "message": msg, "schemas": schemas, "trust": trust, "tools": placed(),
            "options": {"me": me, "strict": strict, "now": now or at(msg, 1), "replay": replay}}, want))

    def resign(obj, purpose, **changes):
        return pcm.sign(LOG, s.vkey, purpose, {**{k: v for k, v in obj.items() if k != "sig"}, **changes})

    ref, qref, pref = (pcm.schema_ref(d) for d in (DOC, QUOTE, PASSED))
    a, b = Run(s, A), Run(s, B)
    root, seq = a.grant("grant-1", ref)
    ev = a.evidence([seq])
    approved = {"type": "approved_by", "args": {"person": "alice", "call": "grant-1"}, "evidence": ev}
    tp = {"type": "tests_passed", "args": {"suite": SUITE}}

    def ran(tool, command, t2=True):
        d, r = a.ran(tool, {"command": command}, t2)
        return {"type": "tests_passed", "args": {"suite": command},
                "evidence": a.evidence([d, r], {d: {"command": command}})}

    # accept and accept-unproven
    m = a.send("uid:990102", ref, claims=[approved], grants=[root])
    vector("accept-approved-by", "A refund request under alice's root grant, with an approved_by claim her approval "
           "record proves; replay checked.", m, [DOC], replay=fresh(m))
    m = a.send("uid:990102", ref, claims=[approved, ran("Bash", SUITE)], grants=[root])
    vector("accept-tests-passed-t2", "The accept message plus tests_passed proven by a result the tool executor wrote "
           "(T2).", m, [DOC])
    m = a.send("uid:990102", ref, claims=[approved, tp], grants=[root])
    vector("accept-unproven-no-evidence", "The accept message plus a tests_passed claim with no evidence.", m, [DOC],
           "tests_passed: unproven (no evidence)")
    m = a.send("uid:990102", ref, claims=[approved, ran("Bash", SUITE, t2=False)], grants=[root])
    vector("accept-unproven-t1-result", "tests_passed whose only result is the agent's own report (T1).", m, [DOC],
           "the agent's own report (T1)")
    m = a.send("uid:990102", ref, claims=[approved, ran("mcp:ci/run", SUITE)], grants=[root])
    vector("accept-unproven-unplaced-tool", "tests_passed run by the executor through mcp:ci/run, a tool the "
           "placement table does not list as shell.", m, [DOC], "can't place as a shell tool")
    m = a.send("uid:990102", ref, claims=[{"type": "approved_by", "args": approved["args"]}], grants=[root])
    vector("reject-strict-required-unproven", "strict: the schema requires approved_by and the claim has no "
           "evidence.", m, [DOC], "approved_by: required, not proven", strict=True)

    # envelope, signature, schema, replay, recipient: a refund.quote, which needs no grant or claim
    q = a.send("uid:990102", qref)
    vector("reject-envelope-extra-field", "A field the envelope does not have, added after signing.",
           {**q, "extra": 1}, [QUOTE], "unexpected field 'extra'")
    vector("reject-envelope-pcm-false", "pcm set to false after signing: it must be the integer 0.",
           {**q, "pcm": False}, [QUOTE], "$.pcm: expected integer")
    vector("reject-forged-signature", "amount changed after signing, signature kept.",
           {**q, "intent": {"type": qref, "args": {**ARGS, "amount": 15000}}}, [QUOTE], "bad signature")
    vector("reject-unpinned-key", "A valid message; trust pins only another log's key.", q, [QUOTE],
           "a key trust.json does not pin", trust=dict(trust, logs=[s2.vkey]))
    vector("reject-grant-signature-as-message", "The message body signed for the grant purpose (pcm.grant.v0) with "
           "the test log key, offline.", resign(q, "pcm-grant"), [QUOTE], "bad signature")
    vector("reject-unknown-schema", "A valid refund.quote; the receiver has only the refund.request schema.", q, [DOC],
           "unknown schema")
    for name, args, what in (("extra-field", {**ARGS, "note": "rush"}, "an arg the schema does not list"),
                             ("int-as-string", {**ARGS, "order": "81"}, 'order as the string "81"'),
                             ("bool-as-int", {**ARGS, "order": True}, "order as true, a bool for an int field"),
                             ("money-over-max", {**ARGS, "amount": 1000001}, "amount 1000001, over the max 1000000")):
        vector(f"reject-schema-{name}", f"Args with {what}.", a.send("uid:990102", qref, args), [QUOTE],
               "schema: args.")
    vector("reject-replay-duplicate-nonce", "The receiver already took this message: its nonce was seen.", q, [QUOTE],
           "replayed: this nonce was seen before", replay=fresh(q, [q]))
    vector("reject-replay-outside-window", "Checked 600 s after it was signed, with a 300 s window.", q, [QUOTE],
           "more than 300 s", replay=fresh(q), now=at(q, 600))
    vector("reject-replay-before-started", "Signed 1 s before the receiver started.", q, [QUOTE],
           "sent before this receiver started", replay=dict(fresh(q), started=at(q, 1)), now=at(q, 2))
    vector("reject-wrong-recipient", "Addressed to uid:990102, checked by uid:990103.", q, [QUOTE],
           "addressed to uid:990102, not uid:990103", me=C)

    # grants
    m = a.send("uid:990102", ref, {**ARGS, "amount": 50000}, [approved], [root])
    vector("reject-grant-amount-over-caveat", "amount 50000 under a grant of amount <= 20000.", m, [DOC],
           "amount 50000 breaks amount <= 20000")
    short, _ = a.grant("grant-2", ref, expires_s=3)
    time.sleep(max(0.0, pcm._epoch(short["expires_at"]) - time.time() + 0.2))
    vector("reject-grant-expired", "Signed after its root grant expired (a grant made to expire in 3 s).",
           a.send("uid:990102", ref, claims=[approved], grants=[short]), [DOC], "expired at")
    acme, _ = Run(s, M).grant("grant-acme", ref, subject=a.agent, approver=CAROL)
    vector("reject-grant-cross-tenant", "A root grant carol approved in a run of tenant acme, used by a sender in "
           "tenant default.", a.send("uid:990102", ref, claims=[approved], grants=[acme]), [DOC],
           "issued in tenant acme")
    vector("reject-grant-root-by-agent", "The root grant's issuer kind edited to agent and re-signed with the test log "
           "key (the signer issues root grants only from a person's approval).",
           a.send("uid:990102", ref, claims=[approved], grants=[resign(root, "pcm-grant", issuer={
               **root["issuer"], "kind": "agent"})]), [DOC], "must come from a person's approval")
    to_b, _ = a.grant("grant-b", ref, subject="uid:990102")
    vector("reject-grant-subject-not-sender", "A root grant for uid:990102, sent by uid:990101.",
           a.send("uid:990102", ref, claims=[approved], grants=[to_b]), [DOC], "not the sender uid:990101")

    # delegation: alice grants A (delegable), A passes B a narrower child, B asks C
    droot, _ = a.grant("grant-d", pref, delegable=True)
    child = a.call("pcm_delegate", parent=droot, subject="uid:990102", caveats=NARROWER,
                   expires_at=droot["expires_at"], delegable=False)["grant"]
    vector("accept-delegation-narrowing", "Two steps: alice's delegable grant to A (amount <= 20000), A's child to B "
           "(amount <= 15000); B asks for 12000.", b.send(C, pref, grants=[droot, child]), [PASSED], me=C)
    vector("reject-delegation-over-child-cap", "The same chain; B asks for 18000, within the root's cap but over the "
           "child's.", b.send(C, pref, {**ARGS, "amount": 18000}, grants=[droot, child]), [PASSED],
           "grant 1: amount 18000 breaks amount <= 15000", me=C)
    edited = "the signer refuses it, so it is the real child edited and re-signed with the test log key"
    for name, caveats, what in (
            ("widening-child", [cv("amount", "<=", 30000), cv("order", "==", 81)], "raises the cap to 30000"),
            ("widen-and-tighten-child", [cv("amount", "<=", 30000), cv("amount", ">=", 100), cv("order", "==", 81)],
             "raises the cap to 30000 and adds amount >= 100"),
            ("missing-caveat-child", [cv("amount", "<=", 15000)], "drops order == 81")):
        vector(f"reject-grant-{name}", f"A's child to B {what}; {edited}.",
               b.send(C, pref, grants=[droot, resign(child, "pcm-grant", caveats=caveats)]), [PASSED],
               "dropped or widened", me=C)
    nd, _ = a.grant("grant-nd", pref)
    vector("reject-grant-below-non-delegable", f"A child below alice's grant that can't be passed on; {edited} under "
           "the non-delegable root.", b.send(C, pref, grants=[nd, resign(child, "pcm-grant", parent=event_hash(nd))]),
           [PASSED], "grant 0 can't be passed on", me=C)
    other, _ = a.grant("grant-d2", pref, delegable=True)
    vector("reject-grant-broken-parent", "A real child placed under another real root, so its parent hash names "
           "another grant.", b.send(C, pref, grants=[other, child]), [PASSED], "its parent is not grant 0", me=C)

    # claims that fail
    def failed(name, description, claim, want, **kw):
        vector(f"reject-claim-{name}", description, a.send("uid:990102", ref, claims=[claim], grants=[root]), [DOC],
               want, **kw)
    rec, h = ev["records"][0], ev["records"][0]["hash"]
    failed("changed-record-hash", "approved_by whose record hash has one hex digit changed.",
           dict(approved, evidence=dict(ev, records=[dict(rec, hash=h[:-1] + ("1" if h[-1] == "0" else "0"))])),
           "hash does not match the event")
    failed("cut-proof", "approved_by whose inclusion proof lost its last hash.",
           dict(approved, evidence=dict(ev, records=[dict(rec, proof=rec["proof"][:-1])])), "not in the checkpoint")
    o = Run(s2, A)
    moved = dict(approved, evidence=dict(ev, checkpoint=o.evidence([0])["checkpoint"]))
    failed("unpinned-log-note", "approved_by under a checkpoint note of a log trust does not pin.", moved,
           "approved_by: failed (checkpoint: ")
    failed("evidence-from-another-log", "The same claim, with trust pinning both logs: the note is not of the log "
           "that signed the message.", moved, "not the one that signed the message",
           trust=dict(trust, logs=[s.vkey, s2.vkey]))
    failed("witnesses-required-unmet", "approved_by under a note with no cosignature; trust requires one witness.",
           approved, "0 pinned cosignature(s), 1 required",
           trust=dict(trust, witnesses=[WITNESS], witnesses_required=1))
    failed("wrong-person", "approved_by naming bob; the approval record is alice's.",
           dict(approved, args={"person": "bob", "call": "grant-1"}), "no approval of grant-1 by the person bob")
    failed("approval-of-another-call", "approved_by of call grant-2, with alice's approval of grant-1 as evidence.",
           dict(approved, args={"person": "alice", "call": "grant-2"}), "no approval of grant-2")
    failed("pytest-or-true", "tests_passed of `pytest ... || true`, run by the executor (T2): its status is not the "
           "tests'.", ran("Bash", SUITE + " || true"), "is not a single test command")
    return out


def verdict_of(name):
    return next(v for v in ("accept-unproven", "accept", "reject") if name.startswith(v + "-"))


def main():
    with mock.patch.object(svc, "CHECKPOINT_S", 3600.0):   # checkpoints only when a case asks for one
        built = build()
    os.makedirs(OUT, exist_ok=True)
    for path in glob.glob(os.path.join(OUT, "*.json")):
        os.remove(path)
    index = []
    for name, description, inp, want in built:
        inp = json.loads(json.dumps(inp))   # exactly what the file holds
        expected = check(inp)
        assert expected["verdict"] == verdict_of(name), (name, expected)
        assert want in "; ".join(expected["reasons"]), (name, want, expected["reasons"])
        with open(os.path.join(OUT, f"{name}.json"), "w", encoding="utf-8") as f:
            f.write(json.dumps({"name": name, "description": description, "input": inp, "expected": expected},
                               indent=2, ensure_ascii=False) + "\n")
        index.append({"name": name, "file": f"{name}.json", "description": description, "verdict": expected["verdict"]})
    with open(os.path.join(OUT, "index.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(index, indent=2, ensure_ascii=False) + "\n")
    for v in index:
        print(f"{v['verdict']:<16} {v['name']}")


if __name__ == "__main__":
    main()
