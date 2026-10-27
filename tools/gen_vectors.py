"""Write the PCM 0.1 test vectors (vectors/<name>.json and vectors/index.json) from Tracekit, the reference
implementation. A real Tracekit signer runs in-process in a temp dir and signs every message and grant; each vector's
`expected` is what tracekit.pcm.verify returns for its input. A case the signer refuses to make is a valid output
edited, and re-signed with the test log key only where the case needs a valid signature; its description says so.

    cd <this repo> && PYTHONPATH=<tracekit checkout> python tools/gen_vectors.py

The log, other-log and witness keys come from a fixed seed, so trust is the same on every run. Run ids, message ids,
nonces and timestamps come from the signer's clock and randomness, so they and the signatures change on every run."""
import base64
import glob
import hashlib
import itertools
import json
import os
import shutil
import tempfile
import time
from unittest import mock

from tracekit import merkle, pcm
from tracekit.crypto import public_from_secret
from tracekit.format import checkpoint
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.pcm.claims import placed
from tracekit.policy2.engine import Engine
from tracekit.signer import logkey, service as svc
from tracekit.signer.rpc_schema import REQUESTS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "vectors")
with open(os.path.join(ROOT, "registry", "tools.json"), encoding="utf-8") as _f:
    TOOLS = json.load(_f)   # PCM 0.1's frozen tool placement table (SPEC 10.2), every vector's `tools`
A, B, M, ALICE, CAROL, DAVE, ERIN, ERIN_AGENT, EGRESS, SENSOR = (CallerIdentity("uid", u, True) for u in (
    "990101", "990102", "990107", "990001", "990008", "990009", "990010", "990011", "990200", "990201"))
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


ORIGIN = "example.com/pcm-test-log"
LOG, OTHER = logkey.FileKey(seed("log")), logkey.FileKey(seed("other log"))
WITNESS = {"name": "example.com/pcm-test-witness", "vkey": checkpoint.vkey(
    "example.com/pcm-test-witness", checkpoint.COSIGNATURE, public_from_secret(seed("witness")))}
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def loose(text):
    """Base64 `text` with the lowest unused bit of its last character set: the same bytes, not canonical."""
    i = len(text.rstrip("=")) - 1
    return text[:i] + B64[B64.index(text[i]) ^ 1] + text[i + 1:]


class Signer:
    """A Tracekit signer in a temp dir: alice approves, and so does uid:990009, whom no person maps to; erin may
    approve her own agent's calls (self_approval: allow); the policy asks a person about pcm.grant, pay and read_file
    calls and denies a Bash call of tests/test_denied.py; the executor GW runs tools; an egress observer and a Tetragon
    import report effects; M and carol are in tenant acme."""

    def __init__(self, origin, key):
        self.dir = tempfile.mkdtemp(prefix="pcm-vec-")
        self.ids = itertools.count()
        self.s = svc.SignerService(
            self.dir, policy=Engine({"ask": [{"id": "PCM-GRANT", "tool": "pcm.grant", "pattern": "^"},
                                             {"id": "PAY", "tool": "pay", "pattern": "^"},
                                             {"id": "READ", "tool": "read_file", "pattern": "^"}],
                                     "deny": [{"id": "NO-DENIED", "tool": "Bash", "pattern": "test_denied"}]}),
            approvals={"approvers": ["uid:990001", "uid:990008", "uid:990009", "uid:990010"], "self_approval": "allow",
                       "persons": {"uid:990001": "alice", "uid:990008": "carol", "uid:990010": "erin",
                                   "uid:990011": "erin"}}, origin=origin, log_key=key,
            gateways=[f"mtls:{GW.subject}"],
            authorize={f"mtls:{GW.subject}": ["decide", "complete"], "uid:990200": ["observe_effect"],
                       "uid:990201": ["observe_effect"]},
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
    def __init__(self, signer, who, run_id=None):
        """A run of `who`; `run_id`: the id the client picks (run ids are the client's, unique per log and tenant)."""
        self.signer, self.who, self.seqs, self.gw = signer, who, itertools.count(), itertools.count()
        r = signer.call(who, "register_run", agent={"name": "agent"}, **({"run_id": run_id} if run_id else {}))
        self.creds = {"run_id": r["run_id"], "run_token": r["run_token"]}
        self.agent = f"{who.scheme}:{who.subject}"
        self.frm = {"agent": self.agent, "run": r["run_id"], "tenant": r["tenant"]}

    def call(self, method, who=None, **req):
        return self.signer.call(who or self.who, method, **self.creds, **req)

    def ran(self, tool, args, t2=True, status="ok"):
        """(decision run_seq, result run_seq) of a call of `tool` that ended with `status`: run by the executor (T2),
        else reported by the agent's own process (T1)."""
        tcid = f"call-{next(self.signer.ids)}"
        who, via, seqs = (GW, {"stream": "gw", "caller": self.agent}, self.gw) if t2 else (self.who, {"stream": "s"},
                                                                                         self.seqs)
        d = self.call("decide", who, client_seq=next(seqs), tool_call_id=tcid, tool=tool, args_source="parsed",
                      args=args, **via)
        r = self.call("complete", who, client_seq=next(seqs), tool_call_id=tcid, decision_id=d["decision_id"],
                      args_digest=event_hash({"tool": tool, "args": args}), status=status, **via)
        return d["run_seq"], r["run_seq"]

    def effect(self):
        """run_seq of the run's latest effect.observed."""
        return [e["run_seq"] for e in self.call("read", limit=1000)["events"] if e["type"] == "effect.observed"][-1]

    def observed(self, host, connections=1):
        """run_seq of the effect.observed an egress observer reports: a minute of the run's traffic to `host`, with
        `connections` connections opened (0: the connect failed, so no byte went either way)."""
        ts, n = svc._iso(time.time()), 512 * bool(connections)
        self.signer.call(EGRESS, "observe_effect", instance="egress-1", effects=[
            {"kind": "net", "host": host, "port": 443, "bytes_out": n, "bytes_in": 4 * n, "connections": connections,
             "first_ts": ts, "last_ts": ts, **self.creds}])
        return self.effect()

    def sensed(self, host, **kw):
        """run_seq of the effect.observed a Tetragon import reports: a process of the run called connect to `host`."""
        self.signer.call(SENSOR, "observe_effect", instance="sensor-1", sensor="tetragon", callers=[self.agent],
                         effects=[{"kind": "connect", "ts": svc._iso(time.time()), "pid": 7,
                                   "binary": "/usr/bin/curl", "host": host, "port": 443, **self.creds, **kw}])
        return self.effect()

    def approval(self, tcid):
        """run_seqs of call `tcid`'s latest approval's policy.decision, approval.request and approval: what was
        approved, the request that names it and the answer (SPEC 6.6 approved_by)."""
        recs = self.call("read", limit=1000)["events"]
        a = [x for x in recs if x["type"] == "approval" and x["data"]["tool_use_id"] == tcid][-1]
        r = next(x for x in recs if x["type"] == "approval.request"
                 and x["data"]["approval_id"] == a["data"]["approval_id"])
        d = next(x for x in recs if x["type"] == "policy.decision"
                 and x["data"].get("decision_id") == r["data"]["decision_id"])
        return [d["run_seq"], r["run_seq"], a["run_seq"]]

    def approve(self, tcid, args, approver):
        """(decision, run_seqs of its decision, request and approval) of a pcm.grant call of `args` that `approver`
        approved."""
        d = self.call("decide", stream="s", client_seq=next(self.seqs), tool_call_id=tcid, tool="pcm.grant",
                      args_source="parsed", args=args)
        aid = self.call("approval_request", tool_call_id=tcid)["approval_id"]
        self.signer.call(approver, "approval_decide", approval_id=aid, decision="approve")
        return d, self.approval(tcid)

    def grant(self, tcid, intent, subject=None, delegable=False, expires_s=3600, approver=ALICE, caveats=CAVEATS):
        """(root grant `approver` approved, run_seqs of its decision, request and approval), as the SDK's pcm_grant
        makes it."""
        args = {"subject": subject or self.agent, "intent": intent, "caveats": caveats,
                "expires_at": svc._iso(time.time() + expires_s), "delegable": delegable}
        d, seqs = self.approve(tcid, args, approver)
        self.call("approval_consume", tool_call_id=tcid, tool="pcm.grant", args_source="parsed", args=args)
        grant = self.call("pcm_grant", tool_call_id=tcid, args=args)["grant"]
        self.call("complete", stream="s", client_seq=next(self.seqs), tool_call_id=tcid, decision_id=d["decision_id"],
                  args_digest=event_hash({"tool": "pcm.grant", "args": args}), status="ok",
                  result={"grant": event_hash(grant)})
        return grant, seqs

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
    assert inp["tools"] == placed(), "registry/tools.json is not tracekit's PCM 0.1 table (tracekit/pcm/tools.json)"
    o, now, rp = inp["options"], pcm._epoch(inp["options"]["now"]), inp["options"]["replay"]
    r = rp and pcm.Replay(rp["window_s"], rp["per_sender"], now=pcm._epoch(rp["started"]))
    for m in (rp or {}).get("seen", []):
        pcm.verify(m, inp["trust"], inp["schemas"], replay=r, me=o["me"], strict=o["strict"], now=now)
    return pcm.verify(inp["message"], inp["trust"], inp["schemas"], replay=r, me=o["me"], strict=o["strict"], now=now)


def build():
    """[(name, description, input, the reason text the verdict must give)]."""
    s, s2 = Signer(ORIGIN, LOG), Signer("example.com/pcm-other-log", OTHER)
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
            "message": msg, "schemas": schemas, "trust": trust, "tools": TOOLS,
            "options": {"me": me, "strict": strict, "now": now or at(msg, 1), "replay": replay}}, want))

    def resign(obj, purpose, **changes):
        return pcm.sign(LOG, s.vkey, purpose, {**{k: v for k, v in obj.items() if k != "sig"}, **changes})

    ref, qref, pref = (pcm.schema_ref(d) for d in (DOC, QUOTE, PASSED))
    a, b = Run(s, A), Run(s, B)
    root, seqs = a.grant("grant-1", ref)
    ev = a.evidence(seqs)   # the pcm.grant decision, the approval.request that names it, alice's approval
    approved = {"type": "approved_by", "args": {"person": "alice", "call": "grant-1"}, "evidence": ev}
    tp = {"type": "tests_passed", "args": {"suite": SUITE}}

    def call(tool, args, t2=True, status="ok"):
        """Evidence of one call: its opened decision and its result."""
        d, r = a.ran(tool, args, t2, status)
        return a.evidence([d, r], {d: args})

    def ran(tool, command, t2=True, status="ok"):
        return {"type": "tests_passed", "args": {"suite": command},
                "evidence": call(tool, {"command": command}, t2, status)}

    # accept and accept-unproven
    m = a.send("uid:990102", ref, claims=[approved], grants=[root])
    vector("accept-approved-by", "A refund request under alice's root grant, with an approved_by claim proven by her "
           "approval, the approval.request it answers and the pcm.grant decision that request names; replay "
           "checked.", m, [DOC], replay=fresh(m))
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
    vector("reject-replay-no-real-time", "ts set to month 13 and re-signed with the test log key (the signer takes ts "
           "from its clock): the TS pattern lets it through, the replay check refuses it.",
           resign(q, "pcm", ts=q["ts"][:5] + "13" + q["ts"][7:]), [QUOTE], "which is no real time",
           replay=fresh(q), now=at(q, 1))

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
    rec, h, rest = ev["records"][0], ev["records"][0]["hash"], ev["records"][1:]
    failed("changed-record-hash", "approved_by whose first record's hash has one hex digit changed.",
           dict(approved, evidence=dict(ev, records=[dict(rec, hash=h[:-1] + ("1" if h[-1] == "0" else "0"))] + rest)),
           "hash does not match the event")
    failed("cut-proof", "approved_by whose first record's inclusion proof lost its last hash.",
           dict(approved, evidence=dict(ev, records=[dict(rec, proof=rec["proof"][:-1])] + rest)),
           "not in the checkpoint")
    o = Run(s2, A)
    moved = dict(approved, evidence=dict(ev, checkpoint=o.evidence([0])["checkpoint"]))
    failed("unpinned-log-note", "approved_by under a checkpoint note of a log trust does not pin.", moved,
           "approved_by: failed (checkpoint: ")
    failed("evidence-from-another-log", "The same claim, with trust pinning both logs: the note is not of the log "
           "that signed the message.", moved, "not the one that signed the message",
           trust=dict(trust, logs=[s.vkey, s2.vkey]))
    vector("reject-grant-from-another-log", "A root grant alice approved on the other log, for uid:990101 there, sent "
           "by uid:990101 of the test log; trust pins both logs. Identities are names inside one log: the grant is not "
           "this sender's.", a.send("uid:990102", ref, claims=[approved], grants=[o.grant("grant-o", ref)[0]]), [DOC],
           "not the log that signed the message", trust=dict(trust, logs=[s.vkey, s2.vkey]))
    twin = o.send("uid:990102", qref)
    twin = pcm.sign(OTHER, s2.vkey, "pcm", {**{k: v for k, v in twin.items() if k != "sig"}, "nonce": q["nonce"]})
    vector("accept-replay-same-agent-other-log", "The receiver first took a message from uid:990101 of the other log "
           "with the nonce of this one (re-signed with the other log's test key); trust pins both logs. A sender is "
           "the pair (log key, agent), so uid:990101 of the test log is another sender and its nonce is new.", q,
           [QUOTE], trust=dict(trust, logs=[s.vkey, s2.vkey]), replay=fresh(q, [twin]))
    failed("proof-non-canonical-base64", "approved_by whose first record's first proof entry has an unused bit of its "
           "last base64 character set: the same 32 bytes, but only canonical base64 is taken.",
           dict(approved, evidence=dict(ev, records=[dict(rec, proof=[loose(rec["proof"][0])] + rec["proof"][1:])]
                                        + rest)), "not in the checkpoint")
    failed("witnesses-required-unmet", "approved_by under a note with no cosignature; trust requires one witness.",
           approved, "0 pinned cosignature(s), 1 required",
           trust=dict(trust, witnesses=[WITNESS], witnesses_required=1))
    failed("wrong-person", "approved_by naming bob; the approval record is alice's.",
           dict(approved, args={"person": "bob", "call": "grant-1"}), "no approval of grant-1 by the person bob")
    failed("approval-of-another-call", "approved_by of call grant-2, with alice's approval of grant-1 as evidence.",
           dict(approved, args={"person": "alice", "call": "grant-2"}), "no approval of grant-2")
    failed("pytest-or-true", "tests_passed of `pytest ... || true`, run by the executor (T2): its status is not the "
           "tests'.", ran("Bash", SUITE + " || true"), "is not a single test command")
    _, dseqs = a.approve("grant-dave", {"subject": a.agent, "intent": ref, "caveats": CAVEATS,
                                        "expires_at": root["expires_at"], "delegable": False}, DAVE)
    failed("approved-by-unmapped-identity", "approved_by naming uid:990009, an approver no person in the signer's "
           "approvals configuration maps to, with its approval, request and decision as evidence: only a person's name "
           "proves it.", {"type": "approved_by", "args": {"person": "uid:990009", "call": "grant-dave"},
                          "evidence": a.evidence(dseqs)}, "no approval of grant-dave by the person uid:990009")
    failed("approved-by-without-decision", "approved_by whose evidence holds alice's approval and the approval.request "
           "it answers, but not the policy.decision the request names: the call id is the agent's own name for the "
           "call, so without its decision nothing says what was approved.",
           dict(approved, evidence=a.evidence(seqs[1:])), "holds no decision of the call it approved")
    pay = a.call("decide", stream="s", client_seq=next(a.seqs), tool_call_id="pay-1", tool="pay",
                 args_source="parsed", args={"amount": 50000, "order": 81})
    a.call("decide", stream="s", client_seq=next(a.seqs), tool_call_id="pay-1", tool="read_file",
           args_source="parsed", args={"path": "/etc/motd"})
    s.call(ALICE, "approval_decide", approval_id=a.call("approval_request", tool_call_id="pay-1")["approval_id"],
           decision="approve")
    _, preq, papp = a.approval("pay-1")
    failed("approved-by-other-decision", "approved_by of call pay-1, which the agent decided twice: a pay of 50000, "
           "then a read_file of /etc/motd. alice approved the read_file (the approval.request names its decision), and "
           "the evidence holds the pay decision with that request and approval: an approval is of the decision its "
           "request names, not of every decision of the call id.",
           {"type": "approved_by", "args": {"person": "alice", "call": "pay-1"},
            "evidence": a.evidence([pay["run_seq"], preq, papp])}, "holds no decision of the call it approved")
    er = Run(s, ERIN_AGENT)
    _, eseqs = er.approve("grant-erin", {"subject": er.agent, "intent": ref, "caveats": CAVEATS,
                                         "expires_at": root["expires_at"], "delegable": False}, ERIN)
    vector("reject-claim-approved-by-self-approval", "approved_by erin, sent by her own agent's run (uid:990011, which "
           "the approvals configuration maps to erin too), with her approval of its call, the request and the decision "
           "as evidence; the signer allows self-approval, so it recorded the answer with self_approved true: a person "
           "approving her own agent's call is no independent approval.",
           er.send("uid:990102", qref, claims=[{"type": "approved_by", "args": {"person": "erin", "call": "grant-erin"},
                                                "evidence": er.evidence(eseqs)}]), [QUOTE],
           "no approval of grant-erin by the person erin")
    vector("reject-claim-evidence-from-another-run", "approved_by with alice's approval records as evidence, sent by "
           "another run of the same agent: evidence must come from the sender's own run.",
           Run(s, A).send("uid:990102", qref, claims=[approved]), [QUOTE], "not the sender's")
    vector("reject-claim-evidence-from-another-tenant", "approved_by with alice's approval records as evidence, sent by "
           "uid:990107 of tenant acme from a run it registered under the run id of A's run (a client picks its run "
           "id): the records are of tenant default, so they are not the sender's.",
           Run(s, M, run_id=a.frm["run"]).send("uid:990102", qref, claims=[approved]), [QUOTE], "not the sender's")
    note = ev["checkpoint"]
    text = note[:note.find("\n\n") + 1]
    vector("accept-witnessed", "approved_by under a note cosigned by the pinned witness; trust requires one witness.",
           a.send("uid:990102", ref, claims=[dict(approved, evidence=dict(ev, checkpoint=note + checkpoint.cosign(
               text, WITNESS["name"], seed("witness"), int(time.time()))))], grants=[root]), [DOC],
           trust=dict(trust, witnesses=[WITNESS], witnesses_required=1))
    failed("malformed-unpinned-note-line", "approved_by under a note with an extra signature line of a key trust does "
           "not pin, whose signature is 3 bytes: a malformed line fails the note even when its key is not pinned.",
           dict(approved, evidence=dict(ev, checkpoint=note + "— example.com/unpinned AAAA\n")), "short signature")

    def relog(records, edit):
        """Evidence of `records` with event i edited by `edit(i, event)` and renumbered from 0, under a checkpoint the
        test log key signs offline: what a hostile pinned log can send."""
        events = [dict(edit(i, r["event"]), seq=i) for i, r in enumerate(records)]
        leaves = [merkle.leaf_hash(bytes.fromhex(event_hash(e)[7:])) for e in events]
        text = checkpoint.body(ORIGIN, len(leaves), merkle.root(leaves))
        return {"checkpoint": text + "\n" + checkpoint.sign(text, ORIGIN, seed("log")), "records": [
            {**r, "event": e, "hash": event_hash(e),
             "proof": [base64.b64encode(p).decode() for p in merkle.inclusion_proof(i, leaves)]}
            for i, (r, e) in enumerate(zip(records, events))]}

    def without(e, key):
        return dict(e, data={k: v for k, v in e["data"].items() if k != key})
    failed("record-not-an-event", "approved_by whose approval record has the number 5 as its prev_hash, which no "
           "claim checker reads, under a checkpoint the test log key signs offline over the edited record: a record "
           "that is no valid tracekit.event.v2 event fails.",
           dict(approved, evidence=relog(ev["records"], lambda i, e: dict(e, prev_hash=5))), "not a valid event")
    failed("approved-by-agent-approver", "approved_by whose evidence is alice's approval, its request and decision, "
           "with approver_kind agent added to the approval, under a checkpoint the test log key signs offline over the "
           "edited records (an honest signer writes no person on an agent approver's answer): an agent approver's "
           "answer proves no person's approval.",
           dict(approved, evidence=relog(ev["records"], lambda i, e: dict(e, data=dict(e["data"], approver_kind="agent"))
                                         if e["type"] == "approval" else e)), "no approval of grant-1 by the person alice")
    failed("witness-key-in-logs", "approved_by with trust pinning the witness's cosignature key in logs, next to the "
           "test log key: a key in logs that is no Ed25519 or hybrid log key fails the note.", approved,
           "wrong signature type", trust=dict(trust, logs=[s.vkey, WITNESS["vkey"]]))
    failed("tests-passed-malformed-no-evidence", "tests_passed of `pytest ... || true` with no evidence: a suite that "
           "is no test command is malformed, so the claim fails without evidence too.",
           {"type": "tests_passed", "args": {"suite": SUITE + " || true"}}, "is not a single test command")
    failed("file-written-relative-no-evidence", "file_written of the relative path work/report.txt with no evidence: "
           "the claim is malformed, so it fails without evidence too.",
           {"type": "file_written", "args": {"path": "work/report.txt", "digest": "sha256:" + "0" * 64}},
           "is relative")

    # claims on a refund.quote, which needs no grant or claim, so the claim is the one cause
    def claimed(name, description, claim, want=""):
        vector(name, description, a.send("uid:990102", qref, claims=[claim]), [QUOTE], want)
    claimed("reject-claim-bash-c", "tests_passed of `bash -c 'pytest || true'`, run by the executor (T2): bash is not a "
            "test runner.", ran("Bash", "bash -c 'pytest || true'"), "is not a single test command")
    for name, cmd, what in (
            ("comment", SUITE + " # || true", "a suite may hold no `#`, even where the shell reads a comment"),
            ("hash-inside-word", SUITE + "#|| true", "a `#` inside a word starts no comment, so the shell runs "
             "`|| true`"),
            ("background", SUITE + " &", "the shell runs the tests in the background and exits 0 whatever they do"),
            ("ansi-c-quote", "pytest $'\\'';true #'", "sh reads `$'\\''` as one quote and runs `true`, where Python's "
             "shlex reads one word"),
            ("unbalanced-quote", "pytest -q 'tests/test_refund.py", "its quotes don't balance"),
            ("dot-slash", "./pytest -q", "the program must be the runner's bare name, not a file of that name"),
            ("runner-path", ".venv/bin/pytest -q", "the program must be the runner's bare name")):
        claimed(f"reject-claim-tests-passed-{name}" if name != "hash-inside-word" else f"reject-claim-{name}",
                f"tests_passed of `{cmd}`, run by the executor (T2): {what}, so it is no test command.",
                ran("Bash", cmd), "is not a single test command")
    for flag in ("--co", "--collect-only", "--help", "-h", "--version", "-V", "--he"):
        claimed(f"reject-claim-tests-passed-{flag.lstrip('-')}", f"tests_passed of `pytest {flag} -q`, "
                f"run by the executor (T2): {flag} is a flag with which a runner runs no tests, or a prefix of one, so "
                "it is no test command.",
                ran("Bash", f"pytest {flag} -q"), "is not a single test command")
    claimed("reject-claim-tests-passed-wrapper", "tests_passed of `uv run pytest -q`, run by the executor (T2): a "
            "wrapper in front is not in the list of test commands.", ran("Bash", "uv run pytest -q"),
            "is not a single test command")
    claimed("accept-tests-passed-npm-test", "tests_passed of `npm test`, run by the executor (T2).",
            ran("Bash", "npm test"))
    claimed("accept-tests-passed-python-m-pytest", "tests_passed of `python3 -m pytest -q`, run by the executor (T2).",
            ran("Bash", "python3 -m pytest -q"))
    claimed("reject-claim-tests-failed", "tests_passed whose T2 result is an error.",
            ran("Bash", SUITE, status="error"), "and failed")
    claimed("reject-claim-tests-passed-denied-call", "tests_passed of `pytest -q tests/test_denied.py`, whose "
            "policy.decision is deny; the executor then reported the call ran and succeeded (T2): a denied decision "
            "matches no call.", ran("Bash", "pytest -q tests/test_denied.py"), "no call in the evidence ran")
    opened = ran("Bash", SUITE)
    dec, res = opened["evidence"]["records"]
    claimed("reject-claim-salt-without-args", "tests_passed whose decision record carries its salt but not its args.",
            dict(opened, evidence=dict(opened["evidence"], records=[
                {k: v for k, v in dec.items() if k != "args"}, res])), "do not open its decision's commitment")
    claimed("reject-claim-opening-wrong-args", "tests_passed whose opening carries other args than the decision "
            "committed to.", dict(opened, evidence=dict(opened["evidence"], records=[
                dict(dec, args={"command": SUITE + " -x"}), res])), "do not open its decision's commitment")
    claimed("reject-claim-decision-without-id", "tests_passed whose policy.decision and tool.result records both lost "
            "data.decision_id, under a checkpoint the test log key signs offline over the edited records: a decision "
            "without its id matches no call, though the two still pair by their missing ids.",
            dict(opened, evidence=relog(opened["evidence"]["records"], lambda i, e: without(e, "decision_id"))),
            "no call in the evidence ran")

    sha = "sha256:" + hashlib.sha256(b"total: 81\n").hexdigest()
    wrote = call("Write", {"file_path": "/work/report.txt", "content": "total: 81\n"})
    for name, path, digest, want, what in (
            ("accept-file-written", "/work/report.txt", sha, "", "with the SHA-256 of the content written"),
            ("reject-claim-file-written-wrong-digest", "/work/report.txt", "sha256:" + "0" * 64,
             "no call in the evidence wrote", "with another digest than the content's"),
            ("reject-claim-file-written-dotdot", "/work/../work/report.txt", sha, "has a `..`",
             "naming the path with `..`, which fails")):
        claimed(name, f"file_written of {path} by a Write of /work/report.txt the executor ran (T2), {what}.",
                {"type": "file_written", "args": {"path": path, "digest": digest}, "evidence": wrote}, want)
    claimed("reject-claim-file-written-relative", "file_written of work/report.txt by a Write of work/report.txt the "
            "executor ran (T2): the paths are equal, but a relative claim is malformed, so it fails.",
            {"type": "file_written", "args": {"path": "work/report.txt", "digest": sha},
             "evidence": call("Write", {"file_path": "work/report.txt", "content": "total: 81\n"})}, "is relative")
    claimed("accept-unproven-file-written-relative-call", "file_written of /work/report.txt by a Write of report.txt "
            "the executor ran (T2): the record doesn't hold the working directory, so the relative path may name this "
            "file or another.", {"type": "file_written", "args": {"path": "/work/report.txt", "digest": sha},
                                 "evidence": call("Write", {"file_path": "report.txt", "content": "total: 81\n"})},
            "can't tell whether")
    for name, path, written, want, what in (
            ("reject-claim-file-written-backslash", "/work/report.txt", "/work\\report.txt",
             "no call in the evidence wrote", "a path that starts with / is read by POSIX rules, where `\\` is part of "
             "a name, so the call wrote the file `work\\report.txt` in /"),
            ("accept-unproven-file-written-drive-separators", "C:\\work\\report.txt", "C:/work/report.txt",
             "can't tell whether", "the two are one file on Windows, but the record doesn't say which system ran the "
             "call, and on POSIX C:/work/report.txt is a relative path"),
            ("accept-file-written-drive-path", "C:\\work\\report.txt", "C:\\work\\report.txt", "",
             "a drive path is proven by a call of the claim's own string")):
        claimed(name, f"file_written of {path} by a Write of {written} the executor ran (T2): {what}.",
                {"type": "file_written", "args": {"path": path, "digest": sha},
                 "evidence": call("Write", {"file_path": written, "content": "total: 81\n"})}, want)
    observed = a.evidence([a.observed("api.example.com")])
    claimed("accept-reached-host-observed", "reached_host proven by the effect.observed record an egress observer "
            "reported to the signer: a minute with one connection to the host.",
            {"type": "reached_host", "args": {"host": "api.example.com"}, "evidence": observed})
    for name, seq, want, what in (
            ("accept-unproven-reached-host-no-connection", a.observed("api.example.com", connections=0),
             "saw no connection to", "an egress observer's minute of the run's traffic to the host with connections 0 "
             "(its connect failed): the run tried the host, nothing says it reached it"),
            ("accept-unproven-reached-host-sensor-connect", a.sensed("api.example.com"), "an attempt",
             "a kernel sensor's (Tetragon's) record that a process of the run called connect to the host: the attempt, "
             "not an opened connection"),
            ("reject-claim-reached-host-denied-connect", a.sensed("api.example.com", denied=True),
             "no call in the evidence", "a kernel sensor import's connect of the run to the host, marked denied (the "
             "sensor blocked it): a denied connect reaches nothing, and nothing else in the evidence says the run "
             "reached the host")):
        claimed(name, f"reached_host api.example.com by {what}.",
                {"type": "reached_host", "args": {"host": "api.example.com"}, "evidence": a.evidence([seq])}, want)
    claimed("accept-unproven-reached-host-unreadable-claim", "reached_host of a..example with the observed evidence: "
            "a host with an empty label won't parse, so the claim is unproven.",
            {"type": "reached_host", "args": {"host": "a..example"}, "evidence": observed},
            "no host the verifier can read")
    for name, url, host, want, what in (
            ("accept-reached-host-http", "https://API.Example.COM:8443/v1/refunds", "api.example.com", "",
             "the host is read lower case, without the port"),
            ("accept-reached-host-claim-port", "https://api.example.com/v1/refunds", "api.example.com:443", "",
             "a port in the claim is ignored too"),
            ("accept-reached-host-trailing-dot", "https://api.example.com./v1/refunds", "api.example.com", "",
             "the host loses its one trailing dot"),
            ("accept-reached-host-short-ipv4", "http://127.1/health", "127.0.0.1", "",
             "127.1 is the IPv4 address 127.0.0.1"),
            ("accept-reached-host-idn", "http://bücher.example/", "xn--bcher-kva.example", "",
             "the host goes to ASCII by IDNA, so it is the punycode name the claim carries"),
            ("reject-claim-reached-host-other-host", "https://api.example.com/v1/refunds", "api.example.org",
             "no call in the evidence", "another host"),
            ("accept-unproven-reached-host-bracket", "http://[x]@good.com/", "good.com", "can't tell whether",
             "a `[` in the userinfo: Python's urlsplit refuses the URL, so its host won't parse"),
            ("accept-unproven-reached-host-ambiguous", "http://a.example\\@b.example/", "b.example",
             "can't tell whether", "a browser reads the host a.example and Python's urllib b.example, so it won't "
             "parse"),
            ("accept-unproven-reached-host-deviation", "http://fa\u00df.example/", "fass.example", "can't tell whether",
             "IDNA 2003 maps the sharp s to ss and a browser keeps it (xn--fa-hia.example), so a host with one of the "
             "four deviation characters won't parse"),
            ("accept-reached-host-unassigned", "http://x\u0378.example/", "xn--x-qib.example", "",
             "U+0378 is unassigned in Unicode 3.2, and the stdlib codec takes it (AllowUnassigned on)"),
            ("reject-claim-reached-host-file-url", "file://api.example.com/x", "api.example.com",
             "no call in the evidence", "a file: URL has no host a browser reads"),
            ("accept-unproven-reached-host-no-ipv6", "http://%5b::1%5d/", "api.example.com", "can't tell whether",
             "percent-decoded, the host is `[`, which is no IPv6 address, so it won't parse"),
            ("accept-unproven-reached-host-nul", "http://api.example.com%00.evil/", "api.example.com",
             "can't tell whether", "percent-decoded, the host holds a NUL, so it won't parse")):
        claimed(name, f"reached_host {host} by a WebFetch of {url} the executor ran (T2): {what}.",
                {"type": "reached_host", "args": {"host": host}, "evidence": call("WebFetch", {"url": url})}, want)
    claimed("accept-unproven-reached-host-claim-bad-port", "reached_host of api.example.com:abc with the observed "
            "evidence: a port must be 1 to 5 digits, so the claim won't parse.",
            {"type": "reached_host", "args": {"host": "api.example.com:abc"}, "evidence": observed},
            "no host the verifier can read")
    claimed("reject-claim-reached-host-too-long", "reached_host of a 200-character host: a claim's host is an id, at "
            "most 128 characters.", {"type": "reached_host", "args": {"host": "a" * 196 + ".com"}}, "not a valid id")

    # signature encodings, identities and JCS
    vector("reject-sig-non-canonical-base64", "sig.sig with an unused bit of its last base64 character set: the same "
           "64 bytes, but only canonical base64 is taken, so a signature has one text form.",
           dict(q, sig=dict(q["sig"], sig=loose(q["sig"]["sig"]))), [QUOTE], "bad signature")
    small = checkpoint.vkey("example.com/pcm-test-log", checkpoint.ED25519, b"\x01" + bytes(31))
    vector("reject-small-order-key", "trust pins a key that is the identity point (small order). The signature "
           "R = identity, S = 0 holds for any message under the plain equation; a verifier must refuse the key.",
           dict(q, sig={"key": small.rpartition("+")[0], "sig": base64.b64encode(b"\x01" + bytes(63)).decode()}),
           [QUOTE], "bad signature", trust=dict(trust, logs=[small]))
    odd = "uid:990102\r x"
    vector("accept-identity-line-break-chars", "to.agent holds a carriage return and U+2028: an identity's subject is "
           "any character but a line feed.", a.send(odd, qref), [QUOTE], me=odd)
    vector("accept-jcs-payload", "A data payload with floats, a non-ASCII key, a key outside the BMP that sorts before "
           "U+E000 by UTF-16 code units, controls and U+2028: the signature verifies only with exact RFC 8785.",
           a.call("pcm_sign", message={
               "from": a.frm, "to": {"agent": "uid:990102"}, "intent": {"type": qref, "args": ARGS},
               "payload": {"kind": "data", "data": {"n": [1.5e-7, 1e21, 0.1, 333333333.33333333, -0.0],
                                                    "été": "\u0007\u001f \u007f",
                                                    "": 1, "\U0001F600": 2}}})["message"], [QUOTE])

    # replay: remembered messages leave in the order they arrived
    q1, q2, q3 = (a.send("uid:990102", qref) for _ in range(3))
    vector("reject-replay-floor-arrival-order", "per_sender 1, no window: the receiver took the 3rd, then the 1st "
           "message, so the 3rd left first and raised the floor to its time; the 2nd is older than the floor.",
           q2, [QUOTE], "older than the messages this receiver remembers",
           replay={"window_s": None, "started": at(q1, -60), "per_sender": 1, "seen": [q3, q1]}, now=at(q3, 1))
    # replay: which messages spend their nonce
    twin = "this message with the same sender, ts and nonce, re-signed with the test log key"
    vector("accept-replay-misaddressed-spends-no-nonce", f"The receiver uid:990102 first got {twin} but addressed to "
           "uid:990103: a message for another receiver spends no nonce here, so this one is fresh.", q, [QUOTE],
           replay=fresh(q, [resign(q, "pcm", to={"agent": C})]))
    vector("accept-replay-schema-rejected-spends-no-nonce", f"The receiver first got {twin} but with order as the "
           'string "81", which its schema refuses: a message rejected for its schema spends no nonce, so this one is '
           "fresh.", q, [QUOTE], replay=fresh(q, [resign(q, "pcm", intent={"type": qref, "args": {
               **ARGS, "order": "81"}})]))
    over = a.send("uid:990102", ref, {**ARGS, "amount": 50000}, [approved], [root])
    again = resign(a.send("uid:990102", ref, claims=[approved], grants=[root]), "pcm", nonce=over["nonce"])
    vector("reject-replay-grant-failure-spends-nonce", "The receiver first got a message of the same sender with this "
           "nonce whose grant check failed (amount 50000 over the cap of 20000); this valid one carries that nonce, "
           "re-signed with the test log key: a message rejected for its grants spends its nonce, so this one is a "
           "replay.", again, [DOC], "replayed: this nonce was seen before", replay=fresh(again, [over]))
    vector("accept-skipped-replay-and-recipient", "A valid refund.quote checked with no replay state and no receiver "
           "identity (me null), as an audit: the result names both checks in skipped.", q, [QUOTE], me=None)

    # schema field types
    ticket = {"pcm_schema": 0, "name": "ticket.open", "fields": {
        "title": {"type": "string", "max": 80}, "code": {"type": "id", "pattern": "^[A-Z]{2}-[0-9]{1,6}$"},
        "level": {"type": "enum", "values": ["low", "high"]}, "urgent": {"type": "bool"}, "due": {"type": "time"},
        "note": {"type": "string", "max": 10, "optional": True}}}
    tref = pcm.schema_ref(ticket)
    vector("accept-schema-field-types", "A string, id, enum, bool and time field, and an optional field left out.",
           a.send("uid:990102", tref, {"title": "Printer jam", "code": "OP-81", "level": "high", "urgent": False,
                                       "due": "2026-11-01T09:00:00.000000Z"}), [ticket])
    vector("reject-schema-field-types", "Each field of the same schema broken: a title of 81 characters, a code the "
           "pattern refuses, a level not in the enum, 0 for a bool, a time without microseconds, an optional field "
           "too long.", a.send("uid:990102", tref, {"title": "x" * 81, "code": "op-81", "level": "urgent", "urgent": 0,
                                                    "due": "2026-11-01T09:00:00Z", "note": "far too long"}),
           [ticket], "schema: args.")

    # grants
    vector("reject-grant-needed", "refund.request needs a grant (grant: true); the message has none.",
           a.send("uid:990102", ref, claims=[approved]), [DOC], "the intent needs a grant")
    for name, grant, want, what in (
            ("tampered", {**root, "delegable": True}, "bad signature", "with delegable set to true after signing"),
            ("unpinned-key", pcm.sign(OTHER, s2.vkey, "pcm-grant", {k: v for k, v in root.items() if k != "sig"}),
             "not the log that signed the message", "signed by the other log, which trust does not pin"),
            ("issuer-is-subject", resign(root, "pcm-grant", issuer={**root["issuer"], "id": a.agent}),
             "issuer is its own subject", "with its issuer id edited to its subject, re-signed with the test log key"),
            ("bad-caveat", resign(root, "pcm-grant", caveats=[cv("amount", "in", [12000]), cv("order", "==", 81)]),
             "in does not apply to a money field", "with an `in` caveat on a money field, re-signed with the test log "
             "key")):
        vector(f"reject-grant-{name}", f"alice's root grant, {what}.",
               a.send("uid:990102", ref, claims=[approved], grants=[grant]), [DOC], want)
    quote_grant, _ = a.grant("grant-q", qref)
    vector("reject-grant-other-intent", "A root grant for refund.quote, sent with a refund.request.",
           a.send("uid:990102", ref, claims=[approved], grants=[quote_grant]), [DOC], "not this intent")
    lt = a.call("pcm_delegate", parent=droot, subject="uid:990102", caveats=[
        cv("amount", "<", 20001), cv("order", "==", 81)], expires_at=droot["expires_at"], delegable=False)["grant"]
    vector("accept-delegation-less-than", "A's child to B has amount < 20001, which narrows amount <= 20000.",
           b.send(C, pref, grants=[droot, lt]), [PASSED], me=C)
    for name, change, want, what in (
            ("child-outlives-parent", {"expires_at": svc._iso(pcm._epoch(droot["expires_at"]) + 60)},
             "outlives its parent", "expires 60 s after its parent"),
            ("child-wrong-issuer", {"issuer": {**child["issuer"], "id": "uid:990107"}}, "not grant 0's subject",
             "names uid:990107, not the parent's subject, as its issuer")):
        vector(f"reject-grant-{name}", f"A's child to B {what}; {edited}.",
               b.send(C, pref, grants=[droot, resign(child, "pcm-grant", **change)]), [PASSED], want, me=C)
    for name, change, want, what in (
            ("root-with-parent", {"parent": event_hash(droot)}, "the root grant has a parent",
             "with its parent set to another grant's hash"),
            ("root-without-person", {"issuer": {k: v for k, v in root["issuer"].items() if k != "person"}},
             "names no person", "with issuer.person removed (the signer names the person on every root grant)")):
        vector(f"reject-grant-{name}", f"alice's root grant {what}, re-signed with the test log key.",
               a.send("uid:990102", ref, claims=[approved], grants=[resign(root, "pcm-grant", **change)]), [DOC], want)
    vector("accept-grant-expires-at-ts", "A message whose ts is its root grant's expires_at, re-signed with the test log "
           "key (the signer takes ts from its clock): a grant still holds at its expires_at.",
           resign(a.send("uid:990102", ref, claims=[approved], grants=[root]), "pcm", ts=root["expires_at"]), [DOC])
    for name, caveat, args, what in (
            ("string-for-int", cv("order", "==", "81"), ARGS, 'order == "81", the string "81" for the int field order'),
            ("bool-for-int", cv("order", "==", True), {**ARGS, "order": 1},
             "order == true, a bool for the int field order, and a message with order 1")):
        g, _ = a.grant(f"grant-{name}", pref, caveats=[CAVEATS[0], caveat])
        vector(f"reject-grant-caveat-{name}", f"A root grant alice approved with {what}: nothing is converted, so a "
               "caveat's value of another JSON type than its field's is no valid caveat, and no args satisfy it.",
               a.send("uid:990102", pref, args, grants=[g]), [PASSED], "not a valid int value")

    # narrowing an `in` set and a time bound: alice grants A region in [eu, us] and due <= 2026-12-31 (delegable)
    scoped = {"pcm_schema": 0, "name": "refund.scoped", "grant": True, "fields": {
        **FIELDS, "region": {"type": "enum", "values": ["eu", "us", "apac"]}, "due": {"type": "time"}}}
    sref, due = pcm.schema_ref(scoped), "2026-12-31T00:00:00.000000Z"
    sargs = {**ARGS, "region": "eu", "due": "2026-11-01T09:00:00.000000Z"}
    sroot, _ = a.grant("grant-s", sref, delegable=True,
                       caveats=CAVEATS + [cv("region", "in", ["eu", "us"]), cv("due", "<=", due)])

    def scoped_caveats(region, before):
        return NARROWER + [cv("region", "in", region), cv("due", "<=", before)]

    def scoped_child(region, before):
        return a.call("pcm_delegate", parent=sroot, subject="uid:990102", caveats=scoped_caveats(region, before),
                      expires_at=sroot["expires_at"], delegable=False)["grant"]
    for name, region, before, what, wide, widened in (
            ("in-set", ["eu"], due, "region in [eu, us] to region in [eu]", (["eu", "us", "apac"], due),
             "region in [eu, us, apac], a superset"),
            ("time-bound", ["eu", "us"], "2026-11-30T00:00:00.000000Z", "due <= 2026-12-31 to due <= 2026-11-30",
             (["eu", "us"], "2027-01-31T00:00:00.000000Z"), "due <= 2027-01-31, a later bound")):
        kid = scoped_child(region, before)
        vector(f"accept-delegation-{name}", f"A's child to B narrows {what}.",
               b.send(C, sref, sargs, grants=[sroot, kid]), [scoped], me=C)
        vector(f"reject-grant-{name}-widened-child", f"A's child to B has {widened} instead; {edited}.",
               b.send(C, sref, sargs, grants=[sroot, resign(kid, "pcm-grant", caveats=scoped_caveats(*wide))]),
               [scoped], "dropped or widened", me=C)
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
