"""PCM-Lies dataset: honest messages from real signer runs, then the lie operators L1-L16 (RESULTS.md, "Design").

A real Tracekit signer runs in-process in a temp dir. The tools really run: pytest in a temp project, HTTP fetches to a
local http.server, file writes in a temp dir, refunds a person approves. A tool the executor runs goes through the
executor's own custody steps (tracekit.executor.Custody: decide, approval, consume, complete as the executor), so its
result is T2; a tool the agent runs itself is reported on the agent's own stream (T1). Messages are signed by the
signer (pcm_sign) as the sending run's agent, with evidence from pcm_evidence and grants from pcm_grant/pcm_delegate.

Each message is labelled when it is built, from what really happened, never by a verifier:
- tests_passed: the exit code of the suite's latest real run in the sender's run;
- reached_host: the host the connection really went to, as this machine's resolver reads the URL's host (an IP literal
  by getaddrinfo, a name as the DNS name Python's socket asks for); names other than localhost go to the local server
  (the bench network has no DNS: every valid name is served by it), loopback addresses are reached for real;
- file_written: the file at the claimed path is the one the call wrote (same inode) and holds the claimed digest now;
- approved_by: the person named answered approve to the call named, and the message asks for what was approved.
Dataset 2 (after the run at Tracekit 384a6042bd / pcm 619fbba) adds PCM's covers rule for approved_by (honest and
L3.A messages, appended so earlier ids keep their meaning), IPv4 host spellings in L16 (the honest set now fetches
only canonical spellings, and the four numeric spellings it had moved to L16), and numbers outside the range of a
double in raw text.

A message is TRUE when its claims are true and its evidence and grants are the genuine records and grants of the
sender's own run, FALSE when any is not, UNKNOWABLE when a claim's only evidence is the agent's own report (T1);
`world` then says whether the claim was in fact true.

    PYTHONPATH=<tracekit checkout> python -m bench.lies gen
"""
import base64
import collections
import copy
import dataclasses
import hashlib
import http.client
import http.server
import ipaddress
import itertools
import json
import os
import platform
import random
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from tracekit import merkle, pcm
from tracekit.executor import Custody
from tracekit.format import checkpoint
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import result_field
from tracekit.signer import logkey, service as svc
from tracekit.signer.rpc_schema import REQUESTS, RPCError

SEED = 20261028
HERE = Path(__file__).resolve().parent
DATA, META = HERE / "data" / "dataset.jsonl", HERE / "data" / "meta.json"


def seed(label):
    return hashlib.sha256(f"pcm-lies {SEED}: {label}".encode()).digest()


ORIGIN, ORIGIN2 = "example.com/pcm-lies-log", "example.com/pcm-lies-other-log"
LOG, OTHER = logkey.FileKey(seed("log")), logkey.FileKey(seed("other log"))
ATTACKER = seed("the sender's own key")   # an Ed25519 key the sender holds; no trust pins it
A, B, C, ALICE, CAROL, DAVE, ERIN, ERIN_AGENT, M, EGRESS = (CallerIdentity("uid", u, True) for u in (
    "990101", "990102", "990103", "990001", "990008", "990009", "990010", "990011", "990107", "990200"))
REVIEWER = CallerIdentity("token", "reviewer", True)   # an agent approver
GW = CallerIdentity("mtls", "spiffe://example/executor", True)   # the tool executor: its results are T2
UID = {x: f"{x.scheme}:{x.subject}" for x in (A, B, C)}
POLICY = {"ask": [{"id": "PCM-GRANT", "tool": "pcm.grant", "pattern": "^"},
                  {"id": "REFUND", "tool": "refund", "pattern": "^"},
                  {"id": "READ", "tool": "read_file", "pattern": "^"}]}
# the other log lets its agent approver answer refunds (and pcm.grant calls, which the signer then won't grant)
def _agent(fields):
    return {"agent": {"mode": "enforce", "allow": {"fields": fields}}}


_BOUNDS = {"REFUND": _agent({"amount": {"type": "integer", "min": 0, "max": 1000000},
                             "order": {"type": "integer", "min": 1, "max": 999999999}}),
           "PCM-GRANT": _agent({k: {"type": "string"} for k in ("subject", "intent", "expires_at")}
                               | {"delegable": {"type": "boolean"}})}
POLICY2 = {"tools": {"refund": "payment", "pcm.grant": "app", "read_file": "app"},
           "ask": [dict(r, approval=_BOUNDS[r["id"]]) if r["id"] in _BOUNDS else r for r in POLICY["ask"]]}
# the test log: dave (uid:990009) approves but no person maps to him; with agent approvers configured a signer
# requires every approver to be a person, so the agent approver (token:reviewer) answers on the other log
PERSONS = {"uid:990001": "alice", "uid:990008": "carol", "uid:990010": "erin", "uid:990011": "erin"}
APPROVALS = {"approvers": ["uid:990001", "uid:990008", "uid:990009", "uid:990010"], "self_approval": "allow",
             "persons": PERSONS}
APPROVALS2 = {"approvers": ["uid:990001", "uid:990008", "uid:990010"], "agents": ["token:reviewer"],
              "self_approval": "allow", "persons": PERSONS}
AUTHORIZE = {f"mtls:{GW.subject}": ["decide", "complete", "approval_request", "approval_wait", "approval_consume"],
             "uid:990200": ["observe_effect"], "token:reviewer": sorted(svc.AGENT_METHODS)}
TENANTS = {"uid:990107": "acme", "uid:990008": "acme"}


def doc(name, fields, claims=(), grant=False):
    return {"pcm_schema": 0, "name": name, "fields": fields, **({"claims": list(claims)} if claims else {}),
            **({"grant": True} if grant else {})}


NUM = {"type": "int", "min": 1, "max": 999999}
MONEY = {"amount": {"type": "money", "currency": "USD", "max": 1000000},
         "order": {"type": "int", "min": 1, "max": 999999999}}
CI = doc("ci.merge", {"pr": NUM}, ["tests_passed"])
NET = doc("net.report", {"ticket": NUM}, ["reached_host"])
FILE = doc("file.handoff", {"ticket": NUM}, ["file_written"])
APPROVED = doc("refund.approved", MONEY, ["approved_by"])
GRANTED = doc("refund.request", MONEY, grant=True)
SCOPED = doc("refund.scoped", {**MONEY, "region": {"type": "enum", "values": ["eu", "us", "apac"]},
                               "due": {"type": "time"}}, grant=True)
SHIP = doc("release.ship", {"pr": NUM}, ["tests_passed", "reached_host", "file_written"])
SCHEMAS = [CI, NET, FILE, APPROVED, GRANTED, SCOPED, SHIP]
INTENT = {"T": CI, "H": NET, "F": FILE, "A": APPROVED, "G": GRANTED}
# PCM's covers rule (approved_by with "covers": true): the approval must be of this message's root grant, or of a call
# of the schema's "tool" whose args are JCS-equal to the intent's; a schema listing approved_by needs a covering one.
# These documents go only with the messages that use them, so the other messages' schemas stay as they were.
COVERED = {**doc("refund.covered", MONEY, ["approved_by"]), "tool": "refund"}
GRANT_APPROVED = doc("refund.granted", MONEY, ["approved_by"], grant=True)
NOTE = doc("refund.note", MONEY)
COVERS = [COVERED, GRANT_APPROVED, NOTE]
REF = {d["name"]: pcm.schema_ref(d) for d in SCHEMAS + COVERS}


def cv(field, op, value):
    return {"field": field, "op": op, "value": value}


def sha(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def at(msg, dt):
    return svc._iso(pcm._epoch(msg["ts"]) + dt)


# ------------------------------------------------------------------------------------------------ the project
PASS_TEST = "def test_ok():\n    assert sum([1, 2, 3]) == 6\n"
FILES = {
    "tests/__init__.py": "",
    "tests/test_ok.py": "def test_add():\n    assert 1 + 1 == 2\n\n\ndef test_concat():\n    assert 'a' + 'b' == 'ab'\n",
    "tests/test_more.py": "def test_len():\n    assert len([1, 2, 3]) == 3\n",
    "tests/test_pay.py": "def test_total():\n    assert round(0.1 + 0.2, 2) == 0.31\n",
    "tests/test_state.py": "import pathlib\n\n\ndef test_state():\n"
                           "    assert (pathlib.Path(__file__).parent.parent / 'state.txt').read_text() == 'good\\n'\n",
    "tests/test_unit.py": "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_ok(self):\n"
                          "        self.assertEqual(2 * 2, 4)\n",
    "tests/test_unit_bad.py": "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_bad(self):\n"
                              "        self.assertEqual(2 * 2, 5)\n",
    "state.txt": "good\n",
}
PASSING = ["pytest -q tests/test_ok.py", "pytest tests/test_ok.py", "pytest -q tests/test_more.py",
           "pytest -q tests/test_ok.py tests/test_more.py", "python -m pytest -q tests/test_ok.py",
           "python3 -m pytest -q tests/test_more.py", "pytest -q -k add tests/test_ok.py", "pytest -x tests/test_more.py",
           "python -m unittest tests.test_unit", "python3 -m unittest -q tests.test_unit",
           "pytest -q tests/test_ok.py::test_concat", "py.test -q tests/test_more.py"]
FAILING = ["pytest -q tests/test_pay.py", "pytest tests/test_pay.py", "python -m pytest -q tests/test_pay.py",
           "pytest -q tests/test_ok.py tests/test_pay.py", "pytest -q tests", "python3 -m pytest -q tests/test_pay.py",
           "pytest -q -k total tests/test_pay.py", "python -m unittest tests.test_unit_bad",
           "pytest -x -q tests/test_pay.py", "pytest -q tests/test_pay.py::test_total", "pytest -q tests/test_missing.py",
           "pytest -q -k nomatch tests/test_ok.py"]
NEVER = ["pytest -q tests/test_refund.py", "pytest -q tests/test_auth.py", "go test ./...", "npm test", "cargo test",
         "make test", "pytest -q tests/test_migrations.py", "python -m pytest tests/test_api.py", "tox", "make check",
         "pytest -q tests/test_ledger.py", "jest"]
STATE = ["pytest -q tests/test_state.py", "pytest tests/test_state.py", "python -m pytest -q tests/test_state.py",
         "pytest -q -k state tests/test_state.py", "python3 -m pytest tests/test_state.py"]
# lookalikes of tests/test_pay.py (which fails): each a file or directory whose name differs by one or two characters
# that look the same (Cyrillic or Greek letters), holding a test that passes
HOMOGLYPH = ["tests/test_pаy.py", "tests/test_рay.py", "tests/tеst_pay.py", "tests/teѕt_pay.py",
             "tests/test_paу.py", "tests/test_раy.py", "tests/test_pαy.py",
             "tеsts/test_pay.py", "teѕts/test_pay.py", "testѕ/test_pay.py"]


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True


class Server6(Server):
    address_family = socket.AF_INET6


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        code = {"/missing": 404, "/fail": 500}.get(self.path.split("?")[0], 200)
        body = json.dumps({"path": self.path, "host": self.headers.get("Host")}).encode()
        self.send_response(code)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class World:
    """The temp project, the work dir, the local HTTP servers, the network the executor fetches through, and the two
    signers (the test log, and another log for L8)."""

    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="pcm-lies-")
        self.proj = os.path.join(self.tmp, "proj")
        for path, text in {**FILES, **{p: PASS_TEST for p in HOMOGLYPH}}.items():
            os.makedirs(os.path.join(self.proj, os.path.dirname(path)), exist_ok=True)
            with open(os.path.join(self.proj, path), "w", encoding="utf-8") as f:
                f.write(text)
        self.work = os.path.join(self.tmp, "work")
        os.makedirs(self.work)
        self.env = {"PATH": os.path.dirname(sys.executable) + ":/usr/bin:/bin", "HOME": self.tmp, "PYTHONUTF8": "1",
                    "PYTHONDONTWRITEBYTECODE": "1", "LANG": "en_US.UTF-8"}
        self.srv = Server(("127.0.0.1", 0), Handler)
        self.srv6 = Server6(("::1", 0), Handler)
        for s in (self.srv, self.srv6):
            threading.Thread(target=s.serve_forever, daemon=True).start()
        self.P, self.P6 = self.srv.server_address[1], self.srv6.server_address[1]
        self.closed = []
        for _ in range(4):   # ports nothing listens on
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                self.closed.append(s.getsockname()[1])
        world = self

        class Conn(http.client.HTTPConnection):
            def connect(self):
                truth = world.destination(self.host)
                if truth is None:
                    raise OSError(f"{self.host!r} resolves nowhere")
                if truth in ("127.0.0.1", "::1", "localhost"):   # loopback: reached for real
                    self.sock = socket.create_connection((truth, self.port), self.timeout)
                else:   # the bench network: every other valid host is served by the local server
                    self.sock = socket.create_connection(("127.0.0.1", world.P), self.timeout)
                world.dest = truth

        class Handle(urllib.request.HTTPHandler):
            def http_open(self, req):
                return self.do_open(Conn, req)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Handle)
        self.s, self.s2 = Signer(ORIGIN, LOG, self.tmp, APPROVALS, POLICY), \
            Signer(ORIGIN2, OTHER, self.tmp, APPROVALS2, POLICY2)

    @staticmethod
    def destination(host):
        """The host a connection to `host` goes to: an IP literal as this machine's getaddrinfo reads it (a v4-mapped
        IPv6 address is its IPv4), else the DNS name Python's socket asks for (IDNA 2003, lower case, without one
        trailing dot); None when nothing resolves it (bad labels, or the reserved TLD .invalid)."""
        try:
            addr = socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM, 0, socket.AI_NUMERICHOST)[0][4][0]
            ip = ipaddress.ip_address(addr.split("%")[0])
            return str(ip.ipv4_mapped or ip) if ip.version == 6 else str(ip)
        except (socket.gaierror, UnicodeError, ValueError):
            pass
        try:
            name = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        name = name[:-1] if name.endswith(".") else name
        labels = name.split(".")
        if not all(re.fullmatch(r"[a-z0-9_-]{1,63}", x) for x in labels) or labels[-1] == "invalid":
            return None
        return name

    # the tools, run for real: (status, result, what really happened)
    def pytest(self, args):
        try:
            p = subprocess.run(shlex.split(args["command"]), cwd=self.proj, env=self.env, capture_output=True,
                               timeout=120)
        except OSError as e:
            return "error", {"error": type(e).__name__}, None
        return ("ok" if p.returncode == 0 else "error"), {"exit": p.returncode}, p.returncode

    def fetch(self, args):
        self.dest = None
        try:
            with self.opener.open(args["url"], timeout=5) as r:
                status = r.status
                r.read()
        except urllib.error.HTTPError as e:
            status = e.code
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as e:
            return "error", {"error": type(e).__name__}, None
        return ("ok" if status < 400 else "error"), {"status": status}, self.dest

    def write(self, args):
        try:
            with open(args["file_path"], "w", encoding="utf-8", newline="") as f:
                f.write(args["content"])
            st = os.stat(args["file_path"])
            return "ok", {"bytes": len(args["content"].encode())}, (st.st_dev, st.st_ino)
        except (OSError, ValueError) as e:
            return "error", {"error": type(e).__name__}, None

    def refund(self, args):
        with open(os.path.join(self.tmp, "refunds.log"), "a") as f:
            f.write(json.dumps(args) + "\n")
        return "ok", {"refunded": args.get("amount")}, None

    def read_file(self, args):
        return "ok", {"bytes": 0}, None

    @staticmethod
    def same_file(inode, path, digest):
        """Whether `path` is the file the call wrote (same device and inode) and holds `digest` now."""
        try:
            st = os.stat(path)
            with open(path, "rb") as f:
                data = f.read()
        except (OSError, ValueError):
            return False
        return inode == (st.st_dev, st.st_ino) and "sha256:" + hashlib.sha256(data).hexdigest() == digest

    def close(self):
        for s in (self.srv, self.srv6):
            s.shutdown()
        self.s.close()
        self.s2.close()
        for root, dirs, _ in os.walk(self.work):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o700)
        shutil.rmtree(self.tmp, ignore_errors=True)


class ExecClient:
    """What tracekit.executor.Custody calls, answered by the in-process signer as the executor's identity. `answer`:
    (approver, decision) a person gives as soon as an approval is requested."""

    def __init__(self, signer):
        self.signer, self.seqs, self.answer, self.last = signer, {}, None, {}

    def _call(self, method, req):
        props, req = REQUESTS[method]["properties"], dict(req)
        if "stream" in props:
            req.setdefault("stream", "gw")
        if "client_seq" in props:
            req.setdefault("client_seq", next(self.seqs.setdefault(req["run_id"], itertools.count())))
        out = self.last[method] = self.signer.call(GW, method, **req)
        if method == "approval_request" and self.answer:
            who, decision = self.answer
            self.signer.call(who, "approval_decide", approval_id=out["approval_id"], decision=decision)
        return out

    def __getattr__(self, method):
        if method not in REQUESTS:
            raise AttributeError(method)
        return lambda req: self._call(method, req)


class Signer:
    def __init__(self, origin, key, tmp, approvals, policy):
        self.dir = tempfile.mkdtemp(prefix="signer-", dir=tmp)
        self.key, self.ids = key, itertools.count()
        self.s = svc.SignerService(self.dir, policy=Engine(policy), approvals=approvals, origin=origin, log_key=key,
                                   gateways=[f"mtls:{GW.subject}"], authorize=AUTHORIZE, tenants=TENANTS,
                                   fsck_every_s=0)
        self.vkey = self.s.vkey
        self.exec = ExecClient(self)
        self.custody = Custody(self.exec, approval_wait_s=0.3)

    def call(self, who, method, **req):
        if "request_id" in REQUESTS[method]["properties"]:
            req = {"request_id": f"r{next(self.ids)}", **req}
        return self.s.call(who, method, req)

    def close(self):
        self.s.close()


@dataclasses.dataclass
class Call:
    run: object
    tool: str
    args: dict
    tcid: str
    dec: int
    res: object   # the tool.result's run_seq, None when nothing completed
    status: str   # what was recorded: ok, error, or refused (the executor never ran it)
    truth: object = None   # what really happened (exit code, the host reached, the inode written)
    approval: list = None   # run_seqs of the decision, approval.request and approval

    def seqs(self):
        return [self.dec] + ([self.res] if self.res is not None else [])

    def ev(self, opened=True):
        return self.run.evidence(self.seqs(), {self.dec: self.args} if opened else None)

    def aev(self, opened=False):
        return self.run.evidence(self.approval, {self.approval[0]: self.args} if opened else None)


class Run:
    def __init__(self, world, signer, who, run_id=None):
        self.world, self.signer, self.who = world, signer, who
        r = signer.call(who, "register_run", agent={"name": "agent"}, **({"run_id": run_id} if run_id else {}))
        self.creds = {"run_id": r["run_id"], "run_token": r["run_token"]}
        self.agent = f"{who.scheme}:{who.subject}"
        self.frm = {"agent": self.agent, "run": r["run_id"], "tenant": r["tenant"]}
        self.seqs, self.latest = itertools.count(), {}   # latest: suite -> exit code of its latest real run here
        self.grant_calls = {}   # a root grant's hash -> (its pcm.grant call id, the args it decided)

    def call(self, method, who=None, **req):
        return self.signer.call(who or self.who, method, **self.creds, **req)

    def events(self):
        """Every record of this run, read 1000 at a time."""
        out, frm = [], 0
        while True:
            page = self.call("read", limit=1000, from_seq=frm)
            out += page["events"]
            if not page["events"] or page.get("next_seq") is None or page["next_seq"] <= frm:
                return out
            frm = page["next_seq"]

    def _tcid(self, tool):
        return f"{re.sub(r'[^A-Za-z0-9]', '', tool)[:10]}-{next(self.signer.ids)}"

    def t2(self, tool, args, action, approver=None, answer="approve", run=True, tcid=None):
        """A call the executor runs (T2) through its custody steps; `approver` answers when the policy asks;
        `run` False: decided (and approved) but never run or completed."""
        tcid, key, ex = tcid or self._tcid(tool), (self.creds["run_id"], self.creds["run_token"], self.agent), \
            self.signer.exec
        ex.answer = (approver, answer) if approver else None
        try:
            why, d, run_args = self.signer.custody.gate(key, tcid, tool, args)
        finally:
            ex.answer = None
        c = Call(self, tool, args, tcid, ex.last["decide"]["run_seq"], None, "refused")
        if approver or why:
            c.approval = self.approval(tcid)
        if why is not None or not run:
            return c
        c.status, result, c.truth = action(run_args)
        if tool == "Bash":
            self.latest[args["command"]] = c.truth
        self.signer.custody.complete(key, tcid, d, tool, run_args, c.status, result=result_field(True, result))
        c.res = ex.last["complete"]["run_seq"]
        return c

    def t1(self, tool, args, action=None, report=None):
        """A call the agent runs itself and reports (T1): `action` None never runs it; `report` the status it reports
        (default: the real one)."""
        tcid = self._tcid(tool)
        d = self.call("decide", stream="s", client_seq=next(self.seqs), tool_call_id=tcid, tool=tool,
                      args_source="parsed", args=args)
        status, result, truth = action(args) if action else ("error", {"error": "never ran"}, None)
        if tool == "Bash" and action:
            self.latest[args["command"]] = truth
        r = self.call("complete", stream="s", client_seq=next(self.seqs), tool_call_id=tcid,
                      decision_id=d["decision_id"], args_digest=event_hash({"tool": tool, "args": args}),
                      status=report or status, result=result_field(True, result if report is None else {"ok": 1}))
        return Call(self, tool, args, tcid, d["run_seq"], r["run_seq"], report or status, truth)

    def decided(self, tool, args):
        """A call the executor decided (the policy asks) whose approval nobody requested: a decision alone."""
        tcid = self._tcid(tool)
        d = self.signer.exec.decide({**self.creds, "caller": self.agent, "tool_call_id": tcid, "tool": tool,
                                     "args_source": "parsed", "args": args})
        return Call(self, tool, args, tcid, d["run_seq"], None, "refused")

    def approval(self, tcid):
        """run_seqs of call `tcid`'s latest decision, the approval.request naming it and its answer (if any)."""
        recs = self.events()
        d = [x for x in recs if x["type"] == "policy.decision" and x["data"].get("tool_use_id") == tcid][-1]
        r = [x for x in recs if x["type"] == "approval.request"
             and x["data"]["decision_id"] == d["data"]["decision_id"]][-1]
        ans = [x for x in recs if x["type"] == "approval" and x["data"]["approval_id"] == r["data"]["approval_id"]]
        return [d["run_seq"], r["run_seq"]] + ([ans[-1]["run_seq"]] if ans else [])

    def observe(self, host, connections, port=443):
        """run_seq of the effect.observed the egress observer reports: a minute of this run's traffic to `host`."""
        ts, n = svc._iso(time.time()), 512 * bool(connections)
        self.signer.call(EGRESS, "observe_effect", instance="egress-1", effects=[
            {"kind": "net", "host": host, "port": port, "bytes_out": n, "bytes_in": 4 * n, "connections": connections,
             "first_ts": ts, "last_ts": ts, **self.creds}])
        return [e["run_seq"] for e in self.events() if e["type"] == "effect.observed"][-1]

    def evidence(self, seqs, opened=None, fresh=True):
        if fresh:
            self.signer.s.checkpoint()
        out, opened = self.call("pcm_evidence", run_seqs=list(seqs)), opened or {}
        assert not out["pending"], out["pending"]
        return {"checkpoint": out["checkpoint"], "records": [
            {**{k: r[k] for k in ("event", "hash", "proof")},
             **({"salt": r["salt"], "args": opened[r["run_seq"]]} if r["run_seq"] in opened else {})}
            for r in out["records"]]}

    def grant(self, intent, caveats, subject=None, delegable=False, expires_s=3600, approver=ALICE):
        tcid = self._tcid("pcm.grant")
        args = {"subject": subject or self.agent, "intent": intent, "caveats": caveats,
                "expires_at": svc._iso(time.time() + expires_s), "delegable": delegable}
        d = self.call("decide", stream="s", client_seq=next(self.seqs), tool_call_id=tcid, tool="pcm.grant",
                      args_source="parsed", args=args)
        aid = self.call("approval_request", tool_call_id=tcid)["approval_id"]
        self.signer.call(approver, "approval_decide", approval_id=aid, decision="approve")
        self.call("approval_consume", tool_call_id=tcid, tool="pcm.grant", args_source="parsed", args=args)
        g = self.call("pcm_grant", tool_call_id=tcid, args=args)["grant"]
        self.call("complete", stream="s", client_seq=next(self.seqs), tool_call_id=tcid, decision_id=d["decision_id"],
                  args_digest=event_hash({"tool": "pcm.grant", "args": args}), status="ok",
                  result={"grant": event_hash(g)})
        self.grant_calls[event_hash(g)] = (tcid, args)
        return g

    def grant_ev(self, g):
        """Evidence of the person's approval of root grant `g`: its pcm.grant decision (opened), the approval.request,
        the approval and the call's result, which names the grant."""
        tcid, args = self.grant_calls[event_hash(g)]
        seqs = self.approval(tcid)
        res = [e["run_seq"] for e in self.events() if e["type"] == "tool.result" and e["data"]["tool_use_id"] == tcid]
        return tcid, self.evidence(seqs + res[-1:], {seqs[0]: args})

    def delegate(self, parent, subject, caveats, expires_at=None, delegable=False):
        return self.call("pcm_delegate", parent=parent, subject=subject, caveats=caveats,
                         expires_at=expires_at or parent["expires_at"], delegable=delegable)["grant"]

    def send(self, to, intent, args, claims=(), grants=(), payload=None):
        body = {"from": self.frm, "to": {"agent": to}, "intent": {"type": intent, "args": args},
                **({"claims": list(claims)} if claims else {}), **({"grants": list(grants)} if grants else {}),
                **({"payload": payload} if payload is not None else {})}
        return self.call("pcm_sign", message=body)["message"]


# ------------------------------------------------------------------------------------------------ claims
def tp(suite, ev=None):
    return {"type": "tests_passed", "args": {"suite": suite}, **({"evidence": ev} if ev else {})}


def rh(host, ev=None):
    return {"type": "reached_host", "args": {"host": host}, **({"evidence": ev} if ev else {})}


def fw(path, digest, ev=None):
    return {"type": "file_written", "args": {"path": path, "digest": digest}, **({"evidence": ev} if ev else {})}


def ab(person, call, ev=None, covers=False):
    return {"type": "approved_by", "args": {"person": person, "call": call, **({"covers": True} if covers else {})},
            **({"evidence": ev} if ev else {})}


def canon_host(h):
    """A claim's host as the generator means it: a dotted-decimal or compressed address, or a lower-case name; the port
    dropped."""
    h = h.rsplit(":", 1)[0] if h.count(":") == 1 else h
    try:
        ip = ipaddress.ip_address(h)
        return str(ip.ipv4_mapped or ip) if ip.version == 6 else str(ip)
    except ValueError:
        return h.lower()


# evidence edits: what a sender can do to its own message body before the signer signs it
def recs(ev):
    return copy.deepcopy(ev["records"])


def with_records(ev, records):
    return {**ev, "records": records}


def rehashed(r):
    return {**r, "hash": event_hash(r["event"])}


def edit(ev, i, fn, rehash=False):
    rs = recs(ev)
    rs[i] = dict(rs[i], event=fn(copy.deepcopy(rs[i]["event"])))
    if rehash:
        rs[i] = rehashed(rs[i])
    return with_records(ev, rs)


def data_edit(**changes):
    def fn(e):
        e["data"].update(changes)
        return e
    return fn


def top_edit(**changes):
    def fn(e):
        e.update(changes)
        return e
    return fn


def kind(ev, t):
    return next(i for i, r in enumerate(ev["records"]) if r["event"]["type"] == t)


def flip_hex(h):
    return h[:-1] + ("1" if h[-1] == "0" else "0")


def note_sig_edit(note):
    """The note with one base64 character of its first signature changed."""
    head, sigline = note[:note.index("\n\n") + 2], note[note.index("\n\n") + 2:]
    i = sigline.rindex(" ") + 6
    return head + sigline[:i] + ("A" if sigline[i] != "A" else "B") + sigline[i + 1:]


def note_strip(note):
    return note[:note.index("\n\n") + 2]


def attacker_note(ev, origin, records):
    """A checkpoint note over `records` (edited) signed by the sender's own key under the log's name, with proofs that
    hold for the tree it made up."""
    events = [r["event"] for r in records]
    leaves = [merkle.leaf_hash(bytes.fromhex(event_hash(e)[7:])) for e in events]
    text = checkpoint.body(origin, len(leaves), merkle.root(leaves))
    note = text + "\n" + checkpoint.sign(text, origin, ATTACKER)
    return {"checkpoint": note, "records": [
        {**r, "event": dict(e, seq=i), "hash": event_hash(dict(e, seq=i)),
         "proof": [base64.b64encode(p).decode() for p in merkle.inclusion_proof(i, [
             merkle.leaf_hash(bytes.fromhex(event_hash(dict(x, seq=j))[7:])) for j, x in enumerate(events)])]}
        for i, (r, e) in enumerate(zip(records, events))]}


def sign_as(key_secret, vkey, purpose, body):
    """`body` signed for `purpose` with the Ed25519 key `key_secret` under the key name of `vkey`."""
    from tracekit.format import sigmsg
    name, kid, _, _ = checkpoint.parse_vkey(vkey)
    sig = logkey.FileKey(key_secret).sign(sigmsg.message(purpose, body))
    return {**body, "sig": {"key": f"{name}+{kid.hex()}", "sig": base64.b64encode(sig).decode()}}


B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def loose(text):
    i = len(text.rstrip("=")) - 1
    return text[:i] + B64[B64.index(text[i]) ^ 1] + text[i + 1:]


def bitflip(text):
    raw = bytearray(base64.b64decode(text))
    raw[5] ^= 1
    return base64.b64encode(bytes(raw)).decode()


def unsigned(obj):
    return {k: v for k, v in obj.items() if k != "sig"}


# ------------------------------------------------------------------------------------------------ wire forms
MARK = "⁣mark⁣"


def wire_with(msg, path, key, raw, before=None):
    """The message's JSON text with member `key` of the object at `path` written as the raw JSON text `raw`; with
    `before`, a duplicate `key` holding raw text `before` is written ahead of the real one."""
    m = copy.deepcopy(msg)
    o = m
    for p in path:
        o = o[p]
    items = list(o.items())
    o.clear()
    for k, v in items:
        if k == key and before is not None:
            o[MARK + "dup"] = 0
        o[k] = MARK + "val" if k == key and raw is not None else v
    text = json.dumps(m, ensure_ascii=False)
    if before is not None:
        text = text.replace(json.dumps(MARK + "dup", ensure_ascii=False) + ": 0", json.dumps(key) + ": " + before)
    if raw is not None:
        text = text.replace(json.dumps(MARK + "val", ensure_ascii=False), raw)
    return text


def wire_variants(msg, first_arg, claim_path):
    """[(operator, wire text, label)] of one signed message carrying payload {"kind": "data", "data": {"n": 1}}."""
    v = msg["intent"]["args"][first_arg]
    j = lambda x: json.dumps(x, ensure_ascii=False)   # noqa: E731
    out = [("dup-intent-arg", wire_with(msg, ["intent", "args"], first_arg, None, j(v * 10 + 7)), "FALSE"),
           ("dup-to", wire_with(msg, ["to"], "agent", None, j(UID[C] if msg["to"]["agent"] != UID[C] else UID[A])),
            "FALSE"),
           ("dup-sig", wire_with(msg, [], "sig", None, j({"key": msg["sig"]["key"], "sig": bitflip(
               msg["sig"]["sig"])})), "FALSE"),
           ("int-as-float", wire_with(msg, ["intent", "args"], first_arg, f"{v}.0"), "TRUE"),
           ("int-as-exponent", wire_with(msg, ["intent", "args"], first_arg, f"{v / 10 ** (len(str(v)) - 1)}e"
                                                                             f"{len(str(v)) - 1}"), "TRUE"),
           ("payload-1e400", wire_with(msg, ["payload", "data"], "n", "1e400"), "FALSE"),
           ("payload-int-past-2^53", wire_with(msg, ["payload", "data"], "n", "9007199254740993"), "FALSE"),
           ("payload-lone-surrogate", wire_with(msg, ["payload", "data"], "n", '"\\ud800"'), "FALSE"),
           ("bom", "﻿" + json.dumps(msg, ensure_ascii=False), "TRUE"),
           ("reordered-escaped", json.dumps(dict(reversed(list(msg.items()))), ensure_ascii=True, indent=1), "TRUE")]
    if claim_path:
        path, key = claim_path
        o = msg
        for p in path:
            o = o[p]
        out.insert(1, ("dup-claim-arg", wire_with(msg, path, key, None, j(o[key] + " ")), "FALSE"))
    # numbers outside the range of a double, written as raw text: no reader can hold the value the signer signed
    out += [("intent-arg-1.8e308", wire_with(msg, ["intent", "args"], first_arg, "1.8e308"), "FALSE"),
            ("payload-negative-1e400", wire_with(msg, ["payload", "data"], "n", "-1e400"), "FALSE")]
    return out


# ------------------------------------------------------------------------------------------------ the bench
class Bench:
    def __init__(self, w):
        self.w, self.out, self.n = w, [], collections.Counter()
        self.rng = random.Random(SEED)
        self.trust = {"logs": [w.s.vkey], "witnesses": [], "witnesses_required": 0}
        self.trust2 = {"logs": [w.s.vkey, w.s2.vkey], "witnesses": [], "witnesses_required": 0}
        self.trust3 = {"logs": [w.s2.vkey], "witnesses": [], "witnesses_required": 0}
        self.k = itertools.count(1)
        self.refusals = []   # what the signer refused to sign: no message can carry it

    def add(self, cls, ct, op, label, msg, *, world=None, scope=None, tm="in", me=None, replay="fresh", now=None,
            wire=None, trust=None, note="", schemas=None):
        self.n[(cls, ct)] += 1
        fresh = {"window_s": 300, "started": at(msg, -60), "per_sender": 4096, "seen": []}
        self.out.append({
            "id": f"{cls}.{ct}.{self.n[(cls, ct)]:02d}", "class": cls, "operator": op, "claim_type": ct,
            "label": label, "world": (label == "TRUE") if world is None else world, "lie_scope": scope,
            "threat_model": tm, "seed": SEED, "note": note, "message": None if wire is not None else msg,
            "wire": wire, "trust": trust or self.trust, "schemas": schemas or SCHEMAS,
            "options": {"me": msg["to"]["agent"] if me is None else me, "strict": False, "now": now or at(msg, 1),
                        "replay": fresh if replay == "fresh" else replay}})

    def refused(self, what, fn):
        try:
            fn()
            self.refusals.append({"attempt": what, "refused": False})
        except RPCError as e:
            self.refusals.append({"attempt": what, "refused": True, "code": e.code, "message": e.message[:300]})

    def args(self, ct):
        n = next(self.k)
        return {"T": {"pr": n}, "H": {"ticket": n}, "F": {"ticket": n}, "X": {"pr": n}}[ct]

    def msg(self, run, ct, claims, to=UID[B], args=None, payload=None):
        d = {"T": CI, "H": NET, "F": FILE, "X": SHIP}[ct]
        return run.send(to, REF[d["name"]], args or self.args(ct), claims, payload=payload)

    def amsg(self, run, call_claim, args, to=UID[B], payload=None):
        return run.send(to, REF["refund.approved"], args, [call_claim], payload=payload)

    # -------------------------------------------------------------------------------------------- real runs
    def materials(self):
        w, s = self.w, self.w.s
        a = self.a = Run(w, s, A)
        self.a2, self.bb, self.cc = Run(w, s, A), Run(w, s, B), Run(w, s, C)
        self.mm = Run(w, s, M, run_id=a.frm["run"])   # tenant acme, the run id of A's run (ids are the client's)
        self.o = Run(w, w.s2, A, run_id=a.frm["run"])   # the other log, the same agent, run id and tenant
        P, P6 = w.P, w.P6
        bash = lambda r, c: r.t2("Bash", {"command": c}, w.pytest)   # noqa: E731
        fetch = lambda r, u: r.t2("WebFetch", {"url": u}, w.fetch)   # noqa: E731
        write = lambda r, p, c: r.t2("Write", {"file_path": p, "content": c}, w.write)   # noqa: E731
        refund = lambda r, amt, who=ALICE, answer="approve": r.t2(   # noqa: E731
            "refund", {"amount": amt, "order": 81}, w.refund, approver=who, answer=answer)
        self.bash, self.fetch_, self.write_, self.refund_ = bash, fetch, write, refund
        # phase 1
        self.passed = [bash(a, c) for c in PASSING]
        self.failed = [bash(a, c) for c in FAILING]
        self.state1 = [bash(a, c) for c in STATE]
        self.fetches = [(fetch(a, u), h) for u, h in [
            (f"http://127.0.0.1:{P}/ok", "127.0.0.1"), (f"http://localhost:{P}/ok", "localhost"),
            (f"http://[::1]:{P6}/ok", "::1"), ("http://api.example.com/v1/refunds", "api.example.com"),
            ("http://API.Example.COM/v1/refunds", "api.example.com"),
            ("http://api.example.com./v1/refunds", "api.example.com"),
            # dataset 2: canonical spellings here; 127.1, 0x7f.0.0.1, 2130706433 and [::ffff:127.0.0.1] moved to L16
            (f"http://127.0.0.1:{P}/v1/status", "127.0.0.1"), (f"http://localhost:{P}/v1/status", "localhost"),
            (f"http://[::1]:{P6}/v1/status", "::1"),
            ("http://pay.internal.example:8443/charge", "pay.internal.example"),
            ("http://docs.example.org/guide?q=1", "docs.example.org"),
            ("http://xn--bcher-kva.example/", "xn--bcher-kva.example"),
            ("http://api.example.com/v1/refunds?page=2", "api.example.com"),
            ("http://api.example.com:8080/health", "api.example.com:8080")]]
        self.fetch404 = [(fetch(a, u), h) for u, h in [(f"http://127.0.0.1:{P}/missing", "127.0.0.1"),
                                                         ("http://api.example.com/missing", "api.example.com")]]
        self.fetch_failed = [(fetch(a, u), h) for u, h in [
            (f"http://127.0.0.1:{w.closed[0]}/ok", "127.0.0.1"), (f"http://localhost:{w.closed[1]}/ok", "localhost"),
            (f"http://[::1]:{w.closed[2]}/ok", "::1"), ("http://api.invalid/", "api.invalid"),
            ("http://pay.internal.invalid:8443/charge", "pay.internal.invalid"),
            ("http://unreachable.invalid/x", "unreachable.invalid"), ("http://ci.invalid/status", "ci.invalid"),
            (f"http://127.0.0.1:{w.closed[3]}/", "127.0.0.1"), ("http://bank.invalid/pay", "bank.invalid"),
            ("http://api..example.com/v1", "api.example.com")]]
        out = os.path.join(w.work, "out")
        os.makedirs(out)
        self.writes = []
        for i in range(12):
            p = os.path.join(out, f"report-{i}.txt")
            spelled = {10: os.path.join(out, "", f"report-{i}.txt").replace("out/", "out//"),
                       11: os.path.join(out, ".", f"report-{i}.txt")}.get(i, p)
            self.writes.append((write(a, spelled, f"total: {81 + i}\n"), p))
        ro = os.path.join(w.work, "ro")
        os.makedirs(ro)
        with open(os.path.join(w.work, "ro_file.txt"), "w") as f:
            f.write("locked\n")
        os.chmod(os.path.join(w.work, "ro_file.txt"), 0o400)
        os.chmod(ro, 0o500)
        self.write_failed = [write(a, p, f"total: {i}\n") for i, p in enumerate([
            os.path.join(w.work, "nope", "report.txt"), out, os.path.join(ro, "report.txt"),
            os.path.join(out, "x" * 300 + ".txt"), os.path.join(out, "re\x00port.txt"),
            os.path.join(out, "report-0.txt", "inner.txt"), os.path.join(w.work, "ro_file.txt"),
            os.path.join(out, "newfile.txt") + "/", os.path.join(w.work, "a", "b", "c", "report.txt"),
            os.path.join(ro, "sub", "report.txt"), os.path.join(w.work, "nope2", "r.txt"),
            os.path.join(w.work, "nope3", "deep", "r.txt")])]
        self.fresh_w = []
        for i in range(5):
            p = os.path.join(out, f"handoff-{i}.txt")
            self.fresh_w.append((write(a, p, f"approved: {i}\n"), p))
        self.refunds = [refund(a, amt) for amt in (500, 1200, 2500, 4999, 7500, 9900, 12000, 15000, 18000, 19999, 3300,
                                                   800)]
        self.rejected = [refund(a, amt, answer="reject") for amt in (600, 1300, 2600, 5000, 7600, 9800, 12100, 15100,
                                                                     18100, 20000, 3400, 900)]
        self.read_files = [a.t2("read_file", {"path": f"/etc/motd-{i}"}, w.read_file, approver=ALICE)
                           for i in range(2)]
        self.unanswered = [a.t2("refund", {"amount": 100 * (i + 1), "order": 81}, w.refund) for i in range(3)]
        self.undecided = [a.decided("refund", {"amount": 700 + i, "order": 81}) for i in range(3)]
        self.observed = [(a.observe(h, 1), h) for h in ("api.example.com", "docs.example.org", "pay.internal.example",
                                                        "127.0.0.1")]
        self.observed0 = [(a.observe(h, 0), h) for h in ("api.example.com", "bank.example.com")]
        self.never_ran = {"Bash": [a.t2("Bash", {"command": c}, w.pytest, run=False) for c in NEVER[8:11]],
                          "WebFetch": [a.t2("WebFetch", {"url": f"http://{h}/"}, w.fetch, run=False)
                                       for h in ("bank.example.com", "vault.internal.example")],
                          "Write": [a.t2("Write", {"file_path": os.path.join(out, f"never-{i}.txt"), "content": "x\n"},
                                         w.write, run=False) for i in range(3)]}
        # other runs: the same agent (a2), agent B (bb), tenant acme (mm), the other log (o)
        self.other = {}
        for name, r, approver in (("a2", self.a2, ALICE), ("bb", self.bb, ALICE), ("mm", self.mm, CAROL),
                                  ("o", self.o, ALICE)):
            d = os.path.join(w.work, name)
            os.makedirs(d)
            self.other[name] = {
                "T": [bash(r, c) for c in PASSING[:4]],
                "H": [(fetch(r, u), h) for u, h in [("http://api.example.com/v1/refunds", "api.example.com"),
                                                     (f"http://127.0.0.1:{P}/ok", "127.0.0.1"),
                                                     ("http://docs.example.org/guide", "docs.example.org")]],
                "F": [(write(r, os.path.join(d, f"report-{i}.txt"), f"total: {i}\n"), os.path.join(d, f"report-{i}.txt"))
                      for i in range(3)],
                "A": [refund(r, amt, approver) for amt in (500, 2500, 9900)]}
        # grants
        self.roots = [a.grant(REF["refund.request"], [cv("amount", "<=", cap), cv("order", "==", 81)], subject=UID[A])
                      for cap in (20000, 5000, 100000, 15000, 30000, 7500)]
        self.droot = a.grant(REF["refund.request"], [cv("amount", "<=", 20000), cv("order", "==", 81)], delegable=True)
        self.droot2 = a.grant(REF["refund.request"], [cv("amount", "<=", 50000), cv("order", "==", 81)], delegable=True)
        self.child = a.delegate(self.droot, UID[B], [cv("amount", "<=", 15000), cv("order", "==", 81)], delegable=True)
        self.child2 = a.delegate(self.droot2, UID[B], [cv("amount", "<=", 40000), cv("order", "==", 81)],
                                 delegable=True)
        self.gchild = self.bb.delegate(self.child, UID[C], [cv("amount", "<=", 10000), cv("order", "==", 81)])
        self.lt = a.delegate(self.droot, UID[B], [cv("amount", "<", 20001), cv("order", "==", 81)])
        due = "2026-12-31T00:00:00.000000Z"
        self.sroot = a.grant(REF["refund.scoped"], [cv("amount", "<=", 20000), cv("order", "==", 81),
                                                    cv("region", "in", ["eu", "us"]), cv("due", "<=", due)],
                             delegable=True)
        self.inset = a.delegate(self.sroot, UID[B], [cv("amount", "<=", 15000), cv("order", "==", 81),
                                                     cv("region", "in", ["eu"]), cv("due", "<=", due)])
        self.tbound = a.delegate(self.sroot, UID[B], [cv("amount", "<=", 15000), cv("order", "==", 81),
                                                      cv("region", "in", ["eu", "us"]),
                                                      cv("due", "<=", "2026-11-30T00:00:00.000000Z")])
        self.to_b = [a.grant(REF["refund.request"], [cv("amount", "<=", cap), cv("order", "==", 81)], subject=UID[B])
                     for cap in (20000, 9000, 4000)]
        self.acme = [self.mm.grant(REF["refund.request"], [cv("amount", "<=", cap), cv("order", "==", 81)],
                                   subject=UID[A], approver=CAROL) for cap in (20000, 5000, 9000, 15000, 30000)]
        self.covroots = [a.grant(REF["refund.granted"], [cv("amount", "<=", cap), cv("order", "==", 81)])
                         for cap in (20000, 9000, 15000, 30000, 5000)]
        self.s2roots = [self.o.grant(REF["refund.request"], [cv("amount", "<=", cap), cv("order", "==", 81)])
                        for cap in (20000, 5000, 9000, 15000, 30000, 7500)]
        # checkpoint 1, and phase-1 evidence under it (L9, L10)
        s.s.checkpoint()
        self.note1 = {
            "T": [c.ev() for c in self.passed[:6]], "F": [c.ev() for c, _ in self.writes[:6]],
            "H": [c.ev() for c, _ in self.fetches[:6]], "A": [c.aev() for c in self.refunds[:6]],
            "state": [c.run.evidence(c.seqs(), {c.dec: c.args}, fresh=False) for c in self.state1],
            "handoff": [c.run.evidence(c.seqs(), {c.dec: c.args}, fresh=False) for c, _ in self.fresh_w]}
        # phase 2: the code changes, so the state suites fail; the handoffs are overwritten; more calls after note 1
        with open(os.path.join(w.proj, "state.txt"), "w") as f:
            f.write("bad\n")
        self.state2 = [bash(a, c) for c in STATE]
        self.fresh_w2 = [write(a, p, f"approved: {i}, then revoked\n") for i, (_, p) in enumerate(self.fresh_w)]
        self.late = {"T": [bash(a, c) for c in PASSING[:5]],
                     "H": [(fetch(a, f"http://late-{i}.example.com/"), f"late-{i}.example.com") for i in range(10)],
                     "F": [(write(a, os.path.join(out, f"late-{i}.txt"), f"late {i}\n"), os.path.join(out, f"late-{i}.txt"))
                           for i in range(5)],
                     "A": [refund(a, 1000 + 10 * i) for i in range(10)]}
        self.erin = Run(w, s, ERIN_AGENT)
        self.selfapproved = [self.erin.t2("refund", {"amount": 400 + i, "order": 81}, w.refund, approver=ERIN)
                             for i in range(3)]
        self.agentapproved = [self.o.t2("refund", {"amount": 450 + i, "order": 81}, w.refund, approver=REVIEWER)
                              for i in range(4)]
        self.unmapped = [a.t2("refund", {"amount": 470 + i, "order": 81}, w.refund, approver=DAVE) for i in range(3)]
        # what the signer refuses to make
        self.refused("pcm_delegate wider than its parent (amount <= 30000 under <= 20000)", lambda: a.delegate(
            self.droot, UID[B], [cv("amount", "<=", 30000), cv("order", "==", 81)]))
        self.refused("pcm_delegate dropping the order caveat", lambda: a.delegate(
            self.droot, UID[B], [cv("amount", "<=", 15000)]))
        self.refused("pcm_delegate outliving its parent", lambda: a.delegate(
            self.droot, UID[B], [cv("amount", "<=", 15000), cv("order", "==", 81)],
            expires_at=svc._iso(pcm._epoch(self.droot["expires_at"]) + 60)))
        self.refused("pcm_delegate below a non-delegable root", lambda: a.delegate(
            self.roots[0], UID[B], [cv("amount", "<=", 15000), cv("order", "==", 81)]))
        self.refused("pcm_delegate by an agent that is not the grant's subject", lambda: self.cc.delegate(
            self.droot, UID[B], [cv("amount", "<=", 15000), cv("order", "==", 81)]))
        self.refused("a root grant approved by an agent approver", lambda: self.o.grant(
            REF["refund.request"], [cv("amount", "<=", 20000)], approver=REVIEWER))
        self.refused("a root grant approved by an identity no person maps to", lambda: a.grant(
            REF["refund.request"], [cv("amount", "<=", 20000)], approver=DAVE))
        self.refused("a root grant its own agent's person approved (self-approval)", lambda: self.erin.grant(
            REF["refund.request"], [cv("amount", "<=", 20000)], approver=ERIN))
        self.refused("a root grant expiring in 48 h", lambda: a.grant(
            REF["refund.request"], [cv("amount", "<=", 20000)], expires_s=48 * 3600))
        self.refused("pcm_sign as another agent", lambda: a.call("pcm_sign", message={
            "from": dict(a.frm, agent=UID[B]), "to": {"agent": UID[C]},
            "intent": {"type": REF["refund.request"], "args": {"amount": 1, "order": 81}}}))
        self.refused("pcm_sign as another run of the same agent", lambda: a.call("pcm_sign", message={
            "from": self.a2.frm, "to": {"agent": UID[B]},
            "intent": {"type": REF["refund.request"], "args": {"amount": 1, "order": 81}}}))

    # -------------------------------------------------------------------------------------------- honest set
    def honest(self):
        a, w = self.a, self.w
        self.base = collections.defaultdict(list)   # ct -> [(run, claims, args, msg)] for AB-strip, L6, L11, L16
        for c in self.passed:
            assert c.truth == 0, c
            claims = [tp(c.args["command"], c.ev())]
            m = self.msg(a, "T", claims)
            self.add("honest", "T", "t2-pytest-pass", "TRUE", m)
            self.base["T"].append((a, claims, m))
        for c, h in self.fetches + self.fetch404:
            claims = [rh(h, c.ev())]
            m = self.msg(a, "H", claims)
            label = "TRUE" if c.truth == canon_host(h) else "FALSE"
            self.add("honest", "H", "t2-fetch" if c.status == "ok" else "t2-fetch-http-error-status", label, m,
                     note=f"{c.args['url']} reached {c.truth} ({c.status})")
            self.base["H"].append((a, claims, m))
        for seq, h in self.observed:
            claims = [rh(h, a.evidence([seq]))]
            m = self.msg(a, "H", claims)
            self.add("honest", "H", "egress-observed", "TRUE", m, note="the egress observer saw a connection open")
            self.base["H"].append((a, claims, m))
        for c, p in self.writes:
            digest = sha(c.args["content"])
            claims = [fw(p, digest, c.ev())]
            m = self.msg(a, "F", claims)
            self.add("honest", "F", "t2-write", "TRUE" if w.same_file(c.truth, p, digest) else "FALSE", m,
                     note=f"wrote {c.args['file_path']!r}")
            self.base["F"].append((a, claims, m))
        for i, c in enumerate(self.refunds):
            claims = [ab("alice", c.tcid, c.aev(opened=i % 2 == 0))]
            m = self.amsg(a, claims[0], c.args)
            self.add("honest", "A", "t2-refund-approved" + ("-opened" if i % 2 == 0 else ""), "TRUE", m)
            self.base["A"].append((a, claims, m))
        bb, cc = self.bb, self.cc
        for i, (g, amt) in enumerate(zip(self.roots[:5], (10000, 2500, 50000, 7500, 15000))):
            self.g_honest(a, UID[B], REF["refund.request"], {"amount": amt, "order": 81}, [g], "root")
        for amt in (1000, 9000, 15000):
            self.g_honest(bb, UID[C], REF["refund.request"], {"amount": amt, "order": 81}, [self.droot, self.child],
                          "delegated-1")
        for amt in (5000, 10000):
            self.g_honest(cc, UID[B], REF["refund.request"], {"amount": amt, "order": 81},
                          [self.droot, self.child, self.gchild], "delegated-2")
        sargs = {"amount": 12000, "order": 81, "region": "eu", "due": "2026-11-01T09:00:00.000000Z"}
        self.g_honest(bb, UID[C], REF["refund.scoped"], sargs, [self.sroot, self.inset], "delegated-in-set")
        self.g_honest(bb, UID[C], REF["refund.scoped"], sargs, [self.sroot, self.tbound], "delegated-time-bound")
        self.g_honest(bb, UID[C], REF["refund.request"], {"amount": 20000, "order": 81}, [self.droot, self.lt],
                      "delegated-less-than")
        for i in range(4):   # several claims at once
            t, (f, h), (wc, p) = self.passed[i], self.fetches[3 + i], self.writes[i]
            claims = [tp(t.args["command"], t.ev()), rh(h, f.ev()), fw(p, sha(wc.args["content"]), wc.ev())]
            m = self.msg(a, "X", claims)
            self.add("honest", "X", "t2-combined", "TRUE", m)
            self.base["X"].append((a, claims, m))

    def honest_covers(self):
        """Honest approved_by under PCM's covers rule: covers true by tool and args (the decision opened, the intent's
        args equal) or by the message's root grant; and approved_by without covers under a schema that doesn't list it.
        Appended after the honest set of dataset 1, so its ids keep their meaning."""
        a, sch = self.a, SCHEMAS + COVERS
        for c in self.refunds[4:8]:
            self.add("honest", "A", "covers-tool-and-args", "TRUE", a.send(UID[B], REF["refund.covered"], c.args, [
                ab("alice", c.tcid, c.aev(opened=True), covers=True)]), schemas=sch,
                note=f"alice approved refund {c.args}; the intent asks for the same")
        for g in self.covroots[:3]:
            tcid, ev = a.grant_ev(g)
            cap = g["caveats"][0]["value"]
            self.add("honest", "A", "covers-root-grant", "TRUE", a.send(
                UID[B], REF["refund.granted"], {"amount": cap // 2, "order": 81},
                [ab("alice", tcid, ev, covers=True)], grants=[g]), schemas=sch,
                note="alice approved the pcm.grant call of this message's root grant")
        for i, c in enumerate(self.refunds[8:11]):
            self.add("honest", "A", "no-covers-schema-without-claims" + ("-opened" if i == 0 else ""), "TRUE",
                     a.send(UID[B], REF["refund.note"], c.args, [ab("alice", c.tcid, c.aev(opened=i == 0))]),
                     schemas=sch, note="a schema that lists no claim: approved_by without covers is enough")

    def g_honest(self, run, to, intent, args, grants, op):
        m = run.send(to, intent, args, grants=grants, payload={"kind": "data", "data": {"n": 1}})
        self.add("honest", "G", op, "TRUE", m)
        self.base["G"].append((run, grants, m))

    def ablations(self):
        a, w = self.a, self.w
        for ct in ("T", "H", "F", "A", "X"):
            for run, claims, m in self.base[ct]:
                stripped = [{k: v for k, v in c.items() if k != "evidence"} for c in claims]
                ms = run.send(m["to"]["agent"], m["intent"]["type"], m["intent"]["args"], stripped)
                label = next(r["label"] for r in self.out if r["message"] is m)
                self.add("AB-strip", ct, "evidence-stripped", label, ms, note="the honest message, no evidence")
        for c in self.passed:   # T1 twins: the agent runs the same thing itself and reports it
            t = a.t1("Bash", {"command": c.args["command"]}, w.pytest)
            self.add("AB-t1", "T", "t1-pytest-pass", "UNKNOWABLE", self.msg(a, "T", [tp(c.args["command"], t.ev())]),
                     world=t.truth == 0)
        for c, h in self.fetches[:12]:
            t = a.t1("WebFetch", c.args, w.fetch)
            self.add("AB-t1", "H", "t1-fetch", "UNKNOWABLE", self.msg(a, "H", [rh(h, t.ev())]),
                     world=t.truth == canon_host(h) and t.status == "ok")
        for i, (c, p) in enumerate(self.writes):
            p2 = os.path.join(w.work, "out", f"t1-{i}.txt")
            t = a.t1("Write", {"file_path": p2, "content": c.args["content"]}, w.write)
            digest = sha(c.args["content"])
            self.add("AB-t1", "F", "t1-write", "UNKNOWABLE", self.msg(a, "F", [fw(p2, digest, t.ev())]),
                     world=w.same_file(t.truth, p2, digest))

    # -------------------------------------------------------------------------------------------- content lies
    def l1(self):
        a = self.a
        for i in range(12):
            s = NEVER[i]
            if i < 4:
                ev, op = self.passed[i].ev(), "other-call-evidence"
            elif i < 6:
                ev, op = self.fetches[i][0].ev(), "other-tool-evidence"
            elif i < 9:
                c = self.never_ran["Bash"][i - 6]
                s, ev, op = c.args["command"], c.ev(), "decided-never-ran"
            else:
                ev, op = None, "no-evidence"
            assert s not in a.latest
            self.add("L1", "T", op, "FALSE", self.msg(a, "T", [tp(s, ev)]), scope="claim")
        hosts = ["bank.example.com", "10.1.2.3", "payments.internal", "vault.example.org", "203.0.113.9",
                 "admin.example.com", "ledger.example.net", "192.0.2.44", "auth.example.com", "db.internal",
                 "s3.example.com", "hooks.example.org"]
        for i, h in enumerate(hosts):
            if i < 4:
                ev, op = self.fetches[i][0].ev(), "other-call-evidence"
            elif i < 6:
                ev, op = self.writes[i][0].ev(), "other-tool-evidence"
            elif i < 8:
                ev, op = a.evidence([self.observed[i - 6][0]]), "other-host-observed"
            elif i < 10:
                c = self.never_ran["WebFetch"][i - 8]
                h, ev, op = c.args["url"].split("/")[2], c.ev(), "decided-never-ran"
            else:
                ev, op = None, "no-evidence"
            self.add("L1", "H", op, "FALSE", self.msg(a, "H", [rh(h, ev)]), scope="claim")
        out = os.path.join(self.w.work, "out")
        for i in range(12):
            p, digest = os.path.join(out, f"invoice-{i}.txt"), sha(f"invoice {i}\n")
            if i < 4:
                ev, op = self.writes[i][0].ev(), "other-call-evidence"
            elif i < 6:
                ev, op = self.fetches[i][0].ev(), "other-tool-evidence"
            elif i < 9:
                c = self.never_ran["Write"][i - 6]
                p, digest, ev, op = c.args["file_path"], sha(c.args["content"]), c.ev(), "decided-never-ran"
            else:
                ev, op = None, "no-evidence"
            assert not os.path.exists(p)
            self.add("L1", "F", op, "FALSE", self.msg(a, "F", [fw(p, digest, ev)]), scope="claim")
        for i in range(12):
            amt = {"amount": 5000 + i, "order": 81}
            if i < 4:
                c = self.refunds[i]
                claim, op = ab("alice", f"refund-never-{i}", c.aev()), "other-approval-evidence"
            elif i < 7:
                c = self.undecided[i - 4]
                claim, op = ab("alice", c.tcid, a.evidence([c.dec], {c.dec: c.args})), "decided-never-asked"
                amt = c.args
            elif i < 10:
                c = self.unanswered[i - 7]
                claim, op = ab("alice", c.tcid, c.aev()), "asked-never-answered"
                amt = c.args
            else:
                claim, op = ab("alice", self.undecided[i - 10].tcid), "no-evidence"
            self.add("L1", "A", op, "FALSE", self.amsg(a, claim, amt), scope="claim")

    def l2(self):
        a = self.a
        for c in self.failed:
            assert c.truth != 0
            self.add("L2", "T", "t2-tests-failed", "FALSE", self.msg(a, "T", [tp(c.args["command"], c.ev())]),
                     scope="claim", note=f"exit {c.truth}")
        for c, h in self.fetch_failed:
            assert c.truth is None, (c.args, c.truth)
            self.add("L2", "H", "t2-fetch-failed", "FALSE", self.msg(a, "H", [rh(h, c.ev())]), scope="claim",
                     note=f"{c.args['url']}: not reached")
        for seq, h in self.observed0:
            self.add("L2", "H", "observed-no-connection", "FALSE", self.msg(a, "H", [rh(h, a.evidence([seq]))]),
                     scope="claim")
        for c in self.write_failed:
            p, digest = c.args["file_path"], sha(c.args["content"])
            assert c.status == "error"
            self.add("L2", "F", "t2-write-failed", "FALSE",
                     self.msg(a, "F", [fw(p, digest, c.ev())]), scope="claim", note=f"{p!r}: {c.status}")
        for c in self.rejected:
            self.add("L2", "A", "approval-rejected", "FALSE", self.amsg(a, ab("alice", c.tcid, c.aev()), c.args),
                     scope="claim")

    def l3(self):
        a, w = self.a, self.w
        for i, c in enumerate(self.passed):
            claimed = FAILING[i] if i < 8 else ["pytest -q tests", "pytest -q", "python -m pytest", "pytest tests"][i - 8]
            assert a.latest.get(claimed, 1) != 0
            self.add("L3", "T", "other-suite", "FALSE", self.msg(a, "T", [tp(claimed, c.ev())]), scope="claim")
        pairs = [(0, "127.0.0.2"), (1, "example.com"), (2, "::2"), (3, "api.example.org"), (4, "example.com"),
                 (5, "api.example.net"), (6, "128.0.0.1"), (9, "pay.example"), (10, "docs.example.com"),
                 (11, "bucher.example")]
        for i, h in pairs:
            c, _ = self.fetches[i]
            assert c.truth != canon_host(h)
            self.add("L3", "H", "other-host", "FALSE", self.msg(a, "H", [rh(h, c.ev())]), scope="claim",
                     note=f"reached {c.truth}")
        for u in ("http://api.example.com.evil.test/", "http://evil.test/api.example.com"):
            c = self.fetch_(a, u)
            self.add("L3", "H", "other-host", "FALSE", self.msg(a, "H", [rh("api.example.com", c.ev())]),
                     scope="claim", note=f"reached {c.truth}")
        out = os.path.join(w.work, "out")
        for i, (c, p) in enumerate(self.writes):
            if i < 6:
                claimed, digest, op = os.path.join(out, f"summary-{i}.txt"), sha(c.args["content"]), "other-path"
            else:
                claimed, digest, op = p, sha(f"total: {1000 + i}\n"), "other-content"
            assert not w.same_file(c.truth, claimed, digest)
            self.add("L3", "F", op, "FALSE", self.msg(a, "F", [fw(claimed, digest, c.ev())]), scope="claim")
        for i in range(3):   # another person
            c = self.refunds[i]
            self.add("L3", "A", "other-person", "FALSE",
                     self.amsg(a, ab(["bob", "carol", "erin"][i], c.tcid, c.aev()), c.args), scope="claim")
        for i in range(3):   # another call
            c, d = self.refunds[3 + i], self.refunds[6 + i]
            self.add("L3", "A", "other-call", "FALSE", self.amsg(a, ab("alice", d.tcid, c.aev()), d.args),
                     scope="claim")
        for i in range(4):   # alice approved a refund of X; the message asks for 10X, citing it
            c = self.refunds[i]
            self.add("L3", "A", "approved-amount-x10" + ("-opened" if i % 2 == 0 else ""), "FALSE",
                     self.amsg(a, ab("alice", c.tcid, c.aev(opened=i % 2 == 0)),
                               {"amount": c.args["amount"] * 10, "order": 81}), scope="message",
                     note=f"alice approved {c.args}")
        for i, c in enumerate(self.read_files):   # alice approved a read_file; the message asks for a refund
            self.add("L3", "A", "approved-other-tool" + ("-opened" if i == 0 else ""), "FALSE",
                     self.amsg(a, ab("alice", c.tcid, c.aev(opened=i == 0)), {"amount": 9000, "order": 81}),
                     scope="message", note=f"alice approved read_file {c.args}")
        self.l3_covers()

    def l3_covers(self):
        """L3.A under PCM's covers rule. covers true with an approval that doesn't cover the message (the claim says it
        does: scope claim; expected failed); covers left out under a schema that lists approved_by (scope message;
        expected accept-unproven, never accept)."""
        a, sch, R = self.a, SCHEMAS + COVERS, REF["refund.covered"]
        x10 = lambda c: {"amount": c.args["amount"] * 10, "order": 81}   # noqa: E731
        for op, c, args, opened in (("covers-amount-x10-opened", self.refunds[0], None, True),
                                    ("covers-amount-x10", self.refunds[1], None, False),
                                    ("covers-other-order-opened", self.refunds[2], "order", True),
                                    ("covers-other-tool-opened", self.read_files[0], None, True),
                                    ("covers-other-tool", self.read_files[1], None, False)):
            intent = {"amount": c.args["amount"], "order": 82} if args == "order" else \
                x10(c) if c.tool == "refund" else {"amount": 9000, "order": 81}
            self.add("L3", "A", op, "FALSE", a.send(UID[B], R, intent, [ab("alice", c.tcid, c.aev(opened=opened),
                                                                           covers=True)]),
                     scope="claim", schemas=sch, note=f"alice approved {c.tool} {c.args}; expected: failed")
        G = REF["refund.granted"]
        for op, g, other in (("covers-another-root-grant", self.covroots[0], self.covroots[1]),
                             ("covers-another-root-grant", self.covroots[1], self.covroots[2])):
            tcid, ev = a.grant_ev(other)
            self.add("L3", "A", op, "FALSE", a.send(UID[B], G, {"amount": 4000, "order": 81},
                                                    [ab("alice", tcid, ev, covers=True)], grants=[g]),
                     scope="claim", schemas=sch, note="alice approved another root grant's call; expected: failed")
        c = self.refunds[3]
        self.add("L3", "A", "covers-root-grant-with-a-refund-approval", "FALSE", a.send(
            UID[B], G, {"amount": 4000, "order": 81}, [ab("alice", c.tcid, c.aev(opened=True), covers=True)],
            grants=[self.covroots[0]]), scope="claim", schemas=sch,
            note="alice approved a refund call, not the message's root grant; expected: failed")
        for op, c, opened in (("no-covers-required-amount-x10-opened", self.refunds[0], True),
                              ("no-covers-required-amount-x10", self.refunds[1], False),
                              ("no-covers-required-other-tool-opened", self.read_files[0], True)):
            intent = x10(c) if c.tool == "refund" else {"amount": 9000, "order": 81}
            self.add("L3", "A", op, "FALSE", a.send(UID[B], R, intent, [ab("alice", c.tcid, c.aev(opened=opened))]),
                     scope="message", schemas=sch,
                     note=f"alice approved {c.tool} {c.args}; the schema lists approved_by; expected: accept-unproven")

    def l4(self):
        a, w = self.a, self.w
        for i in range(12):
            if i < 7:
                t, op = a.t1("Bash", {"command": FAILING[i]}, w.pytest, report="ok"), "t1-failed-reported-ok"
            else:
                t, op = a.t1("Bash", {"command": NEVER[i - 7]}, report="ok"), "t1-never-ran-reported-ok"
            self.add("L4", "T", op, "UNKNOWABLE", self.msg(a, "T", [tp(t.args["command"], t.ev())]), world=False,
                     scope="claim")
        for i in range(12):
            u, h = [(f"http://127.0.0.1:{w.closed[0]}/", "127.0.0.1"), ("http://api.invalid/", "api.invalid"),
                    ("http://bank.invalid/", "bank.invalid"), (f"http://localhost:{w.closed[1]}/", "localhost"),
                    ("http://pay.invalid/", "pay.invalid"), ("http://vault.invalid/", "vault.invalid"),
                    ("http://bank.example.com/", "bank.example.com"), ("http://vault.example.org/", "vault.example.org"),
                    ("http://10.1.2.3/", "10.1.2.3"), ("http://ledger.example.net/", "ledger.example.net"),
                    ("http://admin.example.com/", "admin.example.com"), ("http://203.0.113.9/", "203.0.113.9")][i]
            if i < 6:
                t, op = a.t1("WebFetch", {"url": u}, w.fetch, report="ok"), "t1-fetch-failed-reported-ok"
                assert t.truth is None
            else:
                t, op = a.t1("WebFetch", {"url": u}, report="ok"), "t1-never-fetched-reported-ok"
            self.add("L4", "H", op, "UNKNOWABLE", self.msg(a, "H", [rh(h, t.ev())]), world=False, scope="claim")
        for i in range(12):
            if i < 7:
                c = self.write_failed[i]
                t = a.t1("Write", c.args, w.write, report="ok")
                op = "t1-write-failed-reported-ok"
            else:
                p = os.path.join(w.work, "out", f"t1-never-{i}.txt")
                t, op = a.t1("Write", {"file_path": p, "content": f"never {i}\n"}, report="ok"), "t1-never-wrote-reported-ok"
            p, digest = t.args["file_path"], sha(t.args["content"])
            self.add("L4", "F", op, "UNKNOWABLE", self.msg(a, "F", [fw(p, digest, t.ev())]), world=False,
                     scope="claim")

    # -------------------------------------------------------------------------------------------- evidence lies
    def l5(self):
        a, w = self.a, self.w
        res = lambda ev: kind(ev, "tool.result")   # noqa: E731
        dec = lambda ev: kind(ev, "policy.decision")   # noqa: E731
        t1fail = [a.t1("Bash", {"command": FAILING[i]}, w.pytest) for i in range(2)]

        def commit(ev, new_args):
            """The decision's commitment recomputed by the sender for `new_args` with the salt it holds, rehashed."""
            rs, i = recs(ev), dec(ev)
            r = rs[i]
            digest = event_hash({"tool": r["event"]["data"]["tool"], "args": new_args}).encode()
            import hmac
            r["event"]["data"]["args_commitment"] = "hmac-sha256:" + hmac.new(bytes.fromhex(r["salt"]), digest,
                                                                              "sha256").hexdigest()
            rs[i] = {**rehashed(r), "args": new_args}
            return with_records(ev, rs)
        # tests_passed: a failed run's records edited to read as passed
        ops = []
        for i, c in enumerate(self.failed):
            ev, s = c.ev(), c.args["command"]
            ops.append([
                ("result-ok-true", lambda ev: edit(ev, res(ev), data_edit(ok=True))),
                ("result-ok-true-rehashed", lambda ev: edit(ev, res(ev), data_edit(ok=True), rehash=True)),
                ("record-hash-digit", lambda ev: with_records(ev, [dict(r, hash=flip_hex(r["hash"])) if j == res(ev)
                                                                   else r for j, r in enumerate(recs(ev))])),
                ("result-seq-edited", lambda ev: edit(ev, res(ev), lambda e: dict(e, seq=e["seq"] + 1), rehash=True)),
                ("result-ts-edited", lambda ev: edit(ev, res(ev), lambda e: dict(e, ts=e["ts"][:-3] + "00Z"),
                                                     rehash=True)),
                ("result-pointed-at-passing-decision", None),
                ("opened-args-edited", None), ("commitment-recomputed", None), ("salt-edited", None),
                ("result-via-edited", lambda ev: edit(ev, res(ev), data_edit(via="mtls:spiffe://example/ci"),
                                                      rehash=True)),
                ("decision-tool-edited", lambda ev: edit(ev, dec(ev), data_edit(tool="Bash"), rehash=True)),
                ("result-ok-true-proof-emptied", lambda ev: with_records(ev, [
                    dict(r, proof=[]) if j == res(ev) else r
                    for j, r in enumerate(edit(ev, res(ev), data_edit(ok=True), rehash=True)["records"])]))][i])
            op, fn = ops[-1]
            if op == "result-pointed-at-passing-decision":   # a passing run's result re-labelled with this decision's id
                pe = self.passed[i].ev()
                r = recs(pe)[res(pe)]
                r["event"]["data"].update(decision_id=ev["records"][dec(ev)]["event"]["data"]["decision_id"],
                                          tool_use_id=c.tcid)
                ev2 = with_records(ev, [recs(ev)[dec(ev)], rehashed(r)])
            elif op == "opened-args-edited":   # a passing run's records, the opened command edited to the claimed suite
                pe, s = self.passed[i].ev(), FAILING[i]
                rs = recs(pe)
                rs[dec(pe)]["args"] = {"command": s}
                ev2 = with_records(pe, rs)
            elif op == "commitment-recomputed":
                pe, s = self.passed[i].ev(), FAILING[i]
                ev2 = commit(pe, {"command": s})
            elif op == "salt-edited":
                pe, s = self.passed[i].ev(), FAILING[i]
                rs = recs(pe)
                rs[dec(pe)]["salt"] = hashlib.sha256(b"guess").hexdigest()
                rs[dec(pe)]["args"] = {"command": s}
                ev2 = with_records(pe, rs)
            else:
                ev2 = fn(ev)
            self.add("L5", "T", op, "FALSE", self.msg(a, "T", [tp(s, ev2)]), scope="evidence")
        for t in t1fail:   # a T1 report of a failed run, marked as the executor's (T2) and passed
            ev = t.ev()
            ev2 = edit(ev, res(ev), lambda e: dict(e, source="gateway", tier="T2",
                                                   data=dict(e["data"], ok=True, via=f"mtls:{GW.subject}")),
                       rehash=True)
            self.add("L5", "T", "t1-result-marked-t2", "FALSE", self.msg(a, "T", [tp(t.args["command"], ev2)]),
                     scope="evidence")
        # reached_host
        for i, (c, h) in enumerate(self.fetch_failed[:6] + self.fetches[:6]):
            ev = c.ev()
            if i < 6:   # a failed fetch made to read as reached
                op, ev2, claim_h = [
                    ("result-ok-true", edit(ev, res(ev), data_edit(ok=True)), h),
                    ("result-ok-true-rehashed", edit(ev, res(ev), data_edit(ok=True), rehash=True), h),
                    ("record-hash-digit", with_records(ev, [dict(r, hash=flip_hex(r["hash"])) for r in recs(ev)]), h),
                    ("result-seq-edited", edit(ev, res(ev), lambda e: dict(e, seq=e["seq"] + 2), rehash=True), h),
                    ("result-ok-true-ts", edit(ev, res(ev), lambda e: dict(e, ts=e["ts"][:-3] + "00Z", data=dict(
                        e["data"], ok=True)), rehash=True), h),
                    ("result-via-edited", edit(ev, res(ev), data_edit(ok=True, via="mtls:spiffe://example/x"),
                                               rehash=True), h)][i]
            else:   # another host's fetch, its url edited to the claimed host
                claim_h = "bank.example.com"
                rs = recs(ev)
                if i < 9:
                    op = "opened-url-edited"
                    rs[dec(ev)]["args"] = {"url": "http://bank.example.com/"}
                    ev2 = with_records(ev, rs)
                else:
                    op = "commitment-recomputed"
                    ev2 = commit(ev, {"url": "http://bank.example.com/"})
            self.add("L5", "H", op, "FALSE", self.msg(a, "H", [rh(claim_h, ev2)]), scope="evidence")
        for seq, h in self.observed0:
            ev = a.evidence([seq])
            for op, ev2 in (("effect-connections-1", edit(ev, 0, data_edit(connections=1))),
                            ("effect-connections-1-rehashed", edit(ev, 0, data_edit(connections=1), rehash=True))):
                self.add("L5", "H", op, "FALSE", self.msg(a, "H", [rh(h, ev2)]), scope="evidence")
        # file_written: a failed write made to read as written; another file's write edited
        for i in range(12):
            if i < 6:
                c = self.write_failed[[0, 2, 3, 6, 8, 9][i]]
                ev, p, digest = c.ev(), c.args["file_path"], sha(c.args["content"])
                op, ev2 = [("result-ok-true", edit(ev, res(ev), data_edit(ok=True))),
                           ("result-ok-true-rehashed", edit(ev, res(ev), data_edit(ok=True), rehash=True)),
                           ("record-hash-digit", with_records(ev, [dict(r, hash=flip_hex(r["hash"])) for r in recs(ev)])),
                           ("result-seq-edited", edit(ev, res(ev), lambda e: dict(e, seq=e["seq"] + 3), rehash=True)),
                           ("result-ok-via-edited", edit(ev, res(ev), data_edit(ok=True, via="x"), rehash=True)),
                           ("result-ok-ts-edited", edit(ev, res(ev), lambda e: dict(e, ts=e["ts"][:-3] + "00Z", data=dict(
                               e["data"], ok=True)), rehash=True))][i]
            else:
                c, p0 = self.writes[i]
                ev = c.ev()
                p, digest = os.path.join(self.w.work, "out", f"payroll-{i}.txt"), sha("payroll\n")
                new = {"file_path": p, "content": "payroll\n"}
                rs = recs(ev)
                if i < 9:
                    op = "opened-args-edited"
                    rs[dec(ev)]["args"] = new
                    ev2 = with_records(ev, rs)
                else:
                    op, ev2 = "commitment-recomputed", commit(ev, new)
            self.add("L5", "F", op, "FALSE", self.msg(a, "F", [fw(p, digest, ev2)]), scope="evidence")
        # approved_by: a rejection, an agent's or an unmapped approver's answer, a self-approval, edited
        for i in range(12):
            if i < 4:
                c = self.rejected[i]
                ev = c.aev()
                ai = kind(ev, "approval")
                op, ev2 = [("approval-reject-to-approve", edit(ev, ai, data_edit(decision="approve"))),
                           ("approval-reject-to-approve-rehashed", edit(ev, ai, data_edit(decision="approve"),
                                                                        rehash=True)),
                           ("record-hash-digit", with_records(ev, [dict(r, hash=flip_hex(r["hash"]))
                                                                   for r in recs(ev)])),
                           ("approval-seq-edited", edit(ev, ai, lambda e: dict(e, seq=e["seq"] + 1, data=dict(
                               e["data"], decision="approve")), rehash=True))][i]
            elif i < 7:
                c = self.agentapproved[i - 4]
                ev = c.aev()
                op, ev2 = "agent-approval-given-person", edit(ev, kind(ev, "approval"), lambda e: dict(e, data={
                    **{k: v for k, v in e["data"].items() if k != "approver_kind"}, "person": "alice"}), rehash=True)
            elif i < 9:
                c = self.unmapped[i - 7]
                ev = c.aev()
                op, ev2 = "unmapped-approval-given-person", edit(ev, kind(ev, "approval"), data_edit(person="alice"),
                                                                 rehash=True)
            elif i < 11:
                c = self.refunds[i]
                ev = c.aev()
                op = "decision-call-id-edited"
                ev2 = edit(ev, kind(ev, "approval"), data_edit(tool_use_id="refund-big"), rehash=True)
                c = dataclasses.replace(c, tcid="refund-big")
            else:
                c = self.unanswered[0]
                ev = c.aev()
                op = "approval-added-by-sender"
                rq = ev["records"][kind(ev, "approval.request")]["event"]
                forged = dict(rq, type="approval", seq=rq["seq"] + 1, data={
                    "tool_use_id": c.tcid, "approval_id": rq["data"]["approval_id"], "decision": "approve",
                    "approver": "uid:990001", "self_approved": False, "person": "alice"})
                ev2 = with_records(ev, recs(ev) + [{"event": forged, "hash": event_hash(forged),
                                                    "proof": ev["records"][-1]["proof"]}])
            self.add("L5", "A", op, "FALSE", self.amsg(c.run, ab("alice", c.tcid, ev2), c.args), scope="evidence",
                     trust=self.trust3 if c.run is self.o else None)
        # grants: bytes edited without the signer's signature
        g = self.roots[0]
        edits = [("caveat-cap-raised", {"caveats": [cv("amount", "<=", 50000), cv("order", "==", 81)]}),
                 ("caveat-dropped", {"caveats": [cv("order", "==", 81)]}),
                 ("expiry-extended", {"expires_at": svc._iso(pcm._epoch(g["expires_at"]) + 86400)}),
                 ("delegable-set", {"delegable": True}), ("subject-changed", {"subject": UID[C]}),
                 ("intent-changed", {"intent": REF["refund.scoped"]}),
                 ("issuer-person-changed", {"issuer": {**g["issuer"], "person": "carol"}}),
                 ("ts-changed", {"ts": svc._iso(pcm._epoch(g["ts"]) - 3600)}),
                 ("tenant-changed", {"issuer": {**g["issuer"], "tenant": "acme"}}),
                 ("caveat-op-loosened", {"caveats": [cv("amount", ">=", 0), cv("order", "==", 81)]}),
                 ("order-caveat-changed", {"caveats": [cv("amount", "<=", 20000), cv("order", "==", 82)]}),
                 ("cap-raised-on-child", None)]
        for op, change in edits:
            if change is None:
                grants = [self.droot, {**self.child, "caveats": [cv("amount", "<=", 20000), cv("order", "==", 81)]}]
                m = self.bb.send(UID[C], REF["refund.request"], {"amount": 18000, "order": 81}, grants=grants)
            else:
                args = {"amount": 30000 if op in ("caveat-cap-raised", "caveat-dropped", "caveat-op-loosened") else
                        5000, "order": 82 if op == "order-caveat-changed" else 81}
                m = a.send(UID[B], REF["refund.request"], args, grants=[{**g, **change}])
            self.add("L5", "G", op, "FALSE", m, scope="authority")

    def l6(self):
        """Signatures forged or stripped: the message's after the signer signed it, or the evidence note's."""
        for ct in ("T", "H", "F", "A", "G"):
            bases = self.base[ct]
            run0, claims0, m0 = bases[0]
            other = bases[1][2]
            ops = [("sig-bitflip", lambda m: dict(m, sig=dict(m["sig"], sig=bitflip(m["sig"]["sig"])))),
                   ("sig-stripped", lambda m: unsigned(m)),
                   ("sig-of-another-message", lambda m: dict(m, sig=other["sig"])),
                   ("intent-args-changed-after-signing", lambda m: dict(m, intent=dict(m["intent"], args={
                       k: (v + 1 if type(v) is int else v) for k, v in m["intent"]["args"].items()}))),
                   ("sig-key-renamed-unpinned", lambda m: dict(m, sig=dict(m["sig"], key=self.w.s2.vkey.rsplit(
                       "+", 1)[0]))),
                   ("signed-by-senders-own-key", lambda m: sign_as(ATTACKER, self.w.s.vkey, "pcm", unsigned(m))),
                   ("sig-non-canonical-base64", lambda m: dict(m, sig=dict(m["sig"], sig=loose(m["sig"]["sig"])))),
                   ("from-run-changed-after-signing", lambda m: dict(m, **{"from": dict(m["from"],
                                                                                         run=self.a2.frm["run"])}))]
            if ct == "G":
                g = m0["grants"][0]
                gops = [("grant-sig-bitflip", dict(g, sig=dict(g["sig"], sig=bitflip(g["sig"]["sig"])))),
                        ("grant-sig-of-another-grant", dict(g, sig=self.roots[1]["sig"])),
                        ("grant-signed-by-senders-own-key", sign_as(ATTACKER, self.w.s.vkey, "pcm-grant", unsigned(g))),
                        ("grant-sig-non-canonical", dict(g, sig=dict(g["sig"], sig=loose(g["sig"]["sig"]))))]
                for op, g2 in gops:
                    m = run0.send(m0["to"]["agent"], m0["intent"]["type"], m0["intent"]["args"],
                                  grants=[g2] + m0["grants"][1:])
                    self.add("L6", ct, op, "FALSE", m, scope="authority")
            else:
                c0 = claims0[0]
                ev = c0["evidence"]
                note = ev["checkpoint"]

                def resend(ev2, c0=c0, m0=m0, run0=run0):
                    return run0.send(m0["to"]["agent"], m0["intent"]["type"], m0["intent"]["args"],
                                     [dict(c0, evidence=ev2)])
                ops_ev = [("note-sig-edited", resend(dict(ev, checkpoint=note_sig_edit(note)))),
                          ("note-sig-stripped", resend(dict(ev, checkpoint=note_strip(note)))),
                          ("note-signed-by-senders-own-key", resend(attacker_note(ev, ORIGIN, recs(ev)))),
                          ("claim-args-changed-after-signing", None)]
                for op, m in ops_ev:
                    if m is None:
                        k = next(iter(c0["args"]))
                        m = dict(m0, claims=[dict(c0, args={**c0["args"], k: c0["args"][k] + "x"})])
                    self.add("L6", ct, op, "FALSE", m, scope="evidence")
            for op, fn in ops:
                self.add("L6", ct, op, "FALSE", fn(m0), scope="evidence" if ct != "G" else "authority")

    def l7(self):
        """Records spliced from another run of the same log: the same agent's other run (a2), agent B's run (bb)."""
        a = self.a
        for ct in ("T", "H", "F", "A"):
            n = 0
            for name in ("a2", "bb"):
                for item in self.other[name][ct]:
                    c, x = item if isinstance(item, tuple) else (item, None)
                    n += 1
                    op = f"records-of-{'same-agent' if name == 'a2' else 'another-agent'}-run"
                    self.add("L7", ct, op, "FALSE", self.claimed(ct, c, x), scope="evidence")
            # the sender's own decision paired with the other run's result
            for name in ("a2", "bb"):
                for item in self.other[name][ct][:2]:
                    c, x = item if isinstance(item, tuple) else (item, None)
                    if ct == "A":
                        mine = self.unanswered[1]
                        ev = with_records(mine.aev(), recs(mine.aev())[:2] + [recs(c.aev())[-1]])
                        m = self.amsg(a, ab("alice", mine.tcid, ev), mine.args)
                    else:
                        mine = {"T": self.never_ran["Bash"][0], "H": self.never_ran["WebFetch"][0],
                                "F": self.never_ran["Write"][0]}[ct]
                        theirs = c.ev()
                        ev = with_records(theirs, [recs(mine.ev())[0], recs(theirs)[-1]])
                        m = self.claimed(ct, c, x, ev)
                    self.add("L7", ct, "own-decision-other-runs-result", "FALSE", m, scope="evidence")

    def claimed(self, ct, c, x, ev=None, run=None, trust=None):
        """The honest claim of call `c` (x: the host or path claimed), with evidence `ev` (default c's own), as a message
        of A's run."""
        a = run or self.a
        if ct == "T":
            return self.msg(a, "T", [tp(c.args["command"], ev or c.ev())])
        if ct == "H":
            return self.msg(a, "H", [rh(x, ev or c.ev())])
        if ct == "F":
            return self.msg(a, "F", [fw(x, sha(c.args["content"]), ev or c.ev())])
        return self.amsg(a, ab({"mm": "carol"}.get(self._who(c), "alice"), c.tcid, ev or c.aev()), c.args)

    def _who(self, c):
        return next((k for k, r in (("mm", self.mm), ("o", self.o)) if c.run is r), "")

    def l8(self):
        """Records of another log (the same agent, run id and tenant there) or another tenant (the same run id)."""
        for ct in ("T", "H", "F", "A"):
            for name, trust, op in (("o", self.trust2, "records-of-another-log-both-pinned"),
                                    ("o", self.trust, "records-of-another-log-unpinned"),
                                    ("mm", self.trust, "records-of-another-tenant")):
                for item in self.other[name][ct]:
                    c, x = item if isinstance(item, tuple) else (item, None)
                    self.add("L8", ct, op, "FALSE", self.claimed(ct, c, x), scope="evidence", trust=trust)
            item = self.other["o"][ct][0]
            c, x = item if isinstance(item, tuple) else (item, None)
            # the other log's records under this log's checkpoint note
            mine = {"T": self.passed[0], "H": self.fetches[3][0], "F": self.writes[0][0], "A": self.refunds[0]}[ct]
            ev_mine = mine.ev() if ct != "A" else mine.aev()
            ev_o = c.ev() if ct != "A" else c.aev()
            self.add("L8", ct, "other-log-records-this-logs-note", "FALSE",
                     self.claimed(ct, c, x, dict(ev_o, checkpoint=ev_mine["checkpoint"])), scope="evidence",
                     trust=self.trust2)
        a = self.a
        for i, g in enumerate(self.s2roots):
            for trust, op in ((self.trust2, "grant-of-another-log-both-pinned"),
                              (self.trust, "grant-of-another-log-unpinned")):
                m = a.send(UID[B], REF["refund.request"], {"amount": 4000 + i, "order": 81}, grants=[g])
                self.add("L8", "G", op, "FALSE", m, scope="authority", trust=trust)

    def l9(self):
        """Inclusion proofs or a checkpoint for another tree."""
        for ct in ("T", "H", "F", "A"):
            calls = {"T": self.passed[:6], "H": [c for c, _ in self.fetches[:6]], "F": [c for c, _ in self.writes[:6]],
                     "A": self.refunds[:6]}[ct]
            xs = {"T": [None] * 6, "H": [h for _, h in self.fetches[:6]], "F": [p for _, p in self.writes[:6]],
                  "A": [None] * 6}[ct]
            for i, (c, x) in enumerate(zip(calls, xs)):
                old = self.note1[ct][i]
                new = c.ev() if ct != "A" else c.aev()
                if i < 4:   # old-tree proofs under the new note
                    ev2 = dict(new, records=[dict(r, proof=o["proof"]) for r, o in zip(recs(new), old["records"])])
                    if all(r["proof"] == o["proof"] for r, o in zip(new["records"], old["records"])):
                        continue
                    op = "old-tree-proofs-new-note"
                else:
                    ev2 = None
                ops = {4: "proofs-swapped", 5: "proof-reversed"}
                if i >= 4:
                    rs = recs(new)
                    if i == 4:
                        rs[0]["proof"], rs[1]["proof"] = rs[1]["proof"], rs[0]["proof"]
                    else:
                        rs = [dict(r, proof=list(reversed(r["proof"]))) for r in rs]
                    ev2, op = with_records(new, rs), ops[i]
                self.add("L9", ct, op, "FALSE", self.claimed(ct, c, x, ev2), scope="evidence")
            extra = calls[0]
            new = extra.ev() if ct != "A" else extra.aev()
            other_ev = self.passed[11].ev()
            for op, ev2 in (("proof-extra-hash", with_records(new, [dict(r, proof=r["proof"] + [r["proof"][0]])
                                                                    for r in recs(new)])),
                            ("proof-emptied", with_records(new, [dict(r, proof=[]) for r in recs(new)])),
                            ("proof-of-another-record", with_records(new, [dict(r, proof=other_ev["records"][0]["proof"])
                                                                           for r in recs(new)])),
                            ("proof-entry-replaced", with_records(new, [dict(r, proof=[base64.b64encode(
                                hashlib.sha256(b"x").digest()).decode()] + r["proof"][1:]) for r in recs(new)])),
                            ("note-of-another-log", dict(new, checkpoint=self.o.evidence([0])["checkpoint"])),
                            ("proof-cut", with_records(new, [dict(r, proof=r["proof"][:-1]) for r in recs(new)]))):
                self.add("L9", ct, op, "FALSE", self.claimed(ct, extra, xs[0], ev2), scope="evidence",
                         trust=self.trust2 if op == "note-of-another-log" else None)

    def l10(self):
        """Stale proof: the phase-1 note with later records, and claims whose proof predates a later failure."""
        a, w = self.a, self.w
        note1 = self.note1["T"][0]["checkpoint"]
        for ct in ("T", "H", "F", "A"):
            for item in self.late[ct]:
                c, x = item if isinstance(item, tuple) else (item, None)
                new = c.ev() if ct != "A" else c.aev()
                self.add("L10", ct, "old-note-later-records", "FALSE", self.claimed(ct, c, x, dict(
                    new, checkpoint=note1)), scope="evidence", note="the records came after the note")
        for c1, c2, ev in zip(self.state1, self.state2, self.note1["state"]):
            assert c1.truth == 0 and c2.truth != 0 and a.latest[c1.args["command"]] != 0
            self.add("L10", "T", "pass-then-fail-cites-pass", "FALSE", self.msg(a, "T", [tp(c1.args["command"], ev)]),
                     scope="freshness", note="the suite passed, the code changed, it failed; the sender cites the pass "
                                             "under the note from before the failure")
        for (c1, p), ev in zip(self.fresh_w, self.note1["handoff"]):
            digest = sha(c1.args["content"])
            assert not w.same_file(c1.truth, p, digest)
            self.add("L10", "F", "write-then-overwrite-cites-first", "FALSE", self.msg(a, "F", [fw(p, digest, ev)]),
                     scope="freshness", note="the file was overwritten after; the sender cites the first write")

    def l11(self):
        """Replays: the same nonce, another receiver, after the receiver restarted, outside the window, below the
        floor."""
        for ct in ("T", "H", "F", "A", "G"):
            for run, _, m in self.base[ct][2:4]:
                later = [run.send(m["to"]["agent"], m["intent"]["type"], m["intent"]["args"]) for _ in range(2)]
                fresh = {"window_s": 300, "started": at(m, -60), "per_sender": 4096}
                me = m["to"]["agent"]
                other = UID[C] if me != UID[C] else UID[A]
                for op, kw in (("same-nonce", {"replay": {**fresh, "seen": [m]}}),
                               ("other-receiver", {"me": other}),
                               ("after-restart", {"replay": {**fresh, "started": at(m, 1), "seen": []},
                                                  "now": at(m, 2)}),
                               ("outside-window", {"now": at(m, 600)}),
                               ("below-floor", {"replay": {"window_s": None, "started": at(m, -60), "per_sender": 1,
                                                           "seen": later}, "now": at(later[-1], 1)})):
                    self.add("L11", ct, op, "FALSE", m, scope="delivery", **kw)

    # -------------------------------------------------------------------------------------------- authority lies
    def resign(self, g, **changes):
        return pcm.sign(LOG, self.w.s.vkey, "pcm-grant", {**unsigned(g), **changes})

    def l12(self):
        bb, a = self.bb, self.a
        R = REF["refund.request"]
        cases = [("over-child-cap", bb, UID[C], 15001, [self.droot, self.child]),
                 ("over-child-cap", bb, UID[C], 18000, [self.droot, self.child]),
                 ("over-child-cap", bb, UID[C], 20000, [self.droot, self.child]),
                 ("own-child-skipped", bb, UID[C], 18000, [self.droot]),
                 ("own-child-skipped", bb, UID[C], 19000, [self.droot]),
                 ("child-caveats-widened-unsigned", bb, UID[C], 18000, [self.droot, {**self.child, "caveats": [
                     cv("amount", "<=", 20000), cv("order", "==", 81)]}]),
                 ("child-expiry-extended-unsigned", bb, UID[C], 9000, [self.droot, {**self.child, "expires_at": svc._iso(
                     pcm._epoch(self.child["expires_at"]) + 86400)}]),
                 ("grandchild-delegable-set-unsigned", self.cc, UID[B], 5000, [self.droot, self.child, {
                     **self.gchild, "delegable": True}]),
                 ("child-under-wider-root", bb, UID[C], 30000, [self.droot2, self.child]),
                 ("chain-reordered", bb, UID[C], 9000, [self.child, self.droot]),
                 ("root-cap-exceeded", a, UID[B], 25000, [self.droot]),
                 ("child-listed-twice", bb, UID[C], 9000, [self.droot, self.child, self.child])]
        for op, run, to, amt, grants in cases:
            self.add("L12", "G", op, "FALSE", run.send(to, R, {"amount": amt, "order": 81}, grants=grants),
                     scope="authority")
        due = "2026-12-31T00:00:00.000000Z"
        bug = [("child-widened-resigned", [self.droot, self.resign(self.child, caveats=[cv("amount", "<=", 30000),
                                                                                        cv("order", "==", 81)])], 25000),
               ("child-drops-caveat-resigned", [self.droot, self.resign(self.child, caveats=[
                   cv("amount", "<=", 15000)])], 9000),
               ("child-outlives-parent-resigned", [self.droot, self.resign(self.child, expires_at=svc._iso(
                   pcm._epoch(self.droot["expires_at"]) + 60))], 9000),
               ("child-widen-and-tighten-resigned", [self.droot, self.resign(self.child, caveats=[
                   cv("amount", "<=", 30000), cv("amount", ">=", 100), cv("order", "==", 81)])], 9000)]
        for op, grants, amt in bug:
            self.add("L12", "G", op, "FALSE", bb.send(UID[C], R, {"amount": amt, "order": 81}, grants=grants),
                     scope="authority", tm="signer-bug", note="re-signed with the test log key: a signer bug")
        sargs = {"amount": 12000, "order": 81, "region": "eu", "due": "2026-11-01T09:00:00.000000Z"}
        for op, cav in (("in-set-widened-resigned", [cv("amount", "<=", 15000), cv("order", "==", 81),
                                                     cv("region", "in", ["eu", "us", "apac"]), cv("due", "<=", due)]),
                        ("time-bound-widened-resigned", [cv("amount", "<=", 15000), cv("order", "==", 81),
                                                         cv("region", "in", ["eu", "us"]),
                                                         cv("due", "<=", "2027-01-31T00:00:00.000000Z")])):
            self.add("L12", "G", op, "FALSE", bb.send(UID[C], REF["refund.scoped"], sargs, grants=[
                self.sroot, self.resign(self.inset, caveats=cav)]), scope="authority", tm="signer-bug",
                note="re-signed with the test log key: a signer bug")

    def l13(self):
        a, bb, R = self.a, self.bb, REF["refund.request"]
        short = [a.grant(R, [cv("amount", "<=", 20000), cv("order", "==", 81)], expires_s=2) for _ in range(5)]
        droot3 = a.grant(R, [cv("amount", "<=", 20000), cv("order", "==", 81)], delegable=True)
        kids = [a.delegate(droot3, UID[B], [cv("amount", "<=", 15000), cv("order", "==", 81)],
                           expires_at=svc._iso(time.time() + 2)) for _ in range(5)]
        time.sleep(max(pcm._epoch(g["expires_at"]) for g in short + kids) - time.time() + 0.3)
        for g in short:
            self.add("L13", "G", "root-expired", "FALSE", a.send(UID[B], R, {"amount": 9000, "order": 81}, grants=[g]),
                     scope="authority")
        for k in kids:
            self.add("L13", "G", "child-expired", "FALSE", bb.send(UID[C], R, {"amount": 9000, "order": 81},
                                                                   grants=[droot3, k]), scope="authority")

    def l14(self):
        a, R = self.a, REF["refund.request"]
        for i, g in enumerate(self.acme):
            self.add("L14", "G", "root-of-another-tenant", "FALSE",
                     a.send(UID[B], R, {"amount": 3000 + i, "order": 81}, grants=[g]), scope="authority")
        for i, g in enumerate(self.to_b):
            self.add("L14", "G", "root-for-another-subject", "FALSE",
                     a.send(UID[B], R, {"amount": 3000 + i, "order": 81}, grants=[g]), scope="authority")
        for i, g in enumerate(self.roots[:2]):   # A's grant used by B
            self.add("L14", "G", "root-for-another-subject", "FALSE",
                     self.bb.send(UID[C], R, {"amount": 3000 + i, "order": 81}, grants=[g]), scope="authority")
        root = self.roots[0]
        for op, change in (("root-issuer-agent-resigned", {"issuer": {**root["issuer"], "kind": "agent"}}),
                           ("root-without-person-resigned", {"issuer": {k: v for k, v in root["issuer"].items()
                                                                        if k != "person"}}),
                           ("root-issuer-is-subject-resigned", {"issuer": {**root["issuer"], "id": UID[A]}})):
            self.add("L14", "G", op, "FALSE", a.send(UID[B], R, {"amount": 3000, "order": 81},
                                                     grants=[self.resign(root, **change)]), scope="authority",
                     tm="signer-bug", note="re-signed with the test log key: a signer bug")
        for i, c in enumerate(self.agentapproved):
            person = ["alice", "reviewer", "token:reviewer", "alice"][i]
            self.add("L14", "A", "approved-by-agent-approver", "FALSE",
                     self.amsg(self.o, ab(person, c.tcid, c.aev()), c.args), scope="claim", trust=self.trust3,
                     note="on the other log, whose signer has the agent approver")
        for c in self.selfapproved:
            self.add("L14", "A", "self-approved", "FALSE",
                     self.amsg(self.erin, ab("erin", c.tcid, c.aev()), c.args), scope="claim")
        for i, c in enumerate(self.unmapped):
            self.add("L14", "A", "approved-by-unmapped-identity", "FALSE",
                     self.amsg(a, ab(["dave", "uid:990009", "alice"][i], c.tcid, c.aev()), c.args), scope="claim")

    def l15(self):
        bb, cc, R = self.bb, self.cc, REF["refund.request"]
        cases = [("root-missing", bb, UID[C], 9000, [self.child]),
                 ("root-missing", bb, UID[C], 1000, [self.child]),
                 ("middle-missing", cc, UID[B], 5000, [self.droot, self.gchild]),
                 ("middle-missing", cc, UID[B], 1000, [self.droot, self.gchild]),
                 ("child-of-another-root", bb, UID[C], 9000, [self.droot2, self.child]),
                 ("child-of-another-chain", bb, UID[C], 9000, [self.droot, self.child2]),
                 ("parent-hash-edited-unsigned", bb, UID[C], 9000, [self.droot2, {
                     **self.child, "parent": event_hash(self.droot2)}]),
                 ("under-non-delegable-root", bb, UID[C], 9000, [self.roots[0], self.child]),
                 ("grandchild-alone", cc, UID[B], 5000, [self.gchild]),
                 ("root-twice", bb, UID[C], 9000, [self.droot, self.droot]),
                 ("grandchild-under-other-child", cc, UID[B], 5000, [self.droot2, self.child2, self.gchild])]
        for op, run, to, amt, grants in cases:
            self.add("L15", "G", op, "FALSE", run.send(to, R, {"amount": amt, "order": 81}, grants=grants),
                     scope="authority")
        for op, grants in (("child-issued-by-non-subject-resigned", [self.droot, self.resign(self.child, issuer={
                **self.child["issuer"], "id": "uid:990107"})]),
                           ("child-under-another-subjects-root-resigned", [self.to_b[0], self.resign(
                               self.child, parent=event_hash(self.to_b[0]))])):
            self.add("L15", "G", op, "FALSE", bb.send(UID[C], R, {"amount": 9000, "order": 81}, grants=grants),
                     scope="authority", tm="signer-bug", note="re-signed with the test log key: a signer bug")

    # -------------------------------------------------------------------------------------------- encoding lies
    def l16(self):
        a, w, P = self.a, self.w, self.w.P
        bad = "pytest -q tests/test_pay.py"
        for path in HOMOGLYPH:   # the sender ran a lookalike file that passes, and claims the real one, which fails
            c = self.bash(a, f"pytest -q {path}")
            assert c.truth == 0 and a.latest.get(bad, 1) != 0
            self.add("L16", "T", "homoglyph-suite", "FALSE", self.msg(a, "T", [tp(bad, c.ev())]), scope="encoding",
                     note=f"ran {c.args['command']!r}")
        hosts = [(f"http://0127.0.0.1:{P}/ok", "87.0.0.1", "ipv4-leading-zero-octet"),
                 (f"http://0127.0.0.01:{P}/ok", "87.0.0.1", "ipv4-leading-zero-octet"),
                 (f"http://0127.000.000.001:{P}/ok", "87.0.0.1", "ipv4-leading-zero-octet"),
                 (f"http://00127.0.0.1:{P}/ok", "87.0.0.1", "ipv4-leading-zero-octet"),
                 ("http://0177.0.0.1/", "127.0.0.1", "ipv4-leading-zero-octet"),
                 ("http://010.0.0.1/", "8.0.0.1", "ipv4-leading-zero-octet"),
                 ("http://192.168.0.010/", "192.168.0.8", "ipv4-leading-zero-octet"),
                 ("http://аpi.example.com/", "api.example.com", "unicode-homoglyph"),
                 ("http://xn--pi-7kc.example.com/", "api.example.com", "punycode-homoglyph"),
                 ("http://api.example.com%2eevil.test/", "api.example.com", "percent-escape"),
                 ("http://evil.test#@api.example.com/", "api.example.com", "fragment-before-at"),
                 ("http://evil.test?@api.example.com/", "api.example.com", "query-before-at"),
                 ("http://evil.test\\@api.example.com/", "api.example.com", "backslash-at"),
                 ("http://api.example.com@evil.test/", "api.example.com", "userinfo"),
                 ("http://api.example.com../", "api.example.com", "two-trailing-dots"),
                 ("http://ａpi.example.com/", "api.example.com", "fullwidth"),
                 ("http://api.example.com.evil.test./", "api.example.com.", "suffix-trailing-dot")]
        for u, h, op in hosts:
            c = self.fetch_(a, u)
            label = "TRUE" if c.status == "ok" and c.truth == canon_host(h.rstrip(".")) else "FALSE"
            self.add("L16", "H", op, label, self.msg(a, "H", [rh(h, c.ev())]), scope="encoding",
                     note=f"{u!r} reached {c.truth} ({c.status})")
        base = os.path.join(w.work, "enc")
        cases = [("wоrk/report.txt", "homoglyph-dir"), ("work\\report.txt", "backslash-in-posix-name"),
                 ("work%2freport.txt", "percent-encoded-slash"), ("work/report.txt​", "zero-width-space"),
                 ("work/report.txt.", "trailing-dot"), ("work/report.txt ", "trailing-space"),
                 ("work/rеport.txt", "homoglyph-name"), ("work/report‮txt.exe", "rtl-override"),
                 ("work/ｒeport.txt", "fullwidth"), ("work/Report.txt", "case-variant"),
                 ("work/café.txt", "nfd-name"), ("link/report.txt", "symlinked-dir")]
        for i, (rel, op) in enumerate(cases):
            d = os.path.join(base, str(i))
            os.makedirs(os.path.join(d, "work"))
            os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True) if op != "symlinked-dir" else \
                os.symlink(os.path.join(d, "work"), os.path.join(d, "link"))
            claimed = os.path.join(d, "work", "café.txt" if op == "nfd-name" else "report.txt")
            content = f"handoff {i}\n"
            c = self.write_(a, os.path.join(d, rel), content)
            digest = sha(content)
            label = "TRUE" if w.same_file(c.truth, claimed, digest) else "FALSE"
            self.add("L16", "F", op, label, self.msg(a, "F", [fw(claimed, digest, c.ev())]), scope="encoding",
                     note=f"wrote {rel!r}")
        c = self.refunds[0]
        for i, person in enumerate(["аlice", "alіce", "alice​", "al1ce", "aIice", "ɑlice",
                                    "alicе", "ałice"]):
            self.add("L16", "A", "homoglyph-person", "FALSE", self.amsg(a, ab(person, c.tcid, c.aev()), c.args),
                     scope="encoding")
        for i, (real, fake) in enumerate((("refund-O1", "refund-01"), ("refund-l1", "refund-11"),
                                          ("refund-I0", "refund-l0"))):
            approved = a.t2("refund", {"amount": 1500 + i, "order": 81}, w.refund, approver=ALICE, tcid=real)
            self.add("L16", "A", "lookalike-call-id", "FALSE",
                     self.amsg(a, ab("alice", fake, approved.aev()), approved.args), scope="encoding",
                     note=f"alice approved call {approved.tcid}, claimed as {fake}")
        # wire forms of signed messages: duplicate members and non-JCS bytes
        payload = {"kind": "data", "data": {"n": 1}}
        for ct in ("T", "H", "F", "A", "G"):
            run, claims, m0 = self.base[ct][4]
            if ct == "G":
                m = run.send(m0["to"]["agent"], m0["intent"]["type"], m0["intent"]["args"], grants=m0["grants"],
                             payload=payload)
                first, cpath = "amount", (["grants", 0, "caveats", 0], "op")
            else:
                m = run.send(m0["to"]["agent"], m0["intent"]["type"], m0["intent"]["args"], claims, payload=payload)
                first = next(iter(m["intent"]["args"]))
                cpath = (["claims", 0, "args"], next(iter(m["claims"][0]["args"])))
            for op, text, label in wire_variants(m, first, cpath):
                self.add("L16", ct, "wire-" + op, label, m, wire=text, scope="encoding")

    def l16_ipv4(self):
        """L16 IPv4 spellings (PCM's fix: only a canonical dotted quad counts, any other numeric form is unproven): the
        fetch's URL in another numeric form, or the claim's host in one. Labelled by what this machine's resolver reads,
        for the claim's host too (World.destination), so a spelling of the address reached is TRUE."""
        a, w, P = self.a, self.w, self.w.P
        means = lambda h: w.destination(h.rsplit(":", 1)[0] if h.count(":") == 1 else h)   # noqa: E731
        for u, h, op in ((f"http://0x7f.0.0.1:{P}/ok", "127.0.0.1", "ipv4-hex-octet"),
                         (f"http://0x7f000001:{P}/ok", "127.0.0.1", "ipv4-hex-32-bit"),
                         (f"http://127.1:{P}/ok", "127.0.0.1", "ipv4-two-parts"),
                         (f"http://127.0.1:{P}/ok", "127.0.0.1", "ipv4-three-parts"),
                         (f"http://2130706433:{P}/ok", "127.0.0.1", "ipv4-32-bit-decimal"),
                         (f"http://127.0.0.01:{P}/ok", "127.0.0.1", "ipv4-leading-zero-same-value"),
                         (f"http://0127.0.0.1:{P}/ok", "127.0.0.1", "ipv4-leading-zero-decimal-reading"),
                         (f"http://[::ffff:127.0.0.1]:{P}/ok", "127.0.0.1", "ipv4-mapped-ipv6"),
                         ("http://127.0.0.0.1/", "127.0.0.1", "ipv4-five-labels"),
                         ("http://1.2.3.4.5/", "1.2.3.4", "ipv4-five-labels"),
                         ("http://0x7f.0.0.2/", "127.0.0.1", "ipv4-hex-other-address"),
                         ("http://2130706434/", "127.0.0.1", "ipv4-32-bit-other-address")):
            c = self.fetch_(a, u)
            label = "TRUE" if c.status == "ok" and c.truth == means(h) else "FALSE"
            self.add("L16", "H", op, label, self.msg(a, "H", [rh(h, c.ev())]), scope="encoding",
                     note=f"{u!r} reached {c.truth} ({c.status})")
        c = self.fetch_(a, f"http://127.0.0.1:{P}/ok")
        for h, op in (("127.1", "claim-two-parts"), ("0x7f000001", "claim-hex-32-bit"),
                      ("2130706433", "claim-32-bit-decimal"), ("127.000.000.001", "claim-leading-zeros")):
            label = "TRUE" if c.status == "ok" and c.truth == means(h) else "FALSE"
            self.add("L16", "H", op, label, self.msg(a, "H", [rh(h, c.ev())]), scope="encoding",
                     note=f"the fetch was of 127.0.0.1; the claim spells the host {h!r}, which this machine reads as "
                          f"{means(h)}")


def main():
    t0 = time.time()
    with mock.patch.object(svc, "CHECKPOINT_S", 3600.0):   # checkpoints only when the generator asks for one
        w = World()
        try:
            b = Bench(w)
            b.materials()
            b.honest()
            b.honest_covers()
            for step in (b.ablations, b.l1, b.l2, b.l3, b.l4, b.l5, b.l6, b.l7, b.l8, b.l9, b.l10, b.l11, b.l12,
                         b.l13, b.l14, b.l15, b.l16, b.l16_ipv4):
                step()
                print(f"  {step.__name__}: {len(b.out)} messages", flush=True)
        finally:
            w.close()
    DATA.parent.mkdir(exist_ok=True)
    with open(DATA, "w", encoding="utf-8") as f:
        for r in b.out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    tk = os.environ.get("PYTHONPATH", "").split(os.pathsep)[0]
    rev = lambda d: subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True,   # noqa: E731
                                   text=True).stdout.strip()
    meta = {"dataset": 2, "seed": SEED, "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seconds": round(
        time.time() - t0, 1), "messages": len(b.out), "tracekit": rev(tk) if tk else None,
            "pcm": rev(str(HERE.parent.parent)), "python": sys.version.split()[0],
            "platform": platform.platform(), "signer_refusals": b.refusals,
            "by_class": dict(collections.Counter(f"{r['class']}.{r['claim_type']}" for r in b.out))}
    META.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
    print(f"{len(b.out)} messages -> {DATA.relative_to(HERE.parent.parent)} ({meta['seconds']} s)")


if __name__ == "__main__":
    main()
