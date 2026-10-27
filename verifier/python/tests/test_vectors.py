"""Every vector in ../../vectors gives Tracekit's result on the conformance fields; hostile messages give reject or
failed and never raise; the CLI's exit codes."""
import base64
import copy
import hashlib
import hmac
import json
import pathlib
import subprocess
import sys

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import pcm_verify

HERE = pathlib.Path(__file__).resolve().parent
VECTORS = HERE.parents[2] / "vectors"
INDEX = json.loads((VECTORS / "index.json").read_text())
REGISTRY = HERE.parents[2] / "registry"
TOOLS_SHA256 = "15f8410f513344e4c60327d4fc3dd14949ebeaf7722f641d985d3ca721c8fe07"   # SPEC 10.2: PCM 0.1's table


def conformance(out):
    """The fields a verifier must match (SPEC 13.2): verdict, signature.ok, replay.ok, schema.ok, grants.result, claim
    results and skipped."""
    part = lambda name, key: None if out[name] is None else out[name][key]   # noqa: E731
    return {"verdict": out["verdict"], "signature": part("signature", "ok"), "replay": part("replay", "ok"),
            "schema": part("schema", "ok"), "grants": part("grants", "result"),
            "claims": None if out["claims"] is None else [c["result"] for c in out["claims"]],
            "skipped": out["skipped"]}


def run(inp):
    o, rp = inp["options"], inp["options"]["replay"]
    replay = rp and pcm_verify.Replay(rp["window_s"], rp["per_sender"], started=rp["started"])
    kw = dict(me=o["me"], strict=o["strict"], now=o["now"], replay=replay)
    for m in (rp or {}).get("seen", []):
        pcm_verify.verify(m, inp["trust"], inp["schemas"], **kw)
    return pcm_verify.verify(inp["message"], inp["trust"], inp["schemas"], **kw)


def test_no_tracekit_import():
    assert not [m for m in sys.modules if m.split(".")[0] == "tracekit"]


def test_index_lists_every_vector():
    assert sorted(v["file"] for v in INDEX) == sorted(p.name for p in VECTORS.glob("*.json") if p.name != "index.json")


def test_the_vectors_were_made_with_the_frozen_table():
    """registry/tools.json is PCM 0.1's table (its digest is in SPEC 10.2), the verifier places tools with it, and
    every vector was generated with it."""
    raw = (REGISTRY / "tools.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == TOOLS_SHA256
    assert pcm_verify.TOOLS == json.loads(raw)
    for v in INDEX:
        assert json.loads((VECTORS / v["file"]).read_text())["input"]["tools"] == pcm_verify.TOOLS, v["name"]


@pytest.mark.parametrize("name", [v["name"] for v in INDEX])
def test_vector(name):
    v = json.loads((VECTORS / f"{name}.json").read_text())
    assert conformance(run(v["input"])) == conformance(v["expected"])


# ---------------------------------------------------------------------------------------------------- hostile input
# A log of our own, so a test can sign what it needs: one egress observer's record that the run reached a host, its
# checkpoint and a message citing it.
KEY = Ed25519PrivateKey.from_private_bytes(bytes(32))
PUB = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
NAME = "example.org/hostile-test-log"
KID = hashlib.sha256(NAME.encode() + b"\n\x01" + PUB).digest()[:4].hex()
VKEY = NAME + "+" + KID + "+" + base64.b64encode(b"\x01" + PUB).decode()
TRUST = {"logs": [VKEY], "witnesses": [], "witnesses_required": 0}
DOC = {"pcm_schema": 0, "name": "note", "fields": {"n": {"type": "int", "min": 0, "max": 10}}}
RUN = "0" * 32
ZERO = "sha256:" + "0" * 64
TS = "2026-10-27T12:00:00.000000Z"
EVENT = {"schema_version": "tracekit.event.v2", "id": "1" * 32, "seq": 0, "prev_hash": ZERO, "ts": TS, "run_id": RUN,
         "agent_id": "main", "parent_id": None, "source": "signer", "type": "effect.observed", "data": {
             "observer": "uid:4", "kind": "net", "host": "api.example.com", "port": 443, "bytes_out": 1, "bytes_in": 1,
             "connections": 1, "first_ts": TS, "last_ts": TS, "attribution": "token"},
         "log_id": "2" * 32, "tenant": "t", "run_seq": 0, "run_prev_hash": ZERO}


def b64(raw):
    return base64.b64encode(raw).decode()


def signed(obj, tag):
    body = {k: v for k, v in obj.items() if k != "sig"}
    return {**body, "sig": {"key": f"{NAME}+{KID}", "sig": b64(KEY.sign(rfc8785.dumps({**body, "t": tag})))}}


def leaf(event):
    return hashlib.sha256(b"\x00" + bytes.fromhex(pcm_verify.record_hash(event)[7:])).digest()


def note(size, root):
    text = f"{NAME}\n{size}\n{b64(root)}\n"
    return text + f"\n— {NAME} {b64(bytes.fromhex(KID) + KEY.sign(text.encode()))}\n"


def message(args=None, claim_args=None, event=EVENT, proof=()):
    h = pcm_verify.record_hash(event) if isinstance(event, dict) else "sha256:" + "0" * 64
    claim = {"type": "reached_host", "args": {"host": "api.example.com"} if claim_args is None else claim_args,
             "evidence": {"checkpoint": note(1, hashlib.sha256(b"\x00" + bytes.fromhex(h[7:])).digest()),
                          "records": [{"event": event, "hash": h, "proof": list(proof)}]}}
    return signed({"pcm": 0, "id": "0" * 32, "ts": "2026-10-27T12:00:00.000000Z", "nonce": "1" * 32,
                   "from": {"agent": "uid:1", "run": RUN, "tenant": "t"}, "to": {"agent": "uid:2"},
                   "intent": {"type": pcm_verify.schema_ref(DOC), "args": {"n": 1} if args is None else args},
                   "claims": [claim]}, pcm_verify.MESSAGE_TAG)


def check(msg):
    return pcm_verify.verify(msg, TRUST, [DOC])


def test_own_log_accepts():
    out = check(message())
    assert out["verdict"] == "accept", out["reasons"]


@pytest.mark.parametrize("kw", [{"claim_args": []}, {"claim_args": "alice"}, {"proof": ["%%%"]}, {"proof": ["é"]},
                                {"proof": ["AAAA"]}, {"event": 5}, {"event": [EVENT]},
                                {"event": dict(EVENT, schema_version="tracekit.event.v1")},
                                {"event": dict(EVENT, prev_hash=5)}, {"event": dict(EVENT, data=[])}])
def test_hostile_claim_fails(kw):
    out = check(message(**kw))
    assert out["verdict"] == "reject" and out["claims"][0]["result"] == "failed", out


def test_a_decision_without_its_id_matches_nothing():
    salt, args = "ab" * 32, {"command": "pytest -q"}
    digest = pcm_verify.record_hash({"tool": "Bash", "args": args}).encode()
    t2 = {"source": "gateway", "tier": "T2"}
    dec = {**EVENT, **t2, "type": "policy.decision", "data": {
        "tool_use_id": "call-1", "tool": "Bash", "decision": "allow", "rule_ids": [], "decision_id": "dec-1",
        "args_commitment": "hmac-sha256:" + hmac.new(bytes.fromhex(salt), digest, "sha256").hexdigest()}}
    res = {**EVENT, **t2, "seq": 1, "type": "tool.result",
           "data": {"tool_use_id": "call-1", "ok": True, "decision_id": "dec-1",
                    "output": {"hash": "hmac-sha256:" + "0" * 64, "size": 0, "redacted": False}}}

    def result(dec, res):
        leaves = [leaf(dec), leaf(res)]
        records = [{"event": e, "hash": pcm_verify.record_hash(e), "proof": [b64(leaves[1 - i])]}
                   for i, e in enumerate((dec, res))]
        records[0].update(salt=salt, args=args)
        msg = message()
        msg["claims"] = [{"type": "tests_passed", "args": {"suite": "pytest -q"}, "evidence": {
            "checkpoint": note(2, hashlib.sha256(b"\x01" + leaves[0] + leaves[1]).digest()), "records": records}}]
        return check(signed(msg, pcm_verify.MESSAGE_TAG))["claims"][0]

    def no_id(e):
        return {**e, "data": {k: v for k, v in e["data"].items() if k != "decision_id"}}
    assert result(dec, res)["result"] == "proven", result(dec, res)
    assert result(no_id(dec), no_id(res))["result"] == "failed"


@pytest.mark.parametrize("host, claim, result", [
    ("API.Example.com.", "api.example.com", "proven"), ("bücher.example", "xn--bcher-kva.example", "proven"),
    ("a..example", "api.example.com", "unproven"), ("api.example.org", "api.example.com", "failed"),
    # SPEC 6.7: a deviation character, no IPv6 address in brackets, a NUL, a port that is no number
    ("fa\u00df.example", "fass.example", "unproven"), ("a\u200db.example", "ab.example", "unproven"),
    ("\u03f2.example", "xn--4xa.example", "unproven"), ("%5b", "api.example.com", "unproven"),
    ("h.com%00.evil", "api.example.com", "unproven"), ("api.example.com:x", "api.example.com", "unproven"),
    ("api.example.com", "api.example.com:", "unproven"), ("api.example.com", "api.example.com:443", "proven")])
def test_an_effects_host_is_compared_in_canonical_form(host, claim, result):
    msg = message(claim_args={"host": claim}, event={**EVENT, "data": {**EVENT["data"], "host": host}})
    assert check(msg)["claims"][0]["result"] == result


@pytest.mark.parametrize("claim, path, result", [
    # SPEC 6.6: a path from / by POSIX rules (`\` is part of a name), a drive path by Windows rules and proven only
    # by a call of its own string; case counts
    ("/repo\\a.py", "/repo\\a.py", "proven"), ("/repo//./a\\b", "/repo/a\\b", "proven"),
    ("/repo\\a.py", "/repo/a.py", "failed"), ("/repo/a.py", "/repo\\a.py", "failed"),
    ("/repo/a.py", "\\repo\\a.py", "failed"), ("/repo/x/a.py", "x\\a.py", "failed"),
    ("/repo/a.py", "C:/repo/a.py", "failed"), ("/home/u/C:/repo/a.py", "C:/repo/a.py", "unproven"),
    ("C:/repo/a.py", "C:/repo/a.py", "proven"), ("C:\\repo\\a.py", "C:/repo/a.py", "unproven"),
    ("C:/repo/a.py", "C:\\repo\\.\\a.py", "unproven"), ("C:\\repo\\a.py", "repo\\a.py", "unproven"),
    ("C:\\repo\\a.py", "\\repo\\a.py", "unproven"), ("C:\\repo\\a.py", "D:\\repo\\a.py", "failed"),
    ("C:\\repo\\a.py", "c:\\repo\\a.py", "failed")])
def test_a_backslash_separates_only_in_a_drive_path(claim, path, result):
    digest = "sha256:" + hashlib.sha256(b"x = 1\n").hexdigest()
    d = {"tool_use_id": "c", "tool": "Write", "decision": "allow", "decision_id": "d"}
    recs = [({"type": "policy.decision", "data": d}, {"file_path": path, "content": "x = 1\n"}),
            ({"type": "tool.result", "source": "gateway", "tier": "T2",
              "data": {"tool_use_id": "c", "decision_id": "d", "ok": True}}, None)]
    assert pcm_verify.malformed("file_written", {"path": claim, "digest": digest}) is None
    assert pcm_verify.file_written({"path": claim, "digest": digest}, recs)[0] == result


@pytest.mark.parametrize("path, why", [("/repo\\..\\a.py", None), ("C:\\repo\\..\\a.py", "has a `..`"),
                                       ("\\\\server\\share\\a.py", "is relative"), ("C:a.py", "is relative"),
                                       ("\\repo\\a.py", "is relative")])
def test_which_paths_are_malformed(path, why):
    got = pcm_verify.malformed("file_written", {"path": path, "digest": ZERO})
    assert got is None if why is None else why in got


@pytest.mark.parametrize("url, host", [("file://a.example/x", None), ("gopher://a.example/", None),
                                       ("//a.example/x", "a.example"), ("http://%5b::1%5d/", "[")])
def test_only_a_special_or_schemeless_url_has_a_host(url, host):
    assert pcm_verify.url_info(url).get("host") == host


@pytest.mark.parametrize("suite", [
    "pytest -q tests/x.py", "python3 -m pytest -q", "npm test", "go test -short ./...", "pytest -k 'not slow'",
    'pytest -k "a or b"', "pytest\t-q", "pytest --color=yes", "pytest --verbose"])
def test_a_test_command(suite):
    assert pcm_verify.test_command(suite)


@pytest.mark.parametrize("suite", [
    "pytest &", "(pytest &)", "(pytest) &", "pytest ;", "pytest 2>&1", "pytest || true", "pytest\ntrue",
    "pytest $'\\'';true #'", "pytest $'\\'';true''", "pytest 'a", "pytest $X", "pytest `x`", "pytest \\-h",
    "pytest # x", "pytest x.py#|| true", "pytest -{h,q}", "pytest -[h]", "pytest -?", "pytest\r-q",
    "pytest -V", "pytest -h", "pytest '-h'", "pytest -'-'help", "python -m unittest --he", "pytest --co",
    "pytest --c", "pytest --vers", ".venv/bin/pytest", "./pytest", "/tmp/evil/pytest", "uv run pytest",
    "CI=1 pytest", "echo pytest"])
def test_no_test_command(suite):
    assert not pcm_verify.test_command(suite)


@pytest.mark.parametrize("claim", [{"type": "tests_passed", "args": {"suite": "pytest || true"}},
                                   {"type": "file_written", "args": {"path": "work/x", "digest": ZERO}},
                                   {"type": "file_written", "args": {"path": "/a/../x", "digest": ZERO}}])
def test_a_malformed_claim_fails_without_evidence(claim):
    assert pcm_verify.check_claim(claim, message(), TRUST)["result"] == "failed"


@pytest.mark.parametrize("bad", ["not a vkey", VKEY + "="])
def test_a_bad_vkey_raises_wherever_it_sits(bad):
    for trust in ({"logs": [VKEY, bad]}, {"logs": [bad, VKEY]}, {"logs": [VKEY], "witnesses": [{"vkey": bad}]}):
        with pytest.raises(ValueError):
            pcm_verify.verify(message(), trust, [DOC])


def vkey(name, seed):
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = b64(bytes([pcm_verify.ED25519]) + public)
    return f"{name}+{pcm_verify._key_id(name, pcm_verify.ED25519, public).hex()}+{key}"


def test_two_keys_of_one_log_are_the_receivers_error():
    """SPEC 10.1: one Ed25519 key per log name, so a key names one log; a hybrid key or another log's key is fine."""
    second = vkey(NAME, b"\x01" * 32)
    for logs in ([VKEY, second], [second, VKEY]):
        with pytest.raises(ValueError, match="2 Ed25519 keys of log"):
            pcm_verify.verify(message(), dict(TRUST, logs=logs), [DOC])
    assert check(message())["verdict"] == "accept"
    assert pcm_verify.verify(message(), dict(TRUST, logs=[VKEY, vkey("example.org/other", b"\x01" * 32)]),
                             [DOC])["verdict"] == "accept"


@pytest.mark.parametrize("args", [[1], "n", None, {"n": 2 ** 60}, {"n": 1.0}, {"n": True}])
def test_hostile_args_rejected(args):
    msg = message()
    msg["intent"]["args"] = args   # breaks the signature
    assert check(msg)["verdict"] == "reject"
    if type(args) is not dict or abs(args["n"]) <= pcm_verify.MAX_SAFE_INT:
        assert check(signed(msg, pcm_verify.MESSAGE_TAG))["schema"]["ok"] is False


@pytest.mark.parametrize("edit", [
    lambda m: m["sig"].update(sig="not base64!"), lambda m: m["sig"].update(sig="é" * 8),
    lambda m: m["sig"].update(sig=b64(b"\x00" * 10)), lambda m: m.update(pcm=0.0), lambda m: m.update(pcm=False),
    lambda m: m.update(id="٣" * 32), lambda m: m["intent"].update(args={"n": 10 ** 40}),
    lambda m: m.update(payload={"kind": "data", "data": [[[[[]]]]] * 1000}), lambda m: m.update(claims=None)])
def test_hostile_envelope_rejected(edit):
    msg = message()
    edit(msg)
    out = check(msg)
    assert out["verdict"] == "reject" and out["signature"] in (None, {"ok": False, "key": f"{NAME}+{KID}"}), out


def test_huge_number_signed_is_rejected():
    msg = message()   # JCS can't encode 10**40: sign it with another encoder
    msg["intent"]["args"] = {"n": 10 ** 40}
    body = {k: v for k, v in msg.items() if k != "sig"}
    text = json.dumps({**body, "t": pcm_verify.MESSAGE_TAG}, sort_keys=True, separators=(",", ":")).encode()
    msg["sig"]["sig"] = b64(KEY.sign(text))
    out = check(msg)
    assert out["verdict"] == "reject" and out["signature"]["ok"] is False


def test_deep_value_in_an_enum_field_is_rejected():
    deep = []
    for _ in range(5000):
        deep = [deep]
    msg = message()
    msg["claims"][0]["type"] = deep
    assert check(msg)["verdict"] == "reject"


def hybrid(name):
    public = b"\xff" + pcm_verify.SLH_DSA + bytes(32)
    return f"{name}+{pcm_verify._key_id(name, 0xff, public[1:]).hex()}+{b64(public)}"


def test_hybrid_key_fails_only_its_own_logs_notes():
    other = pcm_verify.verify(message(), dict(TRUST, logs=[VKEY, hybrid("example.org/other")]), [DOC])
    assert other["verdict"] == "accept", other["reasons"]
    own = pcm_verify.verify(message(), dict(TRUST, logs=[VKEY, hybrid(NAME)]), [DOC])
    assert own["claims"][0]["result"] == "failed" and "SLH-DSA" in own["claims"][0]["detail"]


@pytest.mark.parametrize("trust", [{}, {"logs": VKEY}, {"logs": [VKEY], "witnesses": [{"name": "w"}]},
                                   {"logs": [VKEY], "witnesses_required": "1"}])
def test_bad_trust_raises_value_error(trust):
    with pytest.raises(ValueError):
        pcm_verify.verify(message(), trust, [DOC])


@pytest.mark.parametrize("name", ["tools.json", "tracekit.event.v2.json"])
def test_packaged_copies_are_the_registry(name):
    assert (HERE.parent / "pcm_verify" / name).read_text() == (REGISTRY / name).read_text()


# ---------------------------------------------------------------------------------------------------- CLI
def cli(*args):
    return subprocess.run([sys.executable, "-m", "pcm_verify", *args], cwd=HERE.parent, capture_output=True,
                          text=True)


def test_cli_exit_codes(tmp_path):
    def write(name, value):
        (tmp_path / name).write_text(value if isinstance(value, str) else json.dumps(value))
        return str(tmp_path / name)
    trust, schema = write("trust.json", TRUST), write("schema.json", [DOC])
    bad = copy.deepcopy(message())
    bad["sig"]["sig"] = b64(b"\x00" * 64)
    assert cli(write("ok.json", message()), "--trust", trust, "--schema", schema).returncode == 0
    assert cli(write("bad.json", bad), "--trust", trust, "--schema", schema).returncode == 1
    nev = message()
    del nev["claims"][0]["evidence"]
    nev = signed(nev, pcm_verify.MESSAGE_TAG)
    assert cli(write("nev.json", nev), "--trust", trust, "--schema", schema).returncode == 3
    for garbage in ("{", '{"a": NaN}', '{"a": 1, "a": 2}', "[" * 100000):
        r = cli(write("g.json", garbage), "--trust", trust, "--schema", schema)
        assert r.returncode == 2 and "Traceback" not in r.stderr, r.stderr
    r = cli(write("ok.json", message()), "--trust", str(tmp_path / "missing.json"), "--schema", schema)
    assert r.returncode == 2 and "Traceback" not in r.stderr
    assert cli("--json").returncode == 2
    deep = message()
    deep["payload"] = {"kind": "data", "data": json.loads("[" * 200 + "]" * 200)}
    r = cli(write("deep.json", signed(deep, pcm_verify.MESSAGE_TAG)), "--trust", trust, "--schema", schema)
    assert r.returncode == 2 and "deeper than 128" in r.stderr, r.stderr


def test_cli_escapes_what_the_sender_wrote(tmp_path):
    msg = message()
    msg["to"]["agent"] = "uid:\x1b[2J"
    (tmp_path / "m.json").write_text(json.dumps(signed(msg, pcm_verify.MESSAGE_TAG)))
    (tmp_path / "t.json").write_text(json.dumps(TRUST))
    (tmp_path / "s.json").write_text(json.dumps(DOC))
    r = cli(str(tmp_path / "m.json"), "--trust", str(tmp_path / "t.json"), "--schema", str(tmp_path / "s.json"),
            "--me", "uid:2")
    assert r.returncode == 1 and "\x1b" not in r.stdout and "uid:\\u001b[2J" in r.stdout, (r.stdout, r.stderr)
