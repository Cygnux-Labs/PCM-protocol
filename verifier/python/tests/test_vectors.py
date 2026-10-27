"""Every vector in ../../vectors gives Tracekit's result on the conformance fields; hostile messages give reject or
failed and never raise; the CLI's exit codes."""
import base64
import copy
import hashlib
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


def conformance(out):
    """The fields a verifier must match: verdict, signature.ok, replay.ok, schema.ok, grants.result, claim results."""
    part = lambda name, key: None if out[name] is None else out[name][key]   # noqa: E731
    return {"verdict": out["verdict"], "signature": part("signature", "ok"), "replay": part("replay", "ok"),
            "schema": part("schema", "ok"), "grants": part("grants", "result"),
            "claims": None if out["claims"] is None else [c["result"] for c in out["claims"]]}


def run(inp):
    o, rp = inp["options"], inp["options"]["replay"]
    replay = rp and pcm_verify.Replay(rp["window_s"], rp["per_sender"], started=rp["started"])
    kw = dict(me=o["me"], strict=o["strict"], now=o["now"], replay=replay)
    for m in (rp or {}).get("seen", []):
        pcm_verify.verify(m, inp["trust"], inp["schemas"], inp["tools"], **kw)
    return pcm_verify.verify(inp["message"], inp["trust"], inp["schemas"], inp["tools"], **kw)


def test_no_tracekit_import():
    assert not [m for m in sys.modules if m.split(".")[0] == "tracekit"]


def test_index_lists_every_vector():
    assert sorted(v["file"] for v in INDEX) == sorted(p.name for p in VECTORS.glob("*.json") if p.name != "index.json")


@pytest.mark.parametrize("name", [v["name"] for v in INDEX])
def test_vector(name):
    v = json.loads((VECTORS / f"{name}.json").read_text())
    assert conformance(run(v["input"])) == conformance(v["expected"])


# ---------------------------------------------------------------------------------------------------- hostile input
# A log of our own, so a test can sign what it needs: one approval record, its checkpoint and a message citing it.
KEY = Ed25519PrivateKey.from_private_bytes(bytes(32))
PUB = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
NAME = "example.org/hostile-test-log"
KID = hashlib.sha256(NAME.encode() + b"\n\x01" + PUB).digest()[:4].hex()
VKEY = NAME + "+" + KID + "+" + base64.b64encode(b"\x01" + PUB).decode()
TRUST = {"logs": [VKEY], "witnesses": [], "witnesses_required": 0}
DOC = {"pcm_schema": 0, "name": "note", "fields": {"n": {"type": "int", "min": 0, "max": 10}}}
EVENT = {"seq": 0, "tenant": "t", "run_id": "r1", "type": "approval",
         "data": {"tool_use_id": "call-1", "decision": "approve", "approver": "uid:1", "person": "alice"}}


def b64(raw):
    return base64.b64encode(raw).decode()


def signed(obj, tag):
    body = {k: v for k, v in obj.items() if k != "sig"}
    return {**body, "sig": {"key": f"{NAME}+{KID}", "sig": b64(KEY.sign(rfc8785.dumps({**body, "t": tag})))}}


def message(args=None, claim_args=None, event=EVENT, proof=()):
    h = pcm_verify.record_hash(event) if isinstance(event, dict) else "sha256:" + "0" * 64
    leaf = hashlib.sha256(b"\x00" + bytes.fromhex(h[7:])).digest()
    text = f"{NAME}\n1\n{b64(leaf)}\n"
    note = text + f"\n— {NAME} {b64(bytes.fromhex(KID) + KEY.sign(text.encode()))}\n"
    claim = {"type": "approved_by", "args": {"person": "alice", "call": "call-1"} if claim_args is None else claim_args,
             "evidence": {"checkpoint": note, "records": [{"event": event, "hash": h, "proof": list(proof)}]}}
    return signed({"pcm": 0, "id": "0" * 32, "ts": "2026-10-27T12:00:00.000000Z", "nonce": "1" * 32,
                   "from": {"agent": "uid:1", "run": "r1", "tenant": "t"}, "to": {"agent": "uid:2"},
                   "intent": {"type": pcm_verify.schema_ref(DOC), "args": {"n": 1} if args is None else args},
                   "claims": [claim]}, pcm_verify.MESSAGE_TAG)


def check(msg):
    return pcm_verify.verify(msg, TRUST, [DOC], {})


def test_own_log_accepts():
    out = check(message())
    assert out["verdict"] == "accept", out["reasons"]


@pytest.mark.parametrize("kw", [{"claim_args": []}, {"claim_args": "alice"}, {"proof": ["%%%"]}, {"proof": ["é"]},
                                {"proof": ["AAAA"]}, {"event": 5}, {"event": [EVENT]}])
def test_hostile_claim_fails(kw):
    out = check(message(**kw))
    assert out["verdict"] == "reject" and out["claims"][0]["result"] == "failed", out


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
    other = pcm_verify.verify(message(), dict(TRUST, logs=[VKEY, hybrid("example.org/other")]), [DOC], {})
    assert other["verdict"] == "accept", other["reasons"]
    own = pcm_verify.verify(message(), dict(TRUST, logs=[VKEY, hybrid(NAME)]), [DOC], {})
    assert own["claims"][0]["result"] == "failed" and "SLH-DSA" in own["claims"][0]["detail"]


@pytest.mark.parametrize("trust", [{}, {"logs": VKEY}, {"logs": [VKEY], "witnesses": [{"name": "w"}]},
                                   {"logs": [VKEY], "witnesses_required": "1"}])
def test_bad_trust_raises_value_error(trust):
    with pytest.raises(ValueError):
        pcm_verify.verify(message(), trust, [DOC], {})


def test_packaged_tool_table_is_the_registry():
    assert (HERE.parent / "pcm_verify" / "tools.json").read_text() == (HERE.parents[2] / "registry" /
                                                                       "tools.json").read_text()


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
