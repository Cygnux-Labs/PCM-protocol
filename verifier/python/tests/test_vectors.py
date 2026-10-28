"""Every vector in ../../vectors gives Tracekit's result on the conformance fields; hostile messages give reject or
failed and never raise; the CLI's exit codes."""
import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import pathlib
import re
import subprocess
import sys
import urllib.parse

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import pcm_verify
from pcm_verify.__main__ import loads

HERE = pathlib.Path(__file__).resolve().parent
VECTORS = HERE.parents[2] / "vectors"
INDEX = json.loads((VECTORS / "index.json").read_text())
REGISTRY = HERE.parents[2] / "registry"
TOOLS_SHA256 = "15f8410f513344e4c60327d4fc3dd14949ebeaf7722f641d985d3ca721c8fe07"   # SPEC 10.2: PCM 0.1's table


def conformance(out):
    """The fields a verifier must match (SPEC 13.2): verdict, signature.ok, replay.ok, schema.ok, grants.result, claim
    results with a proven approved_by's `approved`, and skipped."""
    part = lambda name, key: None if out[name] is None else out[name][key]   # noqa: E731
    return {"verdict": out["verdict"], "signature": part("signature", "ok"), "replay": part("replay", "ok"),
            "schema": part("schema", "ok"), "grants": part("grants", "result"),
            "claims": None if out["claims"] is None else [(c["result"], "approved" in c, c.get("approved"))
                                                          for c in out["claims"]],
            "skipped": out["skipped"]}


def run(inp):
    """The verifier's result for a vector's input; a `message_text` is parsed first, as the CLI parses a file."""
    o, rp = inp["options"], inp["options"]["replay"]
    replay = rp and pcm_verify.Replay(rp["window_s"], rp["per_sender"], started=rp["started"])
    kw = dict(me=o["me"], strict=o["strict"], now=o["now"], replay=replay)
    for m in (rp or {}).get("seen", []):
        pcm_verify.verify(m, inp["trust"], inp["schemas"], **kw)
    msg = loads(inp["message_text"]) if "message_text" in inp else inp["message"]
    return pcm_verify.verify(msg, inp["trust"], inp["schemas"], **kw)


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


def test_conformance_tells_an_approved_null_from_none():
    """SPEC 13.2: `approved` is present exactly when `expected` has it."""
    out = {"verdict": "accept-unproven", "signature": None, "replay": None, "schema": None, "grants": None,
           "skipped": [], "claims": [{"type": "tests_passed", "result": "unproven", "detail": "no evidence"}]}
    extra = dict(out, claims=[dict(out["claims"][0], approved=None)])
    assert conformance(extra) != conformance(out)


@pytest.mark.parametrize("name", [v["name"] for v in INDEX])
def test_vector(name):
    v = json.loads((VECTORS / f"{name}.json").read_text())
    if v["expected"]["verdict"] == "bad-input":   # SPEC 13.2: the text must not parse, so there is no result
        with pytest.raises(ValueError):
            run(v["input"])
    else:
        assert conformance(run(v["input"])) == conformance(v["expected"])


# ---------------------------------------------------------------------------------------------------- SPEC examples
# SPEC.md ties an example to the vector it quotes with `<!-- vector NAME PATH -->` right before the code block or
# inline code: PATH is a dotted path into vectors/NAME.json (a number indexes an array), and `@signed` turns a message
# into the bytes its signature covers (SPEC 4.2).
SPEC = HERE.parents[2] / "SPEC.md"
QUOTED = re.compile(r"<!-- vector ([\w-]+) ([\w.@-]+) -->\s*(?:```\w*\n(.*?)\n\s*```|`([^`]+)`)", re.S)


def quoted(text):
    """[(name, path, example)]; inline code that wraps reads as one line, as Markdown renders it."""
    return [(name, path, block or re.sub(r"\s*\n\s*", " ", inline)) for name, path, block, inline in QUOTED.findall(text)]


def at(name, path):
    value = json.loads((VECTORS / f"{name}.json").read_text())
    for step in path.split("."):
        if step == "@signed":
            value = rfc8785.dumps({**{k: v for k, v in value.items() if k != "sig"}, "t": pcm_verify.MESSAGE_TAG})
            value = value.decode()
        else:
            value = value[int(step) if isinstance(value, list) else step]
    return value


def elided(e):
    return isinstance(e, str) and e.startswith("...")


def shown(e, v):
    """Whether JSON example `e` shows `v`: a string that starts with `...` stands for any value, an object with a member
    `...` for one with more members, an array that ends in such a string for one with more items."""
    if elided(e):
        return True
    if isinstance(e, dict):
        return isinstance(v, dict) and ("..." in e or e.keys() == v.keys()) and all(
            k in v and shown(x, v[k]) for k, x in e.items() if k != "...")
    if isinstance(e, list):
        n = len(e) - 1 if e and elided(e[-1]) else len(e)
        return isinstance(v, list) and (len(v) >= n if n < len(e) else len(v) == n) and all(map(shown, e[:n], v))
    return type(e) is type(v) and e == v


@pytest.mark.parametrize("name, path, text", quoted(SPEC.read_text()))
def test_spec_example(name, path, text):
    """Each example SPEC.md ties to a vector shows that vector's value: a string as written, `...` for text left out;
    anything else as JSON."""
    value = at(name, path)
    if isinstance(value, str):
        assert re.fullmatch(".*".join(map(re.escape, text.split("..."))), value, re.S), (text, value)
    else:
        assert shown(json.loads(text), value), (text, value)


def test_spec_ties_every_run_value_to_a_vector():
    """Ids and nonces (32 hex digits) change whenever the vectors are made again: SPEC.md holds each only inside an
    example tied to a vector, which test_spec_example checks."""
    assert re.findall(r"\b[0-9a-f]{32}\b", QUOTED.sub("", SPEC.read_text())) == []


def unread(text):
    """The comments in `text` that QUOTED does not tie to an example, but for one quoted as inline code (SPEC 3.4)."""
    read = {m.start() for m in QUOTED.finditer(text)}
    return [text[m.start():text.index("-->", m.start()) + 3] for m in re.finditer(r"(?<!`)<!--", text)
            if m.start() not in read]


def test_spec_ties_every_marker_to_its_example():
    """A mistyped marker, or a word between a marker and its example, would leave the example unchecked."""
    assert unread(SPEC.read_text()) == []
    assert unread("<!-- vectr a b -->\n`x`\n<!-- vector a b --> see `x`") == ["<!-- vectr a b -->", "<!-- vector a b -->"]


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
    ("API.Example.com.", "api.example.com", "proven"), ("XN--BCHER-KVA.example", "xn--bcher-kva.example", "proven"),
    ("xn--zz.example", "xn--zz.example", "proven"), ("::ffff:10.0.0.1", "10.0.0.1", "proven"),
    ("a..example", "api.example.com", "unproven"), ("api.example.org", "api.example.com", "failed"),
    ("a" * 64 + ".example", "a" * 64 + ".example", "unproven"),
    ("api.example.com:x", "api.example.com", "unproven"), ("api.example.com", "api.example.com:", "unproven"),
    ("api.example.com", "api.example.com:443", "proven"),
    # SPEC 6.7: printable ASCII only, never percent-decoded, no leading zero in an IPv6 address's dotted quad
    ("bücher.example", "xn--bcher-kva.example", "unproven"), ("faß.example", "fass.example", "unproven"),
    (" api.example.com", "api.example.com", "unproven"), ("%61pi.example.com", "api.example.com", "unproven"),
    ("h.com%00.evil", "api.example.com", "unproven"), ("%5b", "api.example.com", "unproven"),
    ("::ffff:1.2.03.4", "1.2.3.4", "unproven"), ("1.2.3.4", "::ffff:01.2.3.4", "unproven"),
    # SPEC 6.7: an IPv4 address only as a dotted quad
    ("10.0.0.1", "10.0.0.1", "proven"), ("0127.0.0.1", "127.0.0.1", "unproven"), ("127.1", "127.0.0.1", "unproven"),
    ("2130706433", "127.0.0.1", "unproven"), ("127.0.0.1", "0127.0.0.1", "unproven")])
def test_an_effects_host_is_compared_in_canonical_form(host, claim, result):
    msg = message(claim_args={"host": claim}, event={**EVENT, "data": {**EVENT["data"], "host": host}})
    assert check(msg)["claims"][0]["result"] == result


def fetched(url):
    """A T2 WebFetch of `url`, as evidence() returns its records."""
    d = {"tool_use_id": "c", "tool": "WebFetch", "decision": "allow", "decision_id": "d"}
    return [({"type": "policy.decision", "data": d}, {"url": url}),
            ({"type": "tool.result", "source": "gateway", "tier": "T2",
              "data": {"tool_use_id": "c", "decision_id": "d", "ok": True}}, None)]


def first_part(netloc):
    """urlsplit's bracket check in earlier CPython releases, from 3.11.4 on: the first bracketed part of the whole
    authority."""
    inside = netloc.partition("[")[2].partition("]")[0]
    if not (re.fullmatch(r"v[0-9A-Fa-f]+\..+", inside) if inside.startswith("v")
            else ipaddress.ip_address(inside).version == 6):
        raise ValueError("Invalid IPv6 URL")


@pytest.mark.parametrize("emu", [{}, {"_check_bracketed_netloc": lambda netloc: None},
                                 {"_check_bracketed_netloc": first_part}, {"_WHATWG_C0_CONTROL_OR_SPACE": ""},
                                 {"_WHATWG_C0_CONTROL_OR_SPACE": "", "_UNSAFE_URL_BYTES_TO_REMOVE": []}],
                         ids=["native", "no-bracket-check", "first-part", "no-c0-strip", "no-strip"])
@pytest.mark.parametrize("host, url, result", [
    # SPEC 6.7 bracket rule: one pair around an IPv6 or IPvFuture address that opens the host after the last `@`,
    # checked before anything else reads the URL
    ("good.com", "http://[x]@good.com/", "unproven"), ("api.example.com", "http://[::1]@api.example.com/", "unproven"),
    ("api.example.com", "http://[::1]@evil.example/", "unproven"), ("api.example.com", "[::1]@api.example.com/x",
                                                                    "unproven"),
    ("::1", "http://[zz]@[::1]/", "unproven"), ("::1", "http://[::1]x/", "unproven"), ("x", "http://[@x::1]/", "unproven"),
    ("a.com", "http://[x]@%61.com/", "unproven"),
    ("api.example.com", "http://[::1]@/", "unproven"), ("::1", "http://[::1]@/", "unproven"),
    ("api.example.com", "file://[::1]@api.example.com/", "unproven"),
    # SPEC 6.7 step 1: what urlsplit strips (leading controls and spaces, tabs and line breaks) differs by release
    ("a.example", " http://a.example\\@b.example/", "unproven"), ("a.example", "\x01http://a.example/", "unproven"),
    ("a.example", "ht\ttp://a.example\\@b.example/", "unproven"),
    ("::1", "http://[::1]:8080/", "proven"), ("::1", "http://u@[::1]/x", "proven"), ("1.2.3.4", "http://[::ffff:1.2.3.4]/",
                                                                                      "proven"),
    ("good.com", "http://good.com/a[1]", "proven"), ("other.com", "http://good.com/?q=]", "failed")])
def test_no_verdict_depends_on_the_urlsplit_release(emu, host, url, result, monkeypatch):
    """urlsplit's own bracket check differs between Python releases (none, the first bracketed part, the part after the
    last `@`), and so does what it strips: under each, the verdict and the detail are this release's."""
    urllib.parse.clear_cache()   # urlsplit caches what it read
    native = pcm_verify.reached_host({"host": host}, fetched(url))
    urllib.parse.clear_cache()
    for name, value in emu.items():
        monkeypatch.setattr(urllib.parse, name, value, raising=False)
    try:
        assert native[0] == result
        assert pcm_verify.reached_host({"host": host}, fetched(url)) == native
    finally:
        urllib.parse.clear_cache()


@pytest.mark.parametrize("host, url", [
    ("fass.example", "http://fa%C3\t%9F.example/"), ("fass.example", "http://faß.example/"),
    ("example.com", "http://exa\N{MONGOLIAN TODO SOFT HYPHEN}mple.com/"),
    ("ab.example", "http://a\N{HANGUL FILLER}b.example/"), ("xn--x-qib.example", "http://x" + chr(0x378) + ".example/"),
    ("xn--bcher-kva.example", "http://bücher.example/"), ("::1", "http://[::\N{FULLWIDTH DIGIT ONE}]/"),
    *(("a.example", url) for url in ("http://a.example/café", " http://a.example/", "\x01http://a.example/",
                                     "http://a.ex\tample/", "http://a.example/ x", "http://a.example/\x7f"))])
def test_only_printable_ascii_is_read(host, url):
    """SPEC 6.7 step 1: a URL with any character outside U+0021 to U+007E won't parse: IDNA 2003, UTS 46 and the
    readers of each Unicode version name some hosts apart, and URL readers drop spaces, tabs and controls differently,
    even inside a percent-escape. The detail says what the sender can do (SPEC 6.6)."""
    assert pcm_verify.reached_host({"host": host}, fetched(url)) == (
        "unproven", f"the verifier can't tell whether call c reached {host}: its URL is not printable ASCII: send it "
        "without spaces or control characters, with the host in xn-- form and anything else percent-encoded")


@pytest.mark.parametrize("host, url", [
    ("a.example", "http://%61.example/"), ("a.example", "http:\\\\%61.example/"),
    ("a.example", "http://a.example\\@%61.example/"), ("b.example", "http://a.example\\@%62.example/"),
    ("h.com", "http://%5bh.com%5d/"), ("h.com.evil", "http://h.com%00.evil/"), ("::1", "http://[::1%25eth0]/"),
    # a zone id is no address, so its .01 is no leading zero: the URL passes the bracket rule
    ("::1", "http://[::1%25a.01]/"), ("fe80::1", "http://[fe80::1%25en.05]/")])
def test_a_host_with_a_percent_is_unproven(host, url):
    """SPEC 6.7 step 5: a host is never percent-decoded, in the browser's reading or the generic one. The detail says
    what the sender can do (SPEC 6.6)."""
    assert pcm_verify.reached_host({"host": host}, fetched(url)) == (
        "unproven", f"the verifier can't tell whether call c reached {host}: its host has a %: send the URL with the "
        "host as plain ASCII, not percent-encoded")


NOT_QUAD = ("its host is an IPv4 address not written as a dotted quad: send it as four decimal numbers 0-255 without "
            "leading zeros")


@pytest.mark.parametrize("host, url", [
    ("87.0.0.1", "http://0127.0.0.1/"), ("127.0.0.1", "http://0127.0.0.1:8080/x"), ("10.0.0.1", "http://010.0.0.1/"),
    ("192.168.0.10", "http://192.168.0.010/"), ("127.0.0.1", "http://0127.0.0.1./"), ("127.0.0.1", "http://127.1/"),
    ("127.0.0.1", "http://0x7f.0.0.1/"), ("127.0.0.1", "http://0X7F.0.0.1/"), ("127.0.0.1", "http://2130706433/"),
    ("0.0.0.0", "http://0x/"), ("1.2.3.4", "http://1.2.3.4.5/"), ("1.2.3.4", "http://a.1.2.3.4/"),
    ("1.2.3.4", "http://1.2.3.256/"), ("8.8.8.8", "http://0128.0.0.1/"), ("127.0.0.1", "http:\\\\0127.0.0.1/")])
def test_an_ipv4_host_not_written_as_a_dotted_quad_is_unproven(host, url):
    """SPEC 6.7 step 5: a host whose last label is a number is an IPv4 address, read only as four decimal numbers 0-255
    without leading zeros; resolvers read the other forms apart (macOS reaches 127.0.0.1 from 0127.0.0.1, inet_aton
    reads 87.0.0.1). The detail says what the sender can do (SPEC 6.6)."""
    assert pcm_verify.reached_host({"host": host}, fetched(url)) == (
        "unproven", f"the verifier can't tell whether call c reached {host}: {NOT_QUAD}")


@pytest.mark.parametrize("host", ["0127.0.0.1", "127.1", "2130706433", "0x7f.0.0.1", "127.0.0.01:443"])
def test_a_claimed_ipv4_host_not_written_as_a_dotted_quad_is_unproven(host):
    """SPEC 6.6 step 1: the claim's host is the sender's own, so its detail says what to fix too."""
    assert pcm_verify.reached_host({"host": host}, fetched("http://127.0.0.1/")) == (
        "unproven", f"{host} is no host the verifier can read: {NOT_QUAD}")


@pytest.mark.parametrize("host, url", [("10.0.0.1", "http://10.0.0.1:8080/"), ("0.0.0.0", "http://0.0.0.0/"),
                                       ("127.0.0.1", "http://127.0.0.1./"), ("1a.example", "http://1a.example/"),
                                       ("example.0x1g", "http://example.0x1g/")])
def test_a_dotted_quad_or_a_name_ending_in_no_number_is_read(host, url):
    assert pcm_verify.reached_host({"host": host}, fetched(url))[0] == "proven"


def test_no_advice_for_another_cause():
    assert pcm_verify.reached_host({"host": "b.example"}, fetched("http://a.example\\@b.example/")) == (
        "unproven", "the verifier can't tell whether call c reached b.example")


@pytest.mark.parametrize("host, url", [("::1", "http://[::1]@[::1%25x]/"), ("127.0.0.1", "http://[x]@0127.0.0.1/")])
def test_no_advice_for_a_url_the_bracket_rule_refuses(host, url):
    """SPEC 6.6: the `%` and dotted-quad sentences are for a URL that passes the bracket rule; a reading of one it
    refuses moves with the URL and the urlsplit release."""
    assert pcm_verify.reached_host({"host": host}, fetched(url)) == (
        "unproven", f"the verifier can't tell whether call c reached {host}")


@pytest.mark.parametrize("recs", [fetched("file:///x"), [({**EVENT, "data": {**EVENT["data"], "host": ":443"}}, None)]])
def test_a_claimed_host_that_reads_as_none_is_unproven(recs):
    """SPEC 6.7: `:80` passes the claim pattern and reads as no host, which must not match the no host of a file: URL
    or of an effect's `:443`."""
    assert pcm_verify.reached_host({"host": ":80"}, recs) == ("unproven", ":80 is no host the verifier can read")


@pytest.mark.parametrize("url", ["blob:http://a.com/x", "view-source:http://a.com/", "BLOB:view-source:https://a.com/",
                                 "blob:http://[x]@a.com/", "blob:http://%61.com/", "view-source:http://0127.0.0.1/"])
def test_a_view_source_or_blob_url_is_unproven(url):
    """SPEC 6.7 step 4: a browser's address bar reads the URL inside view-source: and blob:, WHATWG URL reads no host
    from either: the verifier can't tell, and says nothing the sender could fix in the host."""
    assert pcm_verify.reached_host({"host": "a.com"}, fetched(url)) == (
        "unproven", "the verifier can't tell whether call c reached a.com")


def test_a_failed_call_says_how_to_prove_the_host():
    """SPEC 6.6: a call the host answered with an HTTP error is recorded as not ok, as one that reached nothing is; the
    claim fails, and its detail says how to prove the host instead."""
    recs = fetched("http://a.com/")
    recs[1][0]["data"]["ok"] = False
    assert pcm_verify.reached_host({"host": "a.com"}, recs) == (
        "failed", "call c reached a.com, and failed: its result is not ok, which an HTTP error answer gives too: claim "
                  "the host from a call that succeeded, or from an egress observer's record")


@pytest.mark.parametrize("old", [False, True], ids=["this-release", "lenient-ipaddress"])
def test_an_ipv6_dotted_quad_with_a_leading_zero_is_unproven(old, monkeypatch):
    """SPEC 6.7: ::ffff:01.2.3.4 is no IPv6 address. Python before 3.9.5 reads it as ::ffff:1.2.3.4, emulated here."""
    if old:
        octet = ipaddress._BaseV4._parse_octet.__func__
        monkeypatch.setattr(ipaddress._BaseV4, "_parse_octet", classmethod(lambda c, s: octet(c, s.lstrip("0") or "0")))
    urllib.parse.clear_cache()
    try:
        for host, recs in (("1.2.3.4", fetched("http://[::ffff:01.2.3.4]/")),
                           ("1.2.3.4", fetched("http://[::ffff:1.2.03.4]/")),
                           ("1.2.3.4", fetched("file://[::ffff:01.2.3.4]/")),   # the bracket rule comes first
                           # no authority, so no bracket rule: step 5's own check
                           ("1.2.3.4", fetched("http:\\\\[::ffff:01.2.3.4]/")),
                           ("1.2.3.4", fetched("http:\\\\[::ffff:1.2.3.04]/")),
                           ("::ffff:01.2.3.4", fetched("http://1.2.3.4/"))):
            assert pcm_verify.reached_host({"host": host}, recs)[0] == "unproven", (host, recs)
    finally:
        urllib.parse.clear_cache()


def approval(tool="pay", **edit):
    """alice's approval of call c1, the approval.request it answers and the decision of `tool` that request names, as
    evidence() returns them; `edit`: {record type with _ for .: fields to change in its data}."""
    recs = [{"type": "policy.decision", "seq": 1, "data": {"tool": tool, "decision": "ask", "decision_id": "d1",
                                                           "tool_use_id": "c1"}},
            {"type": "approval.request", "seq": 2, "data": {"approval_id": "a1", "decision_id": "d1"}},
            {"type": "approval", "seq": 3, "data": {"decision": "approve", "tool_use_id": "c1", "approval_id": "a1",
                                                    "person": "alice"}}]
    return [(dict(r, data={**r["data"], **edit.get(r["type"].replace(".", "_"), {})}), None) for r in recs]


def asking(args, *grants):
    """A message of run r1 in tenant default asking for `args` under `grants`: what approved_by's covers reads."""
    return {"from": {"agent": "uid:990101", "run": "r1", "tenant": "default"}, "intent": {"args": args},
            "grants": list(grants)}


ASKED = asking({"amount": 12000, "order": 81})


def test_approved_by_names_what_was_approved():
    """SPEC 6.6: `approved` carries the decision's tool and args; the detail writes the agent's tool name as JSON, so
    it can't spell opened args."""
    tool = 'pay call c1 with args {"amount":20000,"to":"acct-9"} and read_file'
    assert pcm_verify.approved_by({"person": "alice", "call": "c1"}, approval(tool), ASKED, None) == (
        "proven", f"approval seq 3 by alice of {rfc8785.dumps(tool).decode()} call c1", {"tool": tool, "args": None})


ASK, SMALL, MOTD = {"amount": 5000, "order": 81}, {"amount": 500, "order": 81}, {"path": "/etc/motd"}
ROOT = {"issuer": {"kind": "person", "id": "uid:990001", "approval_id": "a1", "run": "r1", "tenant": "default"}}
SAID, GRANTED = 'approval seq 3 by alice of "refund" call c1', 'approval seq 3 by alice of "pcm.grant" call c1'
NOT_OF = 'approval seq 3 by alice of "read_file" call c1{}: not of "refund", the tool the intent\'s schema names, so ' \
    "it does not cover this request"
OTHER = f"{GRANTED}: a pcm.grant approval covers only the requests under the grant it issued, and it did not issue " \
    "this message's root grant"


def opened(recs, args):
    return [(recs[0][0], args), *recs[1:]]


@pytest.mark.parametrize("recs, msg, doc, result, detail", [
    (opened(approval("refund"), ASK), asking(ASK), {"tool": "refund"}, "proven",
     f'{SAID} with args {{"amount":5000,"order":81}}: this request\'s tool and args'),
    # PCM-Lies L3.A.07 and .09: alice approved a refund of 500, the message asks for 5000
    (opened(approval("refund"), SMALL), asking(ASK), {"tool": "refund"}, "failed",
     f'{SAID} with args {{"amount":500,"order":81}}: not this request\'s args {{"amount":5000,"order":81}}, so it '
     "does not cover this request"),
    # L3.A.08 and .10: the same, unopened
    (approval("refund"), asking(ASK), {"tool": "refund"}, "unproven",
     f"{SAID}: its args are not opened, so the verifier can't tell whether they are this request's: open the "
     "decision"),
    # L3.A.11 and .12: alice approved a read_file, the message asks for a refund, opened or not
    (opened(approval("read_file"), MOTD), asking(ASK), {"tool": "refund"}, "failed",
     NOT_OF.format(' with args {"path":"/etc/motd"}')),
    (approval("read_file"), asking(ASK), {"tool": "refund"}, "failed", NOT_OF.format("")),
    (opened(approval("refund"), ASK), asking(ASK), None, "unproven",
     f'{SAID} with args {{"amount":5000,"order":81}}: the intent\'s schema names no tool, so the verifier can\'t tell '
     "whether it covers this request: name the tool in the schema document, or cite the approval that issued the "
     "message's root grant"),
    (approval("pcm.grant"), asking(ASK, ROOT), None, "proven", f"{GRANTED}, which issued this message's root grant"),
    (approval("pcm.grant"), asking(ASK, ROOT), {"tool": "refund"}, "proven",
     f"{GRANTED}, which issued this message's root grant"),
    (approval("pcm.grant"), asking(ASK), {"tool": "refund"}, "failed", OTHER),
    *[(approval("pcm.grant"), asking(ASK, {"issuer": {**ROOT["issuer"], k: v}}), None, "failed", OTHER)
      for k, v in (("approval_id", "a2"), ("run", "r2"), ("tenant", "acme"))]])
def test_approved_by_covers_only_this_request(recs, msg, doc, result, detail):
    """SPEC 6.6: with covers the approval covers the message's request by its tool and args, under a schema that names
    the tool, or as the approval that issued the message's root grant. Without covers the claim only says what alice
    approved."""
    got = pcm_verify.approved_by({"person": "alice", "call": "c1", "covers": True}, recs, msg, doc)
    assert got[:2] == (result, detail) and len(got) == (3 if result == "proven" else 2), got
    assert pcm_verify.approved_by({"person": "alice", "call": "c1"}, recs, msg, doc)[0] == "proven"


def test_a_required_approved_by_must_say_it_covers_the_request():
    """SPEC 8 step 7: a proven approved_by without covers meets no need the schema lists, so a sender that cites an
    approval of another call is not accepted on it; under strict it is rejected."""
    out = {"replay": {"ok": True}, "schema": {"errors": []}, "grants": None,
           "claims": [{"type": "approved_by", "result": "proven", "detail": "d"}]}
    need = {"claims": ["approved_by"]}
    for covers, strict, verdict in ((True, False, "accept"), (True, True, "accept"), (False, False, "accept-unproven"),
                                    (False, True, "reject")):
        sent = [{"type": "approved_by", "args": {"person": "alice", "call": "c1", "covers": covers}}]
        assert pcm_verify._verdict(out, need, strict, sent) == (verdict, [] if covers else [
            "approved_by: required, not proven to cover this request: claim it with covers true"])
    assert pcm_verify._verdict(out, {}, True, sent) == ("accept", [])


@pytest.mark.parametrize("tool, ok", [("refund", True), ("x" * 256, True), ("", False), ("x" * 257, False),
                                      (1, False), (None, False), (["refund"], False)])
def test_a_schema_document_may_name_its_tool(tool, ok):
    assert (pcm_verify.check_schema({**DOC, "tool": tool}) == []) is ok


@pytest.mark.parametrize("edit", [{"approval": {"approver_kind": "agent"}}, {"approval": {"self_approved": True}},
                                  {"approval": {"decision": "reject"}}, {"approval_request": {"approval_id": "a2"}},
                                  {"policy_decision": {"tool_use_id": "c2"}}, {"policy_decision": {"tool": ""}}])
def test_approved_by_needs_a_persons_own_approval_of_the_decision_its_request_names(edit):
    assert pcm_verify.approved_by({"person": "alice", "call": "c1"}, approval(**edit), ASKED, None)[0] == "failed"


def test_approved_by_does_not_depend_on_record_order():
    """SPEC 6.6: records that disagree on what the person approved fail the claim in either order: a decision listed
    unopened and opened, two requests of one approval naming two decisions (the other one in the evidence or not), two
    approvals of the call naming different decisions, args {"x": true} and {"x": 1} among them (equal in Python, apart
    in JCS). Records that agree prove it, by the first approval; an opened decision gives its args."""
    claim, motd = {"person": "alice", "call": "c1"}, {"path": "/etc/motd"}
    dec, req, app = approval("read_file")
    pay = ({"type": "policy.decision", "seq": 4, "data": {"tool": "pay", "decision": "ask", "decision_id": "d2",
                                                          "tool_use_id": "c1"}}, None)
    one = ({"type": "policy.decision", "seq": 4, "data": dict(dec[0]["data"], decision_id="d2")}, {"x": 1})
    again = ({"type": "approval", "seq": 6, "data": dict(app[0]["data"], approval_id="a2")}, None)

    def request(aid, did):
        return {"type": "approval.request", "seq": 5, "data": {"approval_id": aid, "decision_id": did}}, None
    two = "approval seq 3: its approval.request records name 2 decisions"
    for recs, why in (([dec, (dec[0], motd), req, app], "2 different decisions approved as call c1 by alice"),
                      ([dec, req, pay, request("a1", "d2"), app], two), ([dec, req, app, request("a1", "d2")], two),
                      ([dec, req, app, pay, request("a2", "d2"), again], "2 different decisions approved as"),
                      ([(dec[0], {"x": True}), req, app, one, request("a2", "d2"), again],
                       "2 different decisions approved as")):
        for order in (recs, recs[::-1]):
            got = pcm_verify.approved_by(claim, order, ASKED, None)
            assert got[0] == "failed" and why in got[1], (order, got)
    for recs, want in (([dec, req, app, request("a2", "d1"), again], {"tool": "read_file", "args": None}),
                       ([(dec[0], motd), req, app], {"tool": "read_file", "args": motd})):
        end = "" if want["args"] is None else ' with args {"path":"/etc/motd"}'
        for order in (recs, recs[::-1]):
            assert pcm_verify.approved_by(claim, order, ASKED, None) == (
                "proven", f'approval seq 3 by alice of "read_file" call c1{end}', want), order


def test_a_record_listed_twice_fails():
    """SPEC 6.2: evidence that lists a record twice fails, so one opened and one unopened can't make the result depend
    on their order."""
    msg = message()
    records = msg["claims"][0]["evidence"]["records"]
    records.append(dict(records[0]))
    got = check(signed(msg, pcm_verify.MESSAGE_TAG))["claims"][0]
    assert (got["result"], got["detail"]) == ("failed", "record 2: the same record as record 1")


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


@pytest.mark.parametrize("url, host", [("file://a.example/x", ""), ("gopher://a.example/", ""),
                                       ("//a.example/x", "a.example"), ("http://%5b::1%5d/", None)])
def test_only_a_special_or_schemeless_url_has_a_host(url, host):
    """SPEC 6.7 step 4: "" is no host, None a host that won't parse."""
    assert pcm_verify._url_host(url) == host


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
    assert pcm_verify.check_claim(claim, message(), TRUST, None)["result"] == "failed"


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
        with pytest.raises(ValueError, match="2 Ed25519 keys for log .*; PCM verifies with one: pass a trust file "
                                             "with only the current key"):
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
    for garbage in ("{", '{"a": NaN}', '{"a": 1, "a": 2}', "[" * 100000, '{"a": 1e400}', '{"a": -1E400}'):
        r = cli(write("g.json", garbage), "--trust", trust, "--schema", schema)
        assert r.returncode == 2 and "Traceback" not in r.stderr, r.stderr
    r = cli(write("ok.json", message()), "--trust", str(tmp_path / "missing.json"), "--schema", schema)
    assert r.returncode == 2 and "Traceback" not in r.stderr
    assert cli("--json").returncode == 2
    deep = message()
    deep["payload"] = {"kind": "data", "data": json.loads("[" * 200 + "]" * 200)}
    r = cli(write("deep.json", signed(deep, pcm_verify.MESSAGE_TAG)), "--trust", trust, "--schema", schema)
    assert r.returncode == 2 and "deeper than 128" in r.stderr, r.stderr


@pytest.mark.parametrize("text", ["1e400", "-1e400", "1.7976931348623159e308", "[0, 1E309]"])
def test_a_number_past_the_double_range_does_not_parse(text):
    """SPEC 3.3: a number that rounds to no finite IEEE 754 double is bad input, not infinity."""
    with pytest.raises(ValueError, match="IEEE 754 double"):
        loads(text)


def test_numbers_within_the_double_range_parse():
    assert loads("[1.7976931348623157e308, 1e-400, -0.0]") == [1.7976931348623157e308, 0.0, -0.0]


def test_cli_prints_what_a_proven_approved_by_approved(tmp_path):
    inp = json.loads((VECTORS / "accept-approved-by.json").read_text())["input"]
    args = []
    for name, flag in (("message", None), ("trust", "--trust"), ("schemas", "--schema")):
        (tmp_path / name).write_text(json.dumps(inp[name]))
        args += [flag, str(tmp_path / name)] if flag else [str(tmp_path / name)]
    r = cli(*args, "--me", inp["options"]["me"])
    assert (r.returncode, r.stdout) == (0, 'accept\n  approved_by: {"tool": "pcm.grant", "args": null}\n'
                                           "  not checked: replay\n"), r.stderr


def test_cli_escapes_what_the_sender_wrote(tmp_path):
    msg = message()
    msg["to"]["agent"] = "uid:\x1b[2J"
    (tmp_path / "m.json").write_text(json.dumps(signed(msg, pcm_verify.MESSAGE_TAG)))
    (tmp_path / "t.json").write_text(json.dumps(TRUST))
    (tmp_path / "s.json").write_text(json.dumps(DOC))
    r = cli(str(tmp_path / "m.json"), "--trust", str(tmp_path / "t.json"), "--schema", str(tmp_path / "s.json"),
            "--me", "uid:2")
    assert r.returncode == 1 and "\x1b" not in r.stdout and "uid:\\u001b[2J" in r.stdout, (r.stdout, r.stderr)
