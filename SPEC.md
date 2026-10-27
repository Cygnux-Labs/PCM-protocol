# PCM 0.1 (draft): Proof-Carrying Messages

Status: draft 0.1, experimental. Wire version `"pcm": 0`. This text can change before 1.0 without notice.

Editor: Cygnux Labs. Reference implementation: Tracekit ([https://github.com/Cygnux-Labs/Tracekit](https://github.com/Cygnux-Labs/Tracekit)),
the `tracekit.pcm` module and the signer's `pcm_*` calls (Tracekit 1.4.2 plus the issue #436 work, RPC contract
version 20).

Each part of this document carries one of two marks:

- **[Tracekit]**: Tracekit implements it today, and the test vectors in `vectors/` were produced by it.
- **[Draft]**: specified here, implemented nowhere yet.

A rule marked **(decided, 0.1)** settles a question an earlier draft left open, by the stricter and less ambiguous
choice. It is normative. Where it constrains a verifier, Tracekit implements it and the vectors pin it.

Where the Tracekit code and its design notes or user docs disagree, this document follows the code. Appendix A lists
each such place. Where Tracekit does less than this document asks, Appendix B lists the place, with the questions
still open.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT
RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174]
when, and only when, they appear in all capitals, as shown here.

## Contents

1. Overview and the problem
2. Terms
3. The message envelope
4. Canonical form and signatures
5. Intent schemas
6. Claims and evidence
7. Grants
8. Verification algorithm
9. Replay and recipient checks
10. Trust anchors
11. Transport bindings
12. The transfer-record extension (C2C latent transfers)
13. Conformance levels and test vectors
14. Security considerations
15. Privacy considerations
16. Versioning
17. Registrations
18. References
Appendix A. Where this document departs from Tracekit's docs and design
Appendix B. Open issues

## 1. Overview and the problem

Agents pass claims to each other that nobody can check.

Agent A asks agent B to refund $120 on order 81. A says alice approved refunds up to $200 for that order. B has only
A's word. If A was prompt-injected, or another process sends the message in A's name, B pays out anyway. If A says
"the tests passed", B cannot tell whether a test ran, whether it passed, or whether A typed the words itself.

A proof-carrying message (PCM) lets B check the request before it acts. Each message carries:

- **who sent it**: the message is signed by an attesting signer, a service the agent cannot control, and the signer
  signs only as the identity of the calling run;
- **what it asks for**: a typed intent, checked against a schema document both sides agreed on by its content hash;
- **what it claims**: each claim with evidence, records of the sender's own signed log with inclusion proofs;
- **who allowed it**: a chain of grants, rooted in a person's approval, each step only narrower.

B checks all of it offline, with keys it already pins. Every claim gets one of three results: `proven`, `unproven`
or `failed`. A claim that rests only on the agent's word is `unproven`, never `proven`. So B sees what it can rely on
and what it can't.

PCM does not make a compromised agent honest. A prompt-injected A can still ask for anything its grant allows. The
grant, not A, sets the limit.

## 2. Terms

- **Agent**: a program that calls tools and sends messages. It is not trusted.
- **Run**: one session of an agent in a log. A run has an id and a tenant. The signer binds a run to the identity that
  registered it.
- **Identity**: `scheme:subject`, as the transport proved it (a Unix uid, a token, an mTLS certificate, a Kubernetes
  service account, an OIDC subject). Example: `uid:990101`.
- **Tenant**: an isolation unit inside one log. Runs, approvals and grants belong to exactly one tenant.
- **Attesting signer** (signer): the service that holds the signing keys, records the run's events, decides policy,
  and signs messages and grants. The agent never holds a key.
- **Log**: the signer's append-only Merkle log of records. Its **log key** signs checkpoints, messages and grants.
- **Record** (event): one entry in the log. Its hash is `"sha256:" + hex(SHA-256(JCS(event)))`.
- **Checkpoint**: a C2SP tlog-checkpoint signed note naming the log's size and root.
- **Witness**: a party that cosigns checkpoints (C2SP tlog-cosignature).
- **Receiver**: the agent or gateway a message is addressed to.
- **Verifier**: code that checks a message offline, as in section 8.
- **Intent**: what a message asks for: a schema reference and typed args.
- **Schema document**: a small JSON document that types an intent's args (section 5).
- **Claim**: a statement that something happened in the sender's run, with optional evidence (section 6).
- **Evidence**: a checkpoint note plus records of the sender's run, each with an inclusion proof.
- **Opening**: a record's `salt` and `args`, which open a policy decision's args commitment.
- **Grant**: a signed statement that a subject may send an intent within caveats until a time (section 7).
- **Caveat**: one limit on one intent field, such as `amount <= 20000`.
- **Person**: a human approver the signer's approvals configuration names. Not an agent.
- **T1, T2**: who recorded a tool result. T1: the agent's own process reported it. T2: an attesting gateway or
  executor ran the call and recorded the result itself.
- **Tool placement table**: a fixed map from tool name to tool class (`shell`, `http`, ...), shipped with the verifier
  (section 10.2).

## 3. The message envelope

### 3.1 Media type

A PCM message is one JSON object, UTF-8 encoded, of media type `application/vnd.pcm+json` **[Tracekit]**.

### 3.2 Fields

The object is closed: a member not listed here makes the envelope invalid. The JSON Schema of this shape is
`schemas/message.schema.json` (generated from Tracekit's `rpc_schema.PCM_MESSAGE`).

| Field | Required | Set by | Value |
|---|---|---|---|
| `pcm` | yes | signer | the integer `0` for every 0.x draft. Not `false`, not `0.0`. |
| `id` | yes | signer | 32 lowercase hex characters (16 random bytes). |
| `ts` | yes | signer | the signer's clock, UTC, `YYYY-MM-DDTHH:MM:SS.ffffffZ` (exactly 6 fraction digits). |
| `nonce` | yes | signer | 32 lowercase hex characters (16 random bytes). |
| `from` | yes | agent, checked by signer | `{"agent": IDENTITY, "run": ID, "tenant": ID}`, closed. The sending run. |
| `to` | yes | agent | `{"agent": IDENTITY}`, closed. The receiver. |
| `intent` | yes | agent | `{"type": SCHEMA_REF, "args": any JSON value}`, closed (section 5). |
| `claims` | no | agent | array of at most 8 claims (section 6). |
| `grants` | no | agent | array of at most 8 grants, root first (section 7). |
| `payload` | no | agent | `{"kind": "text", "text": string <= 65536}` or `{"kind": "data", "data": any JSON value}`. Nothing checks it. |
| `sig` | yes | signer | `{"key": string 1..300, "sig": string <= 88}`, closed (section 4). |

The value patterns. Every pattern matches the whole value, and character classes are ASCII only. Lengths count
Unicode code points.

| Name | Rule |
|---|---|
| IDENTITY | at most 256; `^[a-z0-9_]+:[^\n]+$` (`scheme:subject`; the subject is any characters but U+000A, so `\r`, U+2028 and U+2029 are allowed) |
| ID | 1 to 128; `^[A-Za-z0-9._:-]+$` |
| SCHEMA_REF | at most 136; `^[a-z][a-z0-9_.-]{0,63}@sha256:[0-9a-f]{64}$` |
| TS | at most 27; `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$` |
| DIGEST | `^sha256:[0-9a-f]{64}$` |

An integer field (`pcm`, `pcm_grant`, `pcm_schema`, schema bounds) MUST be a JSON number written without a fraction
or exponent. `true`, `false`, `0.0` and `"0"` are not the integer 0.

TS values compare correctly as strings, because the format is fixed. This document compares them that way. A TS
also names a real UTC date and time: no month 13, no 30 February, no year 0. The envelope checks only the pattern.
The replay check (section 9) MUST refuse a message whose `ts` is no real time, with "sent at <ts>, which is no real
time", and MUST NOT raise. **[Tracekit]** (vector `reject-replay-no-real-time`: month 13, re-signed with the test log
key, since a signer takes `ts` from its clock.)

Python's `.` refuses only U+000A, while an ECMAScript pattern's `.` also refuses `\r`, U+2028 and U+2029. That is why
IDENTITY is written with `[^\n]`, and the published JSON Schemas write it the same way. Vector
`accept-identity-line-break-chars` sends to `uid:990102\r x`.

### 3.3 Parsing

A receiver MUST parse the message strictly: valid UTF-8, no duplicate member names, integers within
±(2^53 − 1), no lone surrogates, nesting at most 128 deep. A message that does not parse this way MUST NOT be
accepted. **[Tracekit]** (`format.canon.loads_strict`; its CLI reports such input as unreadable, exit 2.)

### 3.4 Example

The examples in this document are real. Unless a section says otherwise, they come from the test vector
`vectors/accept-approved-by.json`, which a Tracekit signer produced (agent A is `uid:990101`, agent B `uid:990102`,
alice `uid:990001`). Regenerating the vectors changes ids, times and signatures.

The message, with its claim and grant shown in sections 6.6 and 7.1:

```json
{
 "from": {"agent": "uid:990101", "run": "bb650aec66cc29fb4ee0de297fd3392f", "tenant": "default"},
 "to": {"agent": "uid:990102"},
 "intent": {"type": "refund.request@sha256:d8636b6fbbd07430d057ea9ead9c27f0df1b918b10d34ab9257a4971d487846c",
            "args": {"amount": 12000, "order": 81}},
 "claims": ["... one approved_by claim, section 6.6 ..."],
 "grants": ["... alice's root grant, section 7.1 ..."],
 "pcm": 0,
 "id": "3bbe19efad3c109917731d71bd8bdfe6",
 "ts": "2026-10-27T14:11:57.612864Z",
 "nonce": "270bfcc642e6360e64b4e3c51a92c506",
 "sig": {"key": "example.com/pcm-test-log+0bb91e66",
         "sig": "kifSgYHZQo0HMTspKWXTcA8A/M5qv36s4GLO5oLUTCQuW/tlscekbjNmzN+qCu/lFtQLCOgChfAULJng1IuWAA=="}
}
```

A message may also carry a payload, such as `"payload": {"kind": "text", "text": "please refund order 81"}`.

## 4. Canonical form and signatures

### 4.1 Canonical form

PCM hashes and signs the JSON Canonicalization Scheme (JCS) [RFC8785] encoding of a value. `H(v)` below is
`"sha256:" + lowercase hex(SHA-256(JCS(v)))`. **[Tracekit]** (`format.canon.canonical`, `event_hash`.)

### 4.2 Signatures

Messages and grants are signed with Ed25519 [RFC8032] by the signer's PCM key, which may be its log key (4.5). The
signed bytes are:

```
JCS( the object without its "sig" member, plus the member "t": TAG )
```

| Object | TAG |
|---|---|
| message | `pcm.message.v0` |
| grant | `pcm.grant.v0` |

The signature covers every member except `sig`, including `claims`, `grants` and `payload` in full. `"t"` is never a
member on the wire: both objects are closed, so a `"t"` member makes the envelope invalid. **[Tracekit]**
(`format.sigmsg.TAGS`.)

The bytes signed for the message in 3.4 start:

```
{"claims":[{"args":{"call":"grant-1","person":"alice"},"evidence":{"checkpoint":"example.com/pcm-test-log\n9\n...
```

and further on, in JCS key order:

```
..."nonce":"270bfcc642e6360e64b4e3c51a92c506","pcm":0,"t":"pcm.message.v0","to":{"agent":"uid:990102"},"ts"...
```

The note's line breaks appear as the two characters `\n`: JCS escapes them.

A grant's signature does not verify as a message's. Vector `reject-grant-signature-as-message` is a message body
signed with the grant tag; the verifier rejects it with "signature: bad signature".

### 4.3 Key names

Log keys are pinned as C2SP signed-note verifier keys (vkeys) [C2SP-NOTE]:

```
<name>+<key id, 8 hex>+<base64(0x01 || 32-byte Ed25519 public key)>
```

where key id = the first 4 bytes of SHA-256(name || 0x0A || 0x01 || public key). Example, the vectors' test log
key: `example.com/pcm-test-log+0bb91e66+ASiESUZlr4+aYnGbR8MnqhEfMelvE25+EAPkEwgpZl6C`. Its `sig.key` is
`example.com/pcm-test-log+0bb91e66`.

`sig.key` is the vkey without its key part: `<name>+<key id hex>`. `sig.sig` is the base64 of the 64-byte
signature.

A verifier finds the pinned log vkey of type 0x01 whose `name+keyid` equals `sig.key`, and verifies the signature
with it. If no pinned key matches, the signature fails ("a key trust.json does not pin"). Invalid base64 is a bad
signature, not an error. **[Tracekit]** (`pcm.check_sig`.)

**Canonical base64 (decided, 0.1).** Every base64 value in PCM (`sig.sig`, evidence proof entries, checkpoint note
roots and signature lines, vkeys) MUST be canonical: the standard alphabet of [RFC4648], padded, no white space or
line break, and the unused bits of the last character zero. A verifier MUST decode it so, and MUST treat text that
is not canonical as invalid: a bad signature in `sig.sig`, "not in the checkpoint" in a proof entry, a failed note in
a checkpoint. Rationale: a value has one text form, so a signed object can't be rewritten into another text that
still verifies (and hashes differently, as a grant's `parent` would). **[Tracekit]** (`checkpoint._unb64`; vectors
`reject-sig-non-canonical-base64`, `reject-claim-proof-non-canonical-base64`.)

Ed25519 verification MUST follow these rules, so two verifiers agree on every signature: the signature is 64 bytes;
its S value is below the group order L; the public key is a canonical encoding (y below 2^255 − 19) of a point that is
not of small order; and the cofactorless equation [S]B = R + [k]A holds. **[Tracekit]** (`crypto.verify_v2`, the same
rules as the rest of Tracekit's v2 format.) Common libraries skip the key checks. Without them, a pinned small-order
key verifies a forged signature on any message: vector `reject-small-order-key` pins the identity point and signs
with R = identity, S = 0.

PCM 0.1 signatures are Ed25519 only. A log that also pins a hybrid SLH-DSA key (10.1) gets no second signature on
messages or grants. **[Tracekit]** (a `lean:` limit in the code.)

### 4.4 The attesting signer

The agent never holds a signing key. It sends the message body to the signer, and the signer signs. **[Tracekit]**
(`pcm_sign`.)

- The signer MUST sign only as the calling run's own identity. It MUST refuse a body whose `from` is not exactly
  `{"agent": <the identity that registered the run>, "run": <its id>, "tenant": <its tenant>}`. Tracekit refuses with
  `forbidden: the signer signs only as the calling run's own agent (uid:990101, run …, tenant default)`.
- The signer MUST refuse a caller that holds the run's token but is not the run's owner (an identity the token was
  delegated to, such as a tailer or an observer).
- The signer MUST set `pcm`, `id`, `ts` and `nonce` itself, from its own clock and randomness. The body the agent
  sends cannot contain them, nor `sig` or `t` (the request shape is closed).
- The signer MUST refuse to sign while the run is held or quarantined (section 14.9).
- The signer SHOULD record each message it signs as a record in the sender's run, holding the message hash, id,
  receiver and intent reference, never the args. Tracekit writes `ext` with `name: pcm.sent`. An auditor of the run
  then sees every message the agent had signed, in order among its tool calls.
- The signer does not check the claims or grants of a message. The verifier does.

### 4.5 The PCM key (decided, 0.1)

A signer SHOULD sign messages and grants with a dedicated PCM key, used for nothing else. A signer MAY sign them
with its log key instead, relying on domain separation by the `pcm.*` tags (4.2, 14.5). Tracekit does the latter
(a `lean:` limit in its code). Either way the trust anchors name the key: it is a vkey of type 0x01 in trust.json
`logs`, under the log's own name (the name `sig.key` carries and the evidence origin check of 6.2 step 2
compares), so a receiver pins it like any log key and needs no other trust member. Rationale: a fault in PCM signing
should not force rotating the key that signs the log, but a receiver must still be able to tell which log a message
speaks for.

## 5. Intent schemas

### 5.1 The schema document

An intent's args are typed by a schema document. Both sides keep a copy. Example (the refund demo's):

```json
{"pcm_schema": 0, "name": "refund.request",
 "fields": {"amount": {"type": "money", "currency": "USD", "max": 1000000},
            "order":  {"type": "int", "min": 1, "max": 999999999}},
 "claims": ["approved_by"], "grant": true}
```

| Member | Required | Value |
|---|---|---|
| `pcm_schema` | yes | the integer `0` |
| `name` | yes | at most 64; `^[a-z][a-z0-9_.-]*$` |
| `fields` | yes | an object; each name `^[a-z][a-z0-9_]{0,63}$`, each value a field spec |
| `claims` | no | the claim types the intent needs, distinct, from the claim registry (section 17.2) |
| `grant` | no | `true`: a message without a grant chain is rejected |

The document is closed. The JSON Schema is `schemas/schema-document.schema.json`. **[Tracekit]** (`pcm.SCHEMA_DOC`,
`pcm.check_schema`.)

### 5.2 Field types

Each field spec is closed. It has `type`, the parameters listed (all required) and optionally `"optional": true`.

| Type | Parameters | A value passes when |
|---|---|---|
| `string` | `max` (1..65536) | it is a string of at most `max` code points |
| `int` | `min`, `max` (safe integers, `min <= max`) | it is an integer, `min <= v <= max` |
| `money` | `currency` (`^[A-Z]{3}$`), `max` (0..2^53−1) | it is an integer number of minor units (cents) of `currency`, `0 <= v <= max` |
| `id` | `pattern` (1..256 characters, a regular expression) | it is a string of at most 128 code points that the whole pattern matches |
| `enum` | `values` (1..256 distinct strings) | it is one of `values` |
| `bool` | none | it is `true` or `false` |
| `time` | none | it matches TS |

Nothing is converted. `true`, `120.0` and `"120"` are not ints. $120.00 is `12000`.

PCM 0.1 does not fix the regular expression dialect of `id` patterns. Schema authors SHOULD use only what ECMAScript
and Python `re` read the same way, with ASCII classes (`[0-9]`, not `\d`). Tracekit runs `id` patterns with Python
`re` in its default Unicode mode, where `\d` also matches digits such as `٣`.

A verifier MUST refuse a schema document that does not meet 5.1 and 5.2, or whose `int` field has `min > max`, whose
`enum` values repeat, or whose `id` pattern does not compile. That is a configuration error of the receiver, not a
verdict on a message. **[Tracekit]** (`verify` raises `ValueError`.)

### 5.3 Strict matching of args

`intent.args` MUST be an object. Every member MUST be a field of the document. Every field without `optional` MUST be
present. Every present value MUST pass its field's rule. A real check from Tracekit:

```
args {"amount": 120.0, "order": true, "extra": 1} ->
  args.extra: not in the schema
  args.amount: 120.0 is not a valid money
  args.order: true is not a valid int
```

### 5.4 Content addressing

A schema's name on the wire is `name@H(document)`:

```
refund.request@sha256:d8636b6fbbd07430d057ea9ead9c27f0df1b918b10d34ab9257a4971d487846c
```

A verifier indexes the documents it was given by this computed reference. An `intent.type` that matches none of them
fails the schema check (`unknown schema <ref>`). So an edited document is a different schema, and a reference whose
hash differs by one character matches nothing.

## 6. Claims and evidence

### 6.1 Claims

A claim is `{"type", "args", "evidence"?}`, closed. `type` is one of the registered claim types (section 17.2).
`args` are checked against the claim type's argument table below, with the rules of 5.3. A claim whose args fail is
`failed`; it does not make the envelope invalid. **[Tracekit]**

| Claim type | Args |
|---|---|
| `tests_passed` | `suite`: string, at most 4096 |
| `approved_by` | `person`: string, at most 256; `call`: id matching ID |
| `reached_host` | `host`: id, `^[a-z0-9._:-]+$`, at most 128 (the cap of every `id` value, 5.2; vector `reject-claim-reached-host-too-long`) |
| `file_written` | `path`: string, at most 4096; `digest`: id matching DIGEST |

Each claim gets one result:

- **proven**: the evidence verifies and a record in it says what the claim says, recorded by a party other than the
  agent (6.4).
- **unproven**: there is no evidence, or the only matching record is the agent's own report (T1), or the matching
  call is of a tool the verifier can't place (6.5), or the verifier can't tell whether a record matches: a host that
  won't parse (6.7), a `Write` of a relative path that may be the claimed file (6.6).
- **failed**: the claim's args are invalid or malformed (a `file_written` path that is relative or has a `..`
  segment, 6.6; a `tests_passed` suite that is no test command, 6.8), the evidence does not verify, or no record in it
  says what the claim says. The args and malformed checks come before the evidence: a malformed claim is `failed`
  with or without evidence, at every conformance level (vectors `reject-claim-tests-passed-malformed-no-evidence`,
  `reject-claim-file-written-relative-no-evidence`). **[Tracekit]**

When several records match, the best result counts: proven, then unproven, then failed.

### 6.2 Evidence items

Evidence is `{"checkpoint", "records"}`, closed (`schemas/evidence.schema.json`):

- `checkpoint`: a C2SP tlog-checkpoint signed note [C2SP-CKPT], 1 to 16384 characters:

  ```
  <origin>\n<tree size>\n<base64 root hash>\n\n— <key name> <base64(key id || signature)>\n ...
  ```

  PCM 0.1 accepts exactly the three body lines (no extension lines). **[Tracekit]**
- `records`: 1 to 16 records, each `{"event", "hash", "proof", "salt"?, "args"?}`, closed:
  - `event`: the log record, as the signer wrote it;
  - `hash`: DIGEST, `H(event)`;
  - `proof`: at most 64 base64 strings (each at most 44 characters), the RFC 9162 inclusion proof;
  - `salt` (64 hex) and `args` (any JSON value): an opening (6.3).

A verifier checks an evidence item in this order. The first failure makes the claim `failed`, with the reason.
**[Tracekit]** (`claims.evidence`.)

1. **Note.** The note verifies against the pinned keys (section 10). These are the rules of [C2SP-NOTE],
   [C2SP-CKPT] and [C2SP-COSIG] as Tracekit applies them (`checkpoint.open_note`); breaking any one fails the note:
   - The note ends with `\n` and holds no control character but `\n`. Its text is everything up to the first blank
     line, with its final `\n`. The text is exactly three lines: the origin, the tree size and the root.
   - The origin, and every key name, is 1 to 255 UTF-8 bytes with no `+`, no white space and no control character.
     The tree size is ASCII decimal, at most 20 digits, with no leading zero. The root is 32 bytes.
   - After the blank line come 1 to 64 signature lines. Each is `— `, a key name, one space and base64 of at least
     5 bytes: a 4-byte key id, then the signature. Base64 here MUST be canonical. Every line MUST be well formed, even
     one of a key trust does not pin (vector `reject-claim-malformed-unpinned-note-line`).
   - No (key name, key id) appears twice.
   - A line whose (name, key id) no pinned key has is skipped. A line of a pinned Ed25519 log key MUST verify over the
     text (4.3). A line of a pinned witness key is exactly 72 bytes after the key id: an 8-byte big-endian time `t`,
     then an Ed25519 signature over `cosignature/v1\ntime <t>\n` followed by the text.
   - A key in `logs` that is a cosignature key, or a key in `witnesses` that is not, fails the note.
   - At least one pinned Ed25519 log key named after the origin MUST have a valid line; other pinned keys of that
     name need none (a dedicated PCM key, 4.5, signs no checkpoint). When trust pins a hybrid key named after the
     origin, its line MUST be present and valid (10.1).
2. **Same log.** The note's origin equals the key name in the message's `sig.key` (the part before the last `+`).
   Evidence from another log fails, even if that log is pinned too (section 14.1).
3. **Witnesses.** The note carries at least `witnesses_required` valid cosignatures from pinned witness keys
   (vectors `accept-witnessed`, `reject-claim-witnesses-required-unmet`).
4. For each record, numbered from 1:
   1. `event` is an object and `H(event) == hash`; else "record i: hash does not match the event".
   2. Every `proof` entry is canonical base64 (4.3), `event.seq` is an integer, and the RFC 9162 section 2.1.3.2
      check passes with leaf index `event.seq`, the note's tree size and root, and leaf hash
      `SHA-256(0x00 || the 32 bytes hash names)`. Interior nodes are `SHA-256(0x01 || left || right)`
      [RFC6962] [RFC9162]. Else "record i: not in the checkpoint".
   3. `event.tenant == from.tenant` and `event.run_id == from.run`: the record is from the sender's own run.
   4. `event` is a valid event of the evidence profile (6.4): `schema_version` is `tracekit.event.v2` and the event
      matches that profile's event schema, `registry/tracekit.event.v2.json`; else "record i: not a valid event".
      A pinned log can still be hostile, and a checker must not meet a record without the fields it reads. **[Tracekit]**
      (vector `reject-claim-record-not-an-event`: an approval whose `prev_hash` is the number 5, a field no checker
      reads, under a checkpoint the test log key signs offline.)
   5. If the record has `salt` or `args`, it MUST have both, `event.type` MUST be `policy.decision`, and the opening
      MUST verify (6.3). Vectors: `reject-claim-salt-without-args`, `reject-claim-opening-wrong-args`.

### 6.3 Openings

A signer that never stores tool args in clear commits to them. In the evidence profile (6.4), a `policy.decision`
record holds:

```
data.args_commitment = "hmac-sha256:" + hex( HMAC-SHA256( key = salt, msg = ASCII( H({"tool": data.tool, "args": args}) ) ) )
```

where `salt` is 32 bytes, sent as 64 hex characters. The opening holds `salt` and `args`. The verifier recomputes the
commitment from `data.tool`, the given `args` and `salt`, and compares in constant time. Only an opened decision's
args are read by a claim checker. **[Tracekit]**

### 6.4 The evidence profile `tracekit.event.v2`

Claim checkers read records. Which fields they read, and what the fields mean, is an **evidence profile**. PCM 0.1
defines one profile: Tracekit's v2 event format (`schema_version: "tracekit.event.v2"`). **[Tracekit]**

The profile's trust assumptions. A verifier relies on them, and a log that offers this profile MUST meet them:

- `approval` records are written by the signer only, from the answer of an identity it authenticated. `data.approver`
  is that identity. `data.person` is there only when the signer's approvals configuration maps that identity to a
  person's name. An agent approver's answer carries `approver_kind: "agent"`. A signer without an approvals
  configuration lets any identity of the run's tenant but the run's own answer, and records no `approver_kind`: such
  an answer may come from another agent process (6.6, `approved_by`).
- `effect.observed` records are written by the signer only, from an observer's report. The signer gives a report to
  the run whose token came with it, or else to the latest open run of the identity the observer names, by time. With
  two runs of one identity open at once, an effect can land in the other run.
- A `tool.result` record's top-level `source` and `tier` are set by the signer from the authenticated caller. They are
  `"gateway"` and `"T2"` only when an attesting gateway or executor ran the call and recorded its result. Nothing in
  `data` sets them.
- A `policy.decision` record's `args_commitment` commits to the args the signer decided.

The fields each checker reads:

| Record type | Fields read |
|---|---|
| every record | `seq` (log index), `tenant`, `run_id`, `type`, `data` |
| `policy.decision` | `data.tool`, `data.decision` (`allow`, `ask`, `deny`), `data.decision_id`, `data.tool_use_id`, `data.args_commitment` |
| `tool.result` | top-level `source` and `tier`; `data.decision_id`, `data.tool_use_id`, `data.ok`; `data.via` (detail text only) |
| `approval` | `data.decision`, `data.tool_use_id`, `data.person`, `data.approver_kind` (absent means `person`), `data.self_approved` |
| `effect.observed` | `data.host`, `data.kind`, `data.denied`; `data.observer` (detail text only) |

A real `approval` record, as evidence carries it:

```json
{"schema_version": "tracekit.event.v2", "id": "355a699d3b9517be68b62f40dcaff0bd", "seq": 5,
 "prev_hash": "sha256:cd50e5be123d0cbb792581b0b878096000231b2245cec964d0ac123782abd181",
 "ts": "2026-10-27T14:11:57.591019Z", "run_id": "bb650aec66cc29fb4ee0de297fd3392f", "agent_id": "main",
 "parent_id": null, "source": "sdk", "type": "approval",
 "data": {"tool_use_id": "grant-1", "approval_id": "apr-f64cebe370aa43f2c14051fa70226929", "decision": "approve",
          "approver": "uid:990001", "approver_identity": {"scheme": "uid", "subject": "990001", "attested": true},
          "channel": "rpc", "self_approved": false, "person": "alice"},
 "tenant": "default", "log_id": "4b583d8211fe9891e76921977c9d6f37", "run_seq": 3,
 "run_prev_hash": "sha256:cd50e5be123d0cbb792581b0b878096000231b2245cec964d0ac123782abd181",
 "request_id": "r4", "tool_call_id": "grant-1"}
```

### 6.5 T1, T2 and tool placement

**T1 vs T2.** A tool result the agent's own process reported (T1) is the agent's word: its `ok` is whatever the client
sent. Only a T2 result, or a signer-side record (a person's approval, an observer's effect), proves a claim. A claim
that rests on a T1 result is `unproven`, never `proven`. The T2 mark is read from the record's top-level `source` and
`tier`, never from `data` or anything else the agent wrote.

**Tool placement.** A `command` or `url` member does not make a tool a shell or http tool. The verifier places a tool
by its name, in a fixed tool placement table (section 10.2). A matching call of a tool the table does not place in the
needed class gives `unproven` ("a tool the verifier can't place as a shell tool").

**A call ran.** Several checkers ask whether a call ran and succeeded. `Ran(match, class)` over the records of one
evidence item is:

1. Start with `failed` ("no call in the evidence …").
2. For each record with an opening (so a `policy.decision`) whose opened `args` are an object, that has
   `data.tool` and `data.decision_id` (the event schema leaves both optional; a decision without them matches no
   call: vector `reject-claim-decision-without-id`), and where `data.decision != "deny"`: `match(data.tool, args)`
   answers yes, no, or can't tell. Can't tell: candidate `unproven` ("the verifier can't tell whether call …"); next
   record. No: next record. Yes:
   1. If `class` is set and the placement table does not map `data.tool` to `class`: candidate `unproven`; next record.
   2. For each `tool.result` record whose `(data.decision_id, data.tool_use_id)` equals the decision's:
      - `data.ok` is not `true`: candidate `failed` ("… and failed");
      - else top-level `source == "gateway"` and `tier == "T2"`: result `proven`; stop;
      - else: candidate `unproven` ("the result is the agent's own report (T1)").
3. The result is the best candidate.

From vector `accept-tests-passed-t2`: the evidence for `tests_passed {"suite": "pytest -q tests/test_refund.py"}`
holds an opened decision and its result, both recorded through the tool executor:

```json
[{"event": {"type": "policy.decision", "seq": 10, "source": "gateway", "tier": "T2", "...": "...",
            "data": {"tool_use_id": "call-9", "tool": "Bash", "decision": "allow",
                     "decision_id": "dec-6f24de7a414a186e04e9f2a8895ecd6a", "via": "mtls:spiffe://example/executor",
                     "args_commitment": "hmac-sha256:73d99aec597b8b4d7c370d3f009f7baaf221c25189ca6495a35c95b566815ad8",
                     "...": "..."}},
  "salt": "09e381912a1cac093f63e0b22261446f4796d480b3b882438df786426c7ba2a1",
  "args": {"command": "pytest -q tests/test_refund.py"}, "hash": "...", "proof": ["..."]},
 {"event": {"type": "tool.result", "seq": 11, "source": "gateway", "tier": "T2", "...": "...",
            "data": {"tool_use_id": "call-9", "ok": true, "decision_id": "dec-6f24de7a414a186e04e9f2a8895ecd6a",
                     "via": "mtls:spiffe://example/executor", "...": "..."}},
  "hash": "...", "proof": ["..."]}]
```

Result: `proven`, "call call-9 ran 'pytest -q tests/test_refund.py', run by mtls:spiffe://example/executor (T2)".
The same claim with a result the agent reported itself is `unproven` (`accept-unproven-t1-result`), and so is one
run through `mcp:ci/run`, a tool the table does not place as `shell` (`accept-unproven-unplaced-tool`).

### 6.6 The four claim types

**`tests_passed {suite}`** **[Tracekit]**

1. `suite` MUST be one test command (6.8). Else `failed` ("… is not a single test command"), with or without
   evidence (6.1).

   `pytest -q tests/x.py` and `npm test` pass this step. `pytest || true`, `pytest; true`, `pytest &`, `echo hi`,
   `bash -c 'pytest || true'` (the program is `bash`), `uv run pytest` (a wrapper), `./pytest` (not a bare name),
   `pytest --co` (runs no tests) and `pytest -q tests/x.py # || true` (a `#`) do not.
2. Then `Ran(match, "shell")`, where `match` holds when the call's shell command equals `suite` exactly. The shell
   command is the first non-null of the args members `command`, `cmd`, `commands`.

What `proven` means: the signer recorded that this exact command line ran through an attesting executor and exited 0.
It does not mean every test passed, nor that the tests a receiver cares about ran:

- runners take flags 6.8 does not refuse that select or run no tests and still exit 0: `pytest -qh` (a cluster with
  `-h`), `pytest --fixtures`, `go test -run NONE`, `go test -exec true`, `make test -n`,
  `make test SHELL=/bin/true`, `npm test --script-shell=true`, `cargo test --no-run`, `mvn test -DskipTests`,
  `jest --listTests`;
- the program is whatever the executor's `PATH` and working directory supply under the runner's name, and the
  runner reads its own configuration (`pytest.ini`, `package.json`, a `Makefile`) from the working directory, which
  the agent may have written.

A receiver MUST compare `suite` with the suites it accepts and MUST NOT rely on the runner list of 6.8 to tell a
real test run from another. Vectors: `accept-tests-passed-t2`, `accept-tests-passed-npm-test`,
`accept-tests-passed-python-m-pytest`, `reject-claim-pytest-or-true`, `reject-claim-bash-c`,
`reject-claim-hash-inside-word`, `reject-claim-tests-passed-comment`, `reject-claim-tests-passed-background`,
`reject-claim-tests-passed-ansi-c-quote`, `reject-claim-tests-passed-unbalanced-quote`,
`reject-claim-tests-passed-dot-slash`, `reject-claim-tests-passed-runner-path`, `reject-claim-tests-passed-co`,
`reject-claim-tests-passed-collect-only`, `reject-claim-tests-passed-help`, `reject-claim-tests-passed-h`,
`reject-claim-tests-passed-version`, `reject-claim-tests-passed-V`, `reject-claim-tests-passed-he`,
`reject-claim-tests-passed-wrapper`, `reject-claim-tests-passed-malformed-no-evidence`, `reject-claim-tests-failed`
(the T2 result is an error).

**`approved_by {person, call}`** **[Tracekit]**

`proven` when a record has `type == "approval"`, `data.decision == "approve"`, `data.tool_use_id == call`,
`data.person == person`, `data.approver_kind` is absent or `"person"`, and `data.self_approved` is not `true`. Else
`failed`. No T2 is needed: the signer writes approvals.

**Only a configured person (decided, 0.1).** `person` is compared with `data.person` only, never with
`data.approver`. `data.person` is there only when the signer's approvals configuration maps the answering identity
to a person's name (6.4), so a claim that names a raw identity, or an identity no person maps to, is `failed`.
Rationale: without an approvals configuration any identity of the tenant may answer, so a raw identity proves no
human looked. **[Tracekit]** (vector `reject-claim-approved-by-unmapped-identity`: `uid:990009` answers and no person
maps to it.)

What `proven` means: the person the signer's approvals configuration names `person` answered "approve" to call
`call`.

The claim of `accept-approved-by`, with its evidence:

```json
{"type": "approved_by", "args": {"person": "alice", "call": "grant-1"},
 "evidence": {
  "checkpoint": "example.com/pcm-test-log\n9\nZXhZWXHeS0bz3YSEmavclQ625T/zTkJWtlj3/UlZ+wQ=\n\n— example.com/pcm-test-log C7keZnFJpPe6KxvhUXDapyf7QZJdtlzTv0SDuxIlD64H7S6IE97K6Xm5kP8T8oS2i/l1n5X0wObT6q5ghWvaowA7fgU=\n",
  "records": [{"event": {"...": "the approval record of 6.4"},
               "hash": "sha256:28f907f8a23ad9da3c6e8c13628ac6f3ddf1917a16e82887c3851c98cd5056ff",
               "proof": ["z37pA0XQSZRpEOunXdL8E9y90bPpvcvqsuKsjeIF4JU=",
                         "wR29D4XHHgZQ6WrODvNbSPZnh6yrg7QBlEJlDHfEgFQ=",
                         "HLiOLzvRXW9DnSkqg/8Zd/4fQxgKsOZzT44slptKTEg=",
                         "uARbbqEXw3+3ZhPuu9TNSX3t4aLteFhrKkVXzJEBCtg="]}]}}
```

Result: `{"type": "approved_by", "result": "proven", "detail": "approval seq 5 by alice of grant-1"}`. The vectors
show the other outcomes: one hex digit of `hash` changed (`reject-claim-changed-record-hash`: "record 1: hash does not
match the event"), the proof's last hash cut (`reject-claim-cut-proof`), another person named
(`reject-claim-wrong-person`), the approval of another call (`reject-claim-approval-of-another-call`), a proof entry
that is not canonical base64 (`reject-claim-proof-non-canonical-base64`).

**`reached_host {host}`** **[Tracekit]**

Hosts are compared in the form of 6.7.

1. If the claim's `host` won't parse (6.7): `unproven` ("… is no host the verifier can read"). Vector
   `accept-unproven-reached-host-unreadable-claim` (`a..example`, an empty label).
2. `proven` when a record has `type == "effect.observed"`, `data.kind` is `"net"` or `"connect"`, `data.denied` is
   absent or false, and `data.host` has the claim's compared form. The signer wrote it from an egress observer or a
   kernel sensor (vector `accept-reached-host-observed`). Such a record whose `data.host` is absent or won't parse is a
   candidate `unproven`.
3. Else the best of that candidate and `Ran(match, "http")`, where `match` reads the args member `url`: not a string,
   or a URL with no host (6.7 step 2: a scheme other than `http`, `https`, `ws`, `wss` and `ftp`, such as `file:`,
   `mailto:` or `gopher:`, or no host at all): no; a URL whose host won't parse: can't tell; else yes when the URL's
   host has the claim's compared form.

Vectors: `accept-reached-host-http` (`https://API.Example.COM:8443/v1` is `api.example.com`),
`accept-reached-host-claim-port`, `accept-reached-host-trailing-dot`, `accept-reached-host-short-ipv4`,
`accept-reached-host-idn`, `accept-reached-host-unassigned`, `reject-claim-reached-host-other-host`,
`reject-claim-reached-host-file-url`, `accept-unproven-reached-host-bracket`, `accept-unproven-reached-host-ambiguous`,
`accept-unproven-reached-host-deviation`, `accept-unproven-reached-host-no-ipv6`, `accept-unproven-reached-host-nul`,
`accept-unproven-reached-host-claim-bad-port`.

**`file_written {path, digest}`** **[Tracekit]**

A path is **absolute** when, with `\` read as `/`, it starts with `/` or with a letter, `:` and `/` (`C:/x`). A path
is **rewritten** this way (`policy2.classes.fs_path`): `\` becomes `/`. An absolute path with no `..` segment is
cleaned as POSIX `normpath` does (repeated `/` and `.` segments go; exactly two leading slashes stay, so `//a/b` stays
`//a/b`). Any other path keeps only the part after its last `..` segment, without empty and `.` segments.

Steps 1 and 2 make a claim malformed, so they apply with or without evidence (6.1).

1. If `path`, with `\` read as `/`, has a `..` segment: `failed` ("name the file's own path").
2. **Absolute paths only (decided, 0.1).** If `path` is not absolute: `failed` ("… is relative: name the file's
   absolute path"). Rationale: a relative path names a different file from each working directory, so it can't say
   which file was written. Vectors `reject-claim-file-written-relative` (a Write of the same relative path, which
   would match without this rule), `reject-claim-file-written-relative-no-evidence`.
3. Else `Ran(match)` with no class. `match` is no unless all of these hold:
   - the tool is a write tool: its name maps to the file operation `write` in the reference table, which in 0.1 is the
     tool `Write` only (an `op` member in the args is the agent's word and is ignored);
   - the file path of the args (the first non-null of `file_path`, `notebook_path`, `path`) is a string;
   - the args member `content` is a string, and `"sha256:" + hex(SHA-256(UTF-8 content)) == digest` (what `sha256sum`
     prints for the file, with `sha256:` in front). Edits without the full content never count.

   Then, with `want` the claim's rewritten `path` and `got` the args' rewritten path: `got == want` is yes. A `got`
   that is not absolute, where `"/" + want` ends with `"/" + got`, is can't tell: the record does not hold the
   working directory, so it may be this file or another (`unproven`, never `proven`; vector
   `accept-unproven-file-written-relative-call`). Anything else is no.

Vectors: `accept-file-written`, `reject-claim-file-written-wrong-digest`, `reject-claim-file-written-dotdot`,
`reject-claim-file-written-relative`, `accept-unproven-file-written-relative-call`.

### 6.7 Hosts (decided, 0.1)

`reached_host` compares hosts in one canonical form: the claim's `host`, an effect's `data.host` and a call's URL
host alike. Two hosts match when their compared forms are equal. Ports are ignored. A host that won't parse has no
compared form, and gives `unproven`, never `proven` or `failed`. Rationale: a host has many spellings
(`API.Example.COM:8443`, `api.example.com.`, `bücher.example`, `127.1`); comparing one canonical form makes every
spelling of the same host match. Where two readers this section names disagree on a host (a browser and `urllib`,
IDNA 2003 and UTS 46), the host won't parse rather than match a host the call may not have reached, and a host the
verifier can't read proves nothing either way. **[Tracekit]** (`claims._host`, `claims._a_label`, `claims._deviant`,
`policy2.classes.url_info`.)

The intent is the WHATWG URL host parser [WHATWG-URL] followed by IDNA. PCM 0.1 specifies what the reference
implements with the Python standard library, step by step. A verifier in Python MUST run on CPython 3.11.4 or later
(earlier versions read brackets in `urlsplit` differently, step 2). The vectors were made on CPython 3.11.15.

1. **A URL.** Remove tabs and line breaks. If the URL, with leading controls and spaces skipped, does not start with
   `http:`, `https:`, `ws:`, `wss:`, `ftp:`, `file:`, another scheme (`[A-Za-z][A-Za-z0-9+.-]*` and `:`) not followed
   by a digit (so `localhost:` at the end is a scheme), or two slashes (`/` or `\`), put `http://` in front:
   `example.com:8080/x` is `http://example.com:8080/x`.
2. **The scheme, then the host read two ways.** Read the URL as a browser does: drop tabs and line breaks, strip
   leading and trailing C0 controls and spaces, and peel `view-source:` and `blob:`. Its scheme is the leading
   `[A-Za-z][A-Za-z0-9+.-]*` before a `:`, in lower case, or none. A URL whose scheme is not `http`, `https`, `ws`,
   `wss` or `ftp`, and not none (`//host`), has no host, whatever `urllib` reads (`file://api.example.com/x`,
   `gopher://g.example/`; vector `reject-claim-reached-host-file-url`). Otherwise read the host:
   - as `urllib.parse.urlsplit(url).hostname` reads it. If `urlsplit` refuses the URL, the host won't parse. From
     CPython 3.11.4 it raises for a `[` or `]` without the other, and for a netloc whose bracketed part is neither an
     IPv6 nor an IPvFuture address (`http://[x]@good.com/`; vector `accept-unproven-reached-host-bracket`). Patch
     releases since have changed which netlocs with brackets it refuses (on 3.11.15, a bracketed IPv6 address before the `@` is
     refused because `good.com`, the host after the last `@`, is no address), so a URL with `[` or `]` outside a
     bracketed IPv6 host can read differently between verifiers' Pythons. Senders SHOULD NOT send such URLs
     (Appendix B question 1);
   - as a browser reads it: read `\` as `/`, take what follows the slashes up to `/`, `?` or `#`, then what follows
     the last `@`, then drop the port (a `[...]` IPv6 host keeps its brackets).

   Put each non-empty reading in canonical form (step 3). Neither reading: the URL has no host. Two readings whose
   canonical forms differ: the host won't parse, since the call may have reached either
   (`http://a.example\@b.example/` is `a.example` to a browser and `b.example` to `urllib`; vector
   `accept-unproven-reached-host-ambiguous`). Else the host is the browser's reading, or `urllib`'s when the browser
   has none.
3. **Canonical form.** Percent-decode as UTF-8 (an invalid sequence becomes U+FFFD, which step 4 refuses) and apply
   Unicode NFKC. **Deviation characters (decided, 0.1).** If the result holds U+00DF `ß`, U+03C2 `ς`, U+200C ZWNJ or
   U+200D ZWJ, it won't parse. For a call's URL the check covers the whole URL, percent-decoded and NFKC-normalised,
   its path too (a `lean:` limit of the reference: it gives `unproven` where a stricter reading of the host alone
   could match). Rationale: these are the four characters UTS 46 nontransitional processing, which browsers use,
   keeps where IDNA 2003 maps them away, so `faß.example` is `xn--fa-hia.example` to a browser and `fass.example` to
   the codec of step 4; with them refused, the two either agree or one refuses (vector
   `accept-unproven-reached-host-deviation`). Then read U+3002 as `.` and casefold. If it names an address, write it
   in canonical form: IPv4 is read as `inet_aton` reads it, 1 to 4 parts, each decimal, `0x` hex or `0` octal, so
   `127.1` is `127.0.0.1` (vector `accept-reached-host-short-ipv4`); an IPv6 address is `[...]` in compressed form,
   an IPv4-mapped or NAT64 (`64:ff9b::/96`) one the IPv4 address inside. Something that ends in a number but is no
   valid address won't parse. NFKC follows the Unicode version of the verifier's `unicodedata` (14.0 in CPython
   3.11): a host with a code point that version leaves unassigned can read differently in a verifier with a newer
   one, so senders SHOULD claim ASCII hosts.
4. **A-label.** A host that starts with `[` stays as it is if it is `[`, an IPv6 address and `]`; else it won't
   parse (`http://%5b::1%5d/` decodes to the host `[`; vector `accept-unproven-reached-host-no-ipv6`). Otherwise drop
   one trailing dot (vector `accept-reached-host-trailing-dot`); if the rest is empty or still ends with `.`, it won't
   parse. Then convert it with Python's `idna` codec (`name.encode("idna")`), which is IDNA 2003: an all-ASCII name
   is kept as it is, and each label must be 1 to 63 characters; any other name is split at `.` and each label goes
   through ToASCII [RFC3490] with Nameprep [RFC3491] (Unicode 3.2) and Punycode [RFC3492], with AllowUnassigned on
   (CPython's codec does not check Nameprep's table A.1, so a code point Unicode 3.2 leaves unassigned is taken:
   `x` and U+0378 then `.example` is `xn--x-qib.example`, vector `accept-reached-host-unassigned`) and
   UseSTD3ASCIIRules off: an ASCII label stays, a non-ASCII one becomes `xn--` and its Punycode, and every label
   must end up 1 to 63 characters. What the codec refuses won't parse. The result MUST be labels of `a`-`z`,
   `0`-`9`, `_` and `-`, joined by single dots; else it won't parse (a NUL or `%` after percent-decoding; vector
   `accept-unproven-reached-host-nul`). `bücher.example` is `xn--bcher-kva.example` (vector
   `accept-reached-host-idn`).

**A claim's or an effect's host** is a name or address, maybe with a port. It won't parse if it is not a string, if
it holds `/`, `\`, `?`, `#`, `@`, `[`, `]` or Unicode white space (Python's `\s`), if it holds a deviation character
(step 3), or if it has exactly one `:` and what follows it is not 1 to 5 ASCII digits (`api.example.com:abc`,
`api.example.com:`; vector `accept-unproven-reached-host-claim-bad-port`). Otherwise it is read as the host of the
URL `http://[<host>]/` when it has more than one `:` (a bare IPv6 address), else `http://<host>/`, by steps 2 to 4,
except that the two readings are not compared: the browser's reading counts. So the claim `api.example.com:443` is
`api.example.com` (vector `accept-reached-host-claim-port`).

Where IDNA 2003 and UTS 46 [UTS46] still differ, PCM 0.1 follows the codec, a `lean:` limit of the reference: an
`xn--` label is not checked to be valid Punycode, `_` is allowed, unassigned code points are taken, ZWSP, soft hyphen
and the other characters Nameprep maps to nothing are dropped (`exam` U+00AD `ple.com` is `example.com`), and
Nameprep uses Unicode 3.2. A verifier MUST implement the steps above as
written, not UTS 46. Senders SHOULD claim hosts in ASCII, as DNS names them.

### 6.8 Test commands (decided, 0.1)

A `tests_passed` suite is a **test command** when all of these hold. Rationale: every verifier must recognise the same
commands, so the list is part of the protocol, not a guess at what a command does; the suite must read the same to
every verifier and to `sh`, so it may hold nothing on which a shell and a word splitter can differ; and a flag that
runs no tests must not prove that tests passed. **[Tracekit]** (`claims.test_command`, `claims.TEST_RUNNERS`,
`claims.NO_TESTS`.)

1. **Plain words (decided, 0.1).** `suite` MUST NOT hold any of the characters `;` `&` `|` `(` `)` `<` `>` `$`
   `` ` `` `\` `#` `{` `}` `*` `?` `[` `]`, nor a control character (U+0000 to U+001F and U+007F) other than tab: so
   no operator, background `&`, redirection, expansion, escape, comment, brace expansion, glob or second line. Split
   it into words at spaces and tabs, where `'…'` and `"…"` group characters into a word and are removed (Python's
   `shlex.split`); its quotes MUST balance. Rationale: an earlier draft cut a line at operators with a word splitter
   that reads `$'\''` apart from `sh` (`pytest $'\'';true #'` is one command to it and `pytest "'"; true` to `sh`),
   kept `pytest &` and `(pytest &)` as one command, and let a glob or brace expansion turn into a flag in the working
   directory (`pytest -[h]`). With none of these characters, inside double quotes nothing is special, and every
   splitter reads the same words as `sh`. Vectors `reject-claim-tests-passed-background`,
   `reject-claim-tests-passed-ansi-c-quote`, `reject-claim-tests-passed-unbalanced-quote`,
   `reject-claim-tests-passed-comment`, `reject-claim-hash-inside-word`, `reject-claim-pytest-or-true`.
2. **A listed runner.** The words MUST begin with one of these word sequences, compared exactly, so the first word is
   a bare program name a shell looks up on `PATH` (`./pytest`, `/tmp/x/pytest` and `.venv/bin/pytest` are not
   `pytest`; vectors `reject-claim-tests-passed-dot-slash`, `reject-claim-tests-passed-runner-path`). The list is a
   deliberately strict subset of the test commands the reference's shell analysis knows (no `./gradlew test`,
   `./mvnw test`, `gmake test`, `make tests`, `npm t` or `npm run test:unit`):

   ```text
   pytest  py.test  python -m pytest  python3 -m pytest  python -m unittest  python3 -m unittest  tox  nox  nose2
   trial  behave  jest  vitest  mocha  ava  karma  cucumber  playwright test  phpunit  rspec  ctest
   npm test  npm run test  yarn test  yarn run test  pnpm test  pnpm run test  bun test
   go test  cargo test  cargo nextest run  dotnet test  deno test  swift test  mix test  bazel test
   make test  make check  mvn test  mvn verify  gradle test  gradle check
   ```

   A wrapper or an assignment in front (`uv run pytest`, `CI=1 pytest`, `sudo pytest`) is no test command (vector
   `reject-claim-tests-passed-wrapper`): claim the command the way the list writes it.
3. **Runs tests.** No word is `-h` or `-V`, and no word of 3 or more characters is a prefix of `--help`,
   `--version` or `--collect-only` (so `--he`, `--vers`, `--co` and the full flags): with them a runner lists,
   explains or names itself and runs no tests, and argparse-based runners take a long flag's prefix for the flag
   (vectors `reject-claim-tests-passed-co`, `-collect-only`, `-help`, `-h`, `-version`, `-V`, `-he`). A short-flag
   cluster such as `-qh` is not refused, so that `go test -short` stays a test command; 6.6 says what that leaves.

## 7. Grants

### 7.1 Shape

A grant says: this subject may send this intent, within these caveats, until this time. It is closed
(`schemas/grant.schema.json`). **[Tracekit]**

| Member | Value |
|---|---|
| `pcm_grant` | the integer `0` |
| `ts` | TS, when the signer signed it |
| `issuer` | `{"kind": "person" \| "agent", "id": string <= 256, "person"?: string <= 256, "run": ID, "tenant": ID, "approval_id"?: ID}`, closed. `tenant` is the issuing run's tenant. |
| `subject` | IDENTITY, who may use the grant |
| `intent` | SCHEMA_REF |
| `caveats` | at most 16 `{"field", "op", "value"}`; `field` at most 64, `^[a-z][a-z0-9_]*$`; `op` one of `==` `<=` `>=` `<` `>` `in` |
| `expires_at` | TS |
| `delegable` | boolean: may the subject pass it on, only narrower |
| `parent` | `null` for a root grant, else `H(parent grant)`, the hash of the full signed parent including its `sig` |
| `sig` | as in 4.3, with TAG `pcm.grant.v0` |

The root grant of `accept-approved-by`, signed by a Tracekit signer after alice approved it:

```json
{"pcm_grant": 0, "ts": "2026-10-27T14:11:57.591727Z",
 "issuer": {"kind": "person", "id": "uid:990001", "run": "bb650aec66cc29fb4ee0de297fd3392f", "tenant": "default",
            "approval_id": "apr-f64cebe370aa43f2c14051fa70226929", "person": "alice"},
 "subject": "uid:990101",
 "intent": "refund.request@sha256:d8636b6fbbd07430d057ea9ead9c27f0df1b918b10d34ab9257a4971d487846c",
 "caveats": [{"field": "amount", "op": "<=", "value": 20000}, {"field": "order", "op": "==", "value": 81}],
 "expires_at": "2026-10-27T15:11:57.589997Z", "delegable": false, "parent": null,
 "sig": {"key": "example.com/pcm-test-log+0bb91e66",
         "sig": "p1Ce1ce1N/4FwzNPBTRB8/TQ45mjQHqYZRpYcZc9qtFGwyYQrpt4YpX9ZEO+4q7zbpCFb5lAcLkAhXwaGhh8Bg=="}}
```

### 7.2 Caveats

A caveat is valid for an intent when its field exists in the intent's schema document, its operator suits the field
type, and every value passes the field's rule (5.2):

| Field type | Operators |
|---|---|
| `int`, `money` | `==` `<=` `>=` `<` `>` |
| `time` | `==` `<=` `>=` |
| `string`, `id`, `enum` | `==`, `in` (1 to 64 distinct values) |
| `bool` | `==` |

Real checks from Tracekit against `refund.request`:

```
amount in [1, 2]: in does not apply to a money field
note == "x": no field note in refund.request
amount <= 20000.0: not a valid money value
```

For comparison, each caveat is rewritten as one of `== v`, `in S`, `<= b`, `>= b`: `< b` (an integer) becomes
`<= b-1`, and `> b` becomes `>= b+1`.

**Args satisfy a caveat** when the field is present in `intent.args` and the single-value caveat `== args[field]`
implies the caveat by the table in 7.3. So types must match exactly: `true` does not pass `<= 5`, and `"81"` does not
pass `== 81`. A missing field never passes.

### 7.3 Narrowing: a child is only narrower

A child grant's caveats narrow its parent's when **every parent caveat is implied by at least one child caveat on the
same field**. The child MAY add caveats on any field. A missing caveat counts as widening.

Child caveat `c` implies parent caveat `p` when:

| Parent `p` | `c` is `== v` | `c` is `in T` | `c` is `<= b'` | `c` is `>= b'` |
|---|---|---|---|---|
| `== x` | `v == x` and same JSON type | `T == {x}` (strings only, as `in` is) | never | never |
| `in S` | `v` is a string in `S` | `T ⊆ S` | never | never |
| `<= b` | same type and `v <= b` | never | same type and `b' <= b` | never |
| `>= b` | same type and `v >= b` | never | never | same type and `b' >= b` |

Consequences, each checked by Tracekit (`pcm.narrows`; parent `amount <= 20000, order == 81`):

| Child | Result |
|---|---|
| `amount <= 15000, order == 81` | narrows |
| `amount < 20001, order == 81` | narrows (`<` is `<=` one lower; vector `accept-delegation-less-than`) |
| `amount <= 15000` | `order == 81: dropped or widened` (missing counts as widening) |
| `amount <= 30000, amount >= 100, order == 81` | `amount <= 20000: dropped or widened` (widen and tighten fails) |
| `amount <= 20000, order >= 81, order <= 81` | `order == 81: dropped or widened` (bounds never imply an equality) |
| parent `k in ["a","b"]`, child `k in ["a","b","c"]` | `k in ["a", "b"]: dropped or widened` |

Also: the intent is fixed (a child is for its parent's intent), and expiry only shrinks (a child's `expires_at` is
no later than its parent's).

### 7.4 Root grants come from a person

A caveat-free grant is the widest grant. So a root grant (`parent: null`) MUST come from a person's approval. A
signer MUST refuse to issue a root grant unless all of these hold **[Tracekit]** (`pcm_grant`):

- the signer has an approvals configuration that names who may answer, so an answer comes from a named person;
- the agent made a tool call `pcm.grant` whose args are exactly the grant's `subject`, `intent`, `caveats`,
  `expires_at` and `delegable`, and that call was approved and the approval consumed with exactly these args;
- the approver is a person, not an agent approver; not the run's own agent (self-approved); not the grant's subject;
- `expires_at` is after now and at most 24 hours from now;
- the `pcm.grant` call has no result yet (one grant per approval: section 14.8);
- the run is not held or quarantined.

The grant's `issuer` is `{"kind": "person", "id": <approver identity>, "person"?: <the name the approvals
configuration gives>, "run", "tenant", "approval_id"}`. A policy that does not ask a person about `pcm.grant` leaves
nothing to consume, so no root grant can be made (fail closed). No policy pack shipped with Tracekit has this rule;
the rule `docs/pcm.md` shows is:

```yaml
tools:
  pcm.grant: app
ask:
  - {id: PCM-GRANT, tool: pcm.grant, pattern: "^"}
```

The signer SHOULD record each grant it signs as a record in the issuing run, as it does for messages (4.4): Tracekit
writes `ext` with `name: pcm.grant`, holding the grant's hash, subject and intent, and the approval id (a root) or the
parent's hash (a child).

### 7.5 Delegation

`delegable` is the approving person's choice: they see it in the args they approve. The subject of a delegable grant
MAY ask the signer for a child. A signer MUST refuse a child unless **[Tracekit]** (`pcm_delegate`):

- the parent verifies under this signer's own log key;
- the parent's `issuer.tenant` is the caller's tenant (no cross-tenant delegation);
- the caller is the parent's `subject`;
- the parent is `delegable`;
- the parent has not expired, and the child's `expires_at` is no later than the parent's;
- the child's caveats narrow the parent's (7.3).

The child gets `issuer: {"kind": "agent", "id": <the caller>, "run", "tenant"}`, the parent's `intent`, `parent:
H(parent)` and its own `delegable`. A child needs no approval, since it only narrows.

### 7.6 Chain rules

`grants` is the chain, root first. A verifier checks it against the intent's schema document. Each failing rule adds
one problem; any problem makes the grants result `failed`. **[Tracekit]** (`pcm.verify_grants`.)

| Rule | Check | Vectors (`reject-` left out) |
|---|---|---|
| needed | no grants: result `none`, or `failed` ("the intent needs a grant") when the document has `grant: true` | `grant-needed` |
| signature | every grant's `sig.key` equals the message's `sig.key` ("signed by …, not the log that signed the message"), and the grant verifies (4.3) with TAG `pcm.grant.v0` under that pinned key (14.18) | `grant-tampered`, `grant-unpinned-key`, `grant-from-another-log` |
| intent | every grant's `intent` equals `intent.type` | `grant-other-intent` |
| caveats | every grant's caveats are valid for the intent's document (7.2) | `grant-bad-caveat` |
| expiry | the message's `ts` is not after any grant's `expires_at` | `grant-expired` |
| tenant | every grant's `issuer.tenant` equals `from.tenant` | `grant-cross-tenant` |
| args | `intent.args` satisfies every caveat of every grant, not only the last | `grant-amount-over-caveat`, `delegation-over-child-cap` |
| root | grant 0 has `parent: null`, `issuer.kind == "person"`, and `issuer.id != subject` | `grant-root-by-agent`, `grant-issuer-is-subject` |
| link | each later grant's `parent` is `H(the grant before it)` | `grant-broken-parent` |
| delegable | the grant before each later grant is `delegable` | `grant-below-non-delegable` |
| who delegates | each later grant's issuer is `{"kind": "agent", "id": <the previous grant's subject>}` | `grant-child-wrong-issuer` |
| expiry shrinks | each later grant's `expires_at` is no later than the previous grant's | `grant-child-outlives-parent` |
| narrows | each later grant's caveats narrow the previous grant's (7.3) | `grant-widening-child`, `grant-widen-and-tighten-child`, `grant-missing-caveat-child` |
| subject | the last grant's `subject` equals `from.agent` | `grant-subject-not-sender` |

The result is `{"result": "none" | "ok" | "failed", "steps": <number of grants>, "root": <grant 0's issuer kind, id
and person> or null, "problems": [...]}`. A real problem from the demo, a $500 refund under a $200 grant:
`grant 0: amount 50000 breaks amount <= 20000`.

The verifier reports the root issuer but does not decide whether the receiver trusts that person. A receiver SHOULD
check `grants.root` against the people it accepts.

## 8. Verification algorithm

Inputs: the message (parsed as in 3.3), the trust anchors (section 10), the schema documents the receiver agreed on,
and optionally the receiver's replay state, the receiver's own identity `me`, the flag `strict`, and the time `now`.

Output **[Tracekit]** (`pcm.verify`):

```json
{"verdict": "accept" | "accept-unproven" | "reject",
 "signature": {"ok": bool, "key": string} | null,
 "replay": {"ok": true | false | null, "detail": string} | null,
 "schema": {"ok": bool, "ref": string, "errors": [string]} | null,
 "grants": <7.6 result> | null,
 "claims": [{"type", "result", "detail"}] | null,
 "reasons": [string]}
```

Steps, in this order:

1. **Envelope.** The message MUST match section 3.2. If not: `reject`, every other part `null`, reasons
   `envelope: …` (Tracekit lists up to 8). Stop.
2. **Signature.** Verify `sig` as in 4.2 and 4.3 with TAG `pcm.message.v0`. If it fails: `reject`, `signature.ok`
   false, the later parts `null`. Stop. No claim work is done for a forged message.
3. **Replay and recipient.** If replay state is given, check it (section 9) and record the message. Then, if `me` is
   given and `to.agent != me`, the replay part fails with "addressed to <to.agent>, not <me>". With neither:
   `{"ok": null, "detail": "not checked"}`.
4. **Schema.** Check every given schema document (5.2; a bad one is a configuration error). Find the document whose
   reference equals `intent.type`, and check the args (5.3).
5. **Grants.** If the document was found, check the chain (7.6). Else `grants` is `null`.
6. **Claims.** For each claim in order: check its args and whether it is malformed (6.1), which fails it with or
   without evidence; then, if it has evidence, the evidence (6.2) and its checker (6.6). No evidence: `unproven`
   ("no evidence").
7. **Verdict.**
   - **`reject`** when any of: replay `ok` is `false`; the schema check has errors; the grants result is `failed`; a
     claim is `failed`; or `strict` is set and a claim type the document lists under `claims` has no `proven` claim.
   - Else **`accept-unproven`** when a claim is `unproven`, or a claim type the document lists has no `proven` claim.
   - Else **`accept`**.

   `reasons` holds one line per cause, in this order: replay, schema errors, grant problems, failed claims, then (for
   `strict`) missing required claims; for `accept-unproven`, the unproven claims, then missing required claims.

A receiver MUST NOT act on a `reject`. It SHOULD treat `accept-unproven` as "the sender says so": what is unproven
rests on the agent's word alone.

The expected result of `accept-approved-by` (receiver `uid:990102`, a fresh replay state, 300 s window):

```json
{"signature": {"ok": true, "key": "example.com/pcm-test-log+0bb91e66"},
 "replay": {"ok": true, "detail": "fresh"},
 "schema": {"ok": true, "ref": "refund.request@sha256:d8636b6fbbd07430d057ea9ead9c27f0df1b918b10d34ab9257a4971d487846c", "errors": []},
 "grants": {"result": "ok", "steps": 1, "root": {"kind": "person", "id": "uid:990001", "person": "alice"}, "problems": []},
 "claims": [{"type": "approved_by", "result": "proven", "detail": "approval seq 5 by alice of grant-1"}],
 "verdict": "accept", "reasons": []}
```

Each step stops a different vector: the envelope `reject-envelope-pcm-false` ("envelope: $.pcm: expected integer,
got bool"), the signature `reject-forged-signature` and `reject-unpinned-key`, replay `reject-replay-duplicate-nonce`,
the recipient `reject-wrong-recipient`, the schema `reject-schema-bool-as-int`, the grants
`reject-grant-amount-over-caveat`, a claim `reject-claim-changed-record-hash`, and `strict`
`reject-strict-required-unproven`.

And the whole refund demo, as `tracekit pcm demo` prints it (a separate run):

```text
alice approves agent A's grant: refund.request, amount <= $200.00, order == 81, until 18:00Z, can be passed on: no
A -> B  refund.request {amount $120.00, order 81} + approved_by(alice)
    B: ACCEPT           signature ok · replay ok · schema ok · grant ok (alice, 1 step) · approved_by proven
A -> B  same request + tests_passed(pytest tests/test_refund.py), no evidence
    B: ACCEPT-UNPROVEN  tests_passed: unproven (no evidence)
A -> B  approved_by with one record hash changed
    B: REJECT           approved_by: failed (record 1: hash does not match the event)
A -> B  refund.request {amount $500.00, order 81} + approved_by(alice)
    B: REJECT           grant: grant 0: amount 50000 breaks amount <= 20000
A asks the signer to sign as B
    signer: forbidden: the signer signs only as the calling run's own agent (uid:990101, run 682b33a74fb7e277f59f38d40404dcae, tenant default)
```

## 9. Replay and recipient checks

Replay state is per receiver. A receiver keeps one replay state for its whole life and passes every message through
it. **[Tracekit]** (`pcm.Replay`.) Parameters: `window_s` (default 300 seconds; `null` for an auditor reading a saved
conversation), `per_sender` (default 4096), and `started`, the time the state was created.

**The sender (decided, 0.1).** A sender is the pair (`sig.key`, `from.agent`), never `from.agent` alone. Rationale:
an identity is a name inside one signer, so `uid:990101` of one log and `uid:990101` of another are two senders, and
one must not raise the other's floor or spend its nonces. **[Tracekit]** (vector
`accept-replay-same-agent-other-log`: a message of the other log with the same agent name and the same nonce was seen
first, and this one still passes.)

For a message whose signature passed, with `t = ts` and `sender = (sig.key, from.agent)`:

1. If `ts` names no real time (3.2): refuse ("which is no real time").
2. If `window_s` is set: refuse when `|now − t| > window_s` ("more than … s from this receiver's clock"); refuse when
   `t < started` ("sent before this receiver started: ask for it again").
3. Refuse when `t <= floor[sender]` ("older than the messages this receiver remembers from the sender").
4. Refuse when `nonce` is in `seen[sender]` ("replayed: this nonce was seen before").
5. Else append `(nonce, t)` to `seen[sender]`. Entries stay in the order the messages arrived, not in `ts` order.
   If `window_s` is set: while the first entry's `t` is older than `now − window_s`, remove it (the window refuses it
   anyway); stop at the first entry that is not. Then, while `seen[sender]` has more than `per_sender` entries,
   remove the first and set `floor[sender]` to the larger of the floor and its `t`.

The order matters. With `per_sender` 1 and no window, a receiver that takes the messages signed at :05 and then :01
removes :05 and sets the floor to :05, so it then refuses one signed at :03. A receiver that removed the smallest
`ts` would accept it. Vector `reject-replay-floor-arrival-order` pins this.

Refusing messages signed before the receiver started is what lets a receiver restart with no saved state. The sender
asks again.

A receiver that acts on a message MUST check it with its replay state. Grant expiry is judged at the message's `ts`
(7.6), not at the receiver's clock, so without replay state a message captured while its grant was valid stays
`accept` forever. Verifying without replay state (Tracekit's `tracekit pcm verify` and the standalone CLI do) is for
audit only and MUST NOT lead to action.

**One acceptance per receiver (decided, 0.1).** A receiver MUST accept each (sender, `nonce`) at most once within
its window, per receiver identity (`me`), across every replica or process that answers for that identity. How
replicas share the state (one store, a database, routing each sender to one replica) is implementation-defined.
Rationale: a replica that keeps its own state takes a message another replica already took, so a captured message
could be acted on once per replica. Tracekit's `pcm.Replay` is per process (a `lean:` limit in its code): a deployment
with more than one replica per identity must share it or route each sender to one replica (14.14).

The recipient check: a receiver MUST pass its own identity as `me`. A message addressed to another fails ("addressed
to uid:990102, not uid:990103"). In Tracekit the replay state records the message before the recipient check runs.

Signer and receiver clocks MUST agree within the window (use NTP).

## 10. Trust anchors

### 10.1 trust.json

A receiver pins keys in a trust document:

```json
{"logs": ["example.com/pcm-test-log+0bb91e66+ASiESUZlr4+aYnGbR8MnqhEfMelvE25+EAPkEwgpZl6C"],
 "witnesses": [],
 "witnesses_required": 0}
```

| Member | Required | Value |
|---|---|---|
| `logs` | yes | one or more log vkeys (4.3). They verify messages, grants and evidence checkpoints. |
| `witnesses` | no | witness keys, each `{"name", "vkey"}`, the vkey of type 0x04 (C2SP tlog-cosignature). Default none. |
| `witnesses_required` | no | how many pinned witness cosignatures each evidence checkpoint needs. Default 0. |

A verifier MUST ignore members it does not know, so a Tracekit `trust.json` (which also has `algs`, `rekor`,
`monitors`, and witnesses as `{"vkey", "class"}`) works as it is. A verifier reads only each witness's `vkey`; the key
name inside the vkey is the one that counts. **[Tracekit]**

A trust document with any vkey in `logs` or `witnesses` that does not parse as 4.3 says (a malformed vkey, a key id
that does not match, non-canonical base64) is a configuration error. The verifier MUST report it before it checks
any message, as for a bad schema document (5.2), wherever the vkey sits in the list. Rationale: otherwise a bad vkey
listed before the key that verifies a message stops the check, and one listed after it fails only the evidence, so
the result would depend on the order of the list. **[Tracekit]**

A trust document MUST NOT pin keys of two different logs under one name. Keys that share a name are one log's
rotations. The evidence check compares log names (6.2 step 2), and a note is accepted when any pinned Ed25519 key of
its origin's name signs it, so two logs under one name would let one log's evidence pass for the other's (14.1).
Tracekit names a log `tracekit.local/<log id>` by default, which is unique, but an operator can choose any origin.

A log may also pin a hybrid key: a vkey of type 0xff whose key bytes are the ASCII text `tracekit/slh-dsa-sha2-128s`
followed by the 32-byte SLH-DSA-SHA2-128s public key [FIPS205], under the log's own name. When trust pins one, every
evidence checkpoint of that origin needs a valid SLH-DSA line from it too (its signature is over the note text, as
the Ed25519 line's). Messages and grants stay Ed25519 only (4.3). **[Tracekit]** (`checkpoint.open_note`.) A verifier
that does not implement SLH-DSA MUST fail evidence whose origin has a pinned hybrid key, and evidence whose note
carries a line of any pinned hybrid key. The standalone verifier does so.

### 10.2 The tool placement table

The verifier places tools with a fixed table, `{tool name: class}`. It MUST ship the table itself, or take it from its
operator. It MUST NOT take it from a message, a bundle or a sender. The reference table is `registry/tools.json`,
generated from Tracekit's `tracekit.pcm.claims.placed()`: the tool names the policy packs shipped with Tracekit map,
leaving out patterns and names two packs class differently. For example `Bash`, `bash`, `shell` and `container.exec`
are `shell`; `WebFetch`, `fetch` and `http_get` are `http`. A tool not in the table is unplaced. **[Tracekit]** The
standalone verifier ships a copy of the reference table and uses it unless its operator passes another.

## 11. Transport bindings

PCM authenticity does not depend on the transport. Confidentiality does: use TLS. Each binding carries the message
JSON unchanged. All three bindings are **[Draft]**: Tracekit's receivers call `pcm.verify` themselves today.

### 11.1 A2A

In an A2A [A2A] message, a PCM message is one part whose media type is `application/vnd.pcm+json` and whose data is
the PCM message object. A gateway or receiver that understands PCM verifies each such part before it forwards or acts
on it, and drops a part that is rejected. Other parts of the same A2A message are not covered by the PCM signature;
put what must be covered in `payload`.

### 11.2 MCP

In MCP [MCP], a PCM message travels as an embedded resource in a tool call's result content, or in a tool call's
arguments where the tool's input schema names it, with `mimeType` `application/vnd.pcm+json` and the message JSON as
its `text`. The MCP server or client that receives it verifies it before it acts.

### 11.3 HTTP

The request body is the message JSON with `Content-Type: application/vnd.pcm+json` [RFC9110]. A receiver that rejects
the message MUST NOT act on it. It MAY return the verification result as its response body.

## 12. The transfer-record extension (C2C latent transfers)

**[Draft]** This extension waits for Tracekit issue #434 (the A2A gateway and C2C transfer records), built in PR #445,
open as of this draft. Until it merges, it is DRAFT: no verifier implements it, and a PCM 0.1 verifier rejects a
`transfer` payload
at the envelope, because `payload` is closed to `text` and `data`. That is fail-closed by design.

### 12.1 The problem

Some agents exchange model state instead of text: one model's KV cache fused into another's through a projector
(Cache-to-Cache, C2C). The bytes are large, opaque and not meant to be read. A receiver still needs to know who sent
which bytes, through which adapter, and that the sender's signer allowed it before it happened.

### 12.2 The transfer record (from issue #434, PR #445)

Before a transfer, the sender's code calls `RunHandle.transfer` with the payload bytes, the sender and receiver model
ids, the modality and an optional projector, and two options: `measured` (more fields the caller computed) and
`keep`. The signer decides it as the tool `a2a:transfer` and records a `policy.decision` whose committed args are:

```json
{"sender": "qwen-7b@1", "receiver": "llama-1b@2", "modality": "kv-cache", "projector": "c2c@0.1",
 "claimed": ["modality", "projector", "receiver", "sender"],
 "size": 5, "digest": "sha256:<hex of SHA-256 of the payload bytes>",
 "measured": ["digest", "size"]}
```

- `sender`, `receiver`: model ids with their version (`name@version`); `projector`: the adapter id and version,
  optional; `modality`: `kv-cache`, `embedding`, `activations`, or another the code names.
- `size` and `digest` are computed from the bytes by the sender's own process; `claimed` and `measured` list which
  fields the caller stated and which it computed. More measured fields MAY appear (C2C adds the fuser's weights hash
  and layer map). All of them come from the agent's process (T1): the signer takes none of them on trust.
- The record never holds the payload.

### 12.3 The transfer payload

```json
{"kind": "transfer", "evidence": {"checkpoint": "...", "records": [ ... ]}}
```

`evidence` is an evidence item (6.2). A verifier that implements this extension checks, after step 6 of section 8:

1. The evidence verifies as in 6.2, against the sender's run.
2. Exactly one record has an opening, and it is a `policy.decision` with `data.tool == "a2a:transfer"`.
3. The decision is `allow`, or `ask` with an `approval` record in the same evidence that approves its
   `data.tool_use_id` (`data.decision == "approve"`).
4. The opened args have `sender`, `receiver`, `modality`, `size` (integer) and `digest` (DIGEST).

If any check fails, the verdict is `reject`. The verifier reports the opened `sender`, `receiver`, `projector`,
`modality`, `size` and `digest`. The receiver MUST then compare the bytes it actually received (out of band) with
`size` and `digest`, and MUST NOT use them if they differ.

What it proves: before the transfer, the sender's signer recorded and allowed a transfer that the sender declared
with this size and digest, between these named models. Once the receiver has compared the bytes, it knows the bytes it
got are the bytes the sender declared to its signer. What it does not prove: every field, `size` and `digest`
included, is the sender process's word (T1). The record does not show what the state means, or that the named models
are the ones that ran.

## 13. Conformance levels and test vectors

### 13.1 Levels

- **Level 1**: envelope (3), signature (4), schema (5), grants (7), replay and recipient (9), the verdict (8), and
  claim args with the malformed-claim rules (6.1: a `tests_passed` suite that is no test command, 6.8, and a
  `file_written` path that is relative or has a `..` segment, 6.6, are `failed`). After that check, a Level 1
  verifier MUST give every claim that has evidence the result
  `unproven` ("evidence not checked"). It never gives `proven`.
- **Level 2**: Level 1, plus evidence (6.2, 6.3), the evidence profile (6.4) and the four claim checkers (6.5, 6.6).
- The transfer extension (12) is separate and DRAFT.

Tracekit's `pcm.verify` is a Level 2 verifier, and so is the standalone verifier in `verifier/python`.

### 13.2 Test vectors

The vectors are in `vectors/`, produced by Tracekit's `tracekit.pcm.verify`. `vectors/index.json` is a JSON list of
`{"name", "file", "description", "verdict"}`. Each `vectors/<name>.json` is:

```json
{"name": "...", "description": "...",
 "input": {
   "message": { "...": "the PCM message" },
   "schemas": [ "...schema documents..." ],
   "trust": {"logs": ["<vkey>"], "witnesses": [{"name": "...", "vkey": "..."}], "witnesses_required": 0},
   "tools": {"Bash": "shell", "WebFetch": "http"},
   "options": {"me": "uid:990102", "strict": false, "now": "YYYY-MM-DDTHH:MM:SS.ffffffZ",
               "replay": null}},
 "expected": {"verdict": "...", "signature": {}, "replay": {}, "schema": {}, "grants": {}, "claims": [],
              "reasons": []}}
```

- `tools` is the tool placement table the verifier uses for this vector: `registry/tools.json` when the vectors were
  made. (Tracekit's `pcm.verify` uses its own `claims.placed()`, which the generator checks is equal.)
- `options.replay` is `null` (no replay state) or `{"window_s": seconds or null, "started": TS, "per_sender": n,
  "seen": [earlier messages]}`. The verifier creates one replay state with these parameters and verifies each message
  of `seen` in order with it (same trust, schemas, `me`, `strict` and `now`; their results are ignored, and one whose
  signature fails is not recorded), then verifies `message`. `now` is the receiver's clock for all of them.
- `expected` is the full result Tracekit returned for that input.

**Conformance rule.** A verifier conforms on a vector when its `verdict`, `signature.ok`, `replay.ok`, `schema.ok`,
`grants.result` and every `claims[i].result` equal the expected ones (a part that is `null` in `expected` must be
absent or `null`). The `detail`, `reasons` and `problems` strings are for people, not compared.

A vector is a Level 2 vector when any claim of its message carries `evidence`; otherwise it is a Level 1 vector. A
verifier conforms to a level when it conforms on every vector of that level.

## 14. Security considerations

Each item below is an attack or a mistake found while building or reviewing the reference implementation, with the
rule that closes it.

1. **Cross-log evidence replay.** An agent on another signer reused a victim's run id and tenant, then replayed the
   victim's evidence in its own messages. Run ids are chosen by clients and are unique only per log. **Rule:** the
   evidence checkpoint's origin MUST equal the log name of the key that signed the message (6.2 step 2), and a trust
   document MUST NOT pin two logs under one name (10.1). Vector: `reject-claim-evidence-from-another-log`, where trust
   pins both logs. Grants and replay state have the same problem: 14.18.
2. **T1 is not proof.** A tool result the agent's own process reported is its own word. **Rule:** only a T2 result
   (an attesting gateway or executor recorded it) or a signer-side record (a person's approval, an observer's effect)
   proves a claim; T1 gives `unproven`, never `proven`. The T2 mark MUST be read from the record's own attested fields
   (top-level `source` and `tier`), never from `data` or anything the agent wrote (6.4, 6.5). Vectors:
   `accept-tests-passed-t2`, `accept-unproven-t1-result`.
3. **Tool placement.** An agent called a harmless tool with a `command` or `url` member to look like a shell or http
   call. **Rule:** the verifier places tools with a fixed table (10.2); an args member never places a tool; an
   unplaced tool gives `unproven`. Vector: `accept-unproven-unplaced-tool`.
4. **Tenant binding.** A grant issued in one tenant must not authorise a run in another. **Rule:** grants carry the
   issuer's tenant; a chain with a grant whose tenant differs from `from.tenant` is rejected (7.6); the signer MUST
   refuse cross-tenant delegation (7.5). Vector: `reject-grant-cross-tenant`.
5. **Key reuse.** The log key signs checkpoints and also PCM messages and grants. **Rule:** domain separation by the
   `t` tag. The tags `pcm.message.v0` and `pcm.grant.v0` differ from every other purpose the key or the signer signs
   (Tracekit's own tags are `tracekit.<purpose>.v2`), and the signed bytes are a JCS object, which starts with `{` and
   holds no raw line break, so they can never parse as a checkpoint note's text. A signer SHOULD use a dedicated PCM
   key and MAY use its log key (4.5); one that uses its log key turns a bug in PCM signing into rotating the log key.
   Vector: `reject-grant-signature-as-message`.
6. **Person-rooted grants.** A caveat-free grant is the widest grant. **Rule:** a root grant MUST come from a person's
   approval, never an agent approver's, never self-approved, never by the grant's subject; the signer MUST require an
   approvals configuration (7.4). The verifier MUST reject a root whose issuer kind is not `person`, or whose issuer
   is its subject (7.6). Vectors: `reject-grant-root-by-agent`, `reject-grant-issuer-is-subject`.
7. **Delegation.** **Rule:** `delegable` is set by the approving person. A non-delegable grant cannot be passed on, by
   the signer or in a chain a verifier accepts. Children only narrow (7.3): a missing caveat is widening; widening one
   caveat while tightening another fails; an equality is narrowed only by the same equality; enum sets shrink only by
   subset; expiry only shrinks; the intent is fixed. Vectors: `accept-delegation-narrowing`,
   `accept-delegation-less-than`, `reject-delegation-over-child-cap`, `reject-grant-below-non-delegable`,
   `reject-grant-widening-child`, `reject-grant-widen-and-tighten-child`, `reject-grant-missing-caveat-child`,
   `reject-grant-broken-parent`, `reject-grant-child-outlives-parent`, `reject-grant-child-wrong-issuer`.
8. **One grant per approval.** **Rule:** the signer MUST refuse a second root grant once the `pcm.grant` call has its
   result. Tracekit honours this after the call completes; until then, repeated `pcm_grant` calls on the same consumed
   approval can mint grants that differ only in `ts` (a documented `lean:` limit). Its SDK completes the call at once.
9. **Held runs.** **Rule:** a held or quarantined run MUST NOT get new messages or grants signed: no new outward
   authority while a person looks at it. Reading evidence stays allowed.
10. **`tests_passed` on a compound command.** `pytest || true` and `pytest &` exit 0 whether the tests pass or not.
    **Rule:** `suite` MUST be one line of plain words (no operator, redirection, expansion, escape, comment, brace or
    glob character) beginning with a runner from a fixed list by its bare name (6.8); anything else fails, and so does
    a runner with a flag that runs no tests (`--co`, `--help`, `-V`, `--he`, …). Vectors:
    `reject-claim-pytest-or-true`, run by the executor (T2) and still `failed`, `reject-claim-bash-c`,
    `reject-claim-tests-passed-background`, `reject-claim-tests-passed-dot-slash`, `reject-claim-tests-passed-co` and
    the other flags. A `#` inside a word, and `$'…'` quoting, once hid a second command from this rule: 14.19. Even
    so, a listed runner can be told to run no tests by flags and files the list can't see (6.6 "What `proven`
    means"): a receiver compares `suite` with the suites it accepts.
11. **`file_written`.** **Rule:** only write tools count (by tool name, not by an `op` in the args), only with the full
    content, checked by its SHA-256 digest; a claim path with `..` fails, and so does a relative one, with or without
    evidence; a `Write` of a relative path is `unproven`, never `proven` (6.6). Vectors: `accept-file-written`,
    `reject-claim-file-written-wrong-digest`, `reject-claim-file-written-dotdot`, `reject-claim-file-written-relative`,
    `reject-claim-file-written-relative-no-evidence`, `accept-unproven-file-written-relative-call`.
12. **Hostile input.** A pinned log can be hostile, and a caller can pass any object. **Rule:** a verifier MUST NOT
    crash on hostile input: args that are not an object, wrong JSON types, invalid or non-canonical base64, non-ASCII
    proof entries, events that are not objects or not valid events of the profile, records without a field a checker
    reads, a `ts` that is no real time, values nested deeper than the recursion limit where an error message would
    show them (an error names a deep list or object by its type, never by its text). Each is a `failed` claim or a
    `reject`; `verify` returns a verdict and never raises for a message. Integer `const` checks MUST reject `false`
    and `0.0`. Envelope and claim-arg patterns MUST match the whole value and use ASCII classes (`[0-9]`, not Unicode
    digits); a schema's own `id` patterns run in Python's Unicode mode (5.2). Public keys MUST be checked as in 4.3.
    Vectors: `reject-envelope-pcm-false`, `reject-envelope-extra-field`, `reject-schema-bool-as-int`,
    `reject-schema-int-as-string`, `reject-schema-field-types`, `reject-claim-reached-host-too-long`,
    `reject-small-order-key`, `accept-jcs-payload`, `reject-sig-non-canonical-base64`,
    `reject-claim-proof-non-canonical-base64`, `reject-claim-record-not-an-event`, `reject-claim-decision-without-id`,
    `reject-replay-no-real-time`. Non-object args, non-object events and deep values are covered by the standalone
    verifier's tests, not by vectors: a signer never makes them, and a value past the recursion limit is no portable
    JSON.
13. **Evidence is not freshness.** Evidence proves a call happened in the sender's run, not that it is the latest
    state. Tests that passed at 10:00 prove nothing about code changed at 10:05. **Rule:** a receiver that needs
    freshness SHOULD read the record's `ts` and ask for a fresh claim; a sender SHOULD claim right after the call.
14. **Replay.** **Rule:** replay state is per receiver: nonce, plus the time window, plus a per-sender floor raised by
    eviction (section 9). Messages signed before the receiver started are refused. A message replayed to another
    replica of the same receiver must not pass there: each (sender, nonce) is accepted at most once per receiver
    identity across all its replicas, by state they share or by routing each sender to one replica (section 9). A
    sender is (log key, agent). Vectors: `reject-replay-duplicate-nonce`, `reject-replay-outside-window`,
    `reject-replay-before-started`, `reject-replay-floor-arrival-order`, `accept-replay-same-agent-other-log`,
    `reject-wrong-recipient`.
15. **Schema trust.** The content hash pins what a schema says, not who wrote it. `id` patterns are regular
    expressions the receiver runs, so a hostile pattern can be slow (ReDoS). **Rule:** a receiver MUST only load
    schema documents it chose, ship them with the code that uses them, and review their patterns like code.
16. **Openings disclose args.** With a decision's commitment, its salt lets anyone brute-force low-entropy args.
    **Rule:** the signer hands out salts only to the run's own agent, for the records it names (`pcm_evidence`). A
    sender MUST NOT send a salt for a decision it does not open, and opens only the decisions it chooses to show. (A
    verifier also fails a record that has one of `salt` and `args` without the other: vector
    `reject-claim-salt-without-args`.) See section 15.
17. **No revocation.** PCM 0.1 has no revocation: a grant holds until `expires_at`. **Rule:** the signer MUST cap a
    grant's lifetime (24 hours in Tracekit); a verifier checks expiry against the signer-set message `ts`, not the
    receiver's clock, so a later audit reaches the same answer. So a receiver that acts MUST also check replay
    (section 9): else a captured message stays `accept` after its grant expired. Grant per task, not per agent.
    Vector: `reject-grant-expired`.
18. **Cross-log grant replay.** Identities and tenants are names inside one signer: the default tenant is `default`
    everywhere, and `uid:990101` on one host is not `uid:990101` on another. When a grant was checked under any pinned
    log key, a grant signed by log X could ride in a message signed by log Y, sent by an agent on Y whose identity
    string is the grant's subject; anyone who saw the grant could hand it on. **Rule:** every grant in a chain MUST be
    signed by the key that signed the message (7.6), and a sender is the pair (`sig.key`, `from.agent`), never
    `from.agent` alone (section 9, decided 0.1). `pcm_delegate` takes only its own signer's grants (7.5). Vectors:
    `reject-grant-from-another-log` (trust pins both logs), `accept-replay-same-agent-other-log`.
19. **A word splitter that reads apart from the shell.** A splitter that reads every `#` outside quotes as a comment
    reads `pytest -q tests/x.py#|| true` as the one command `pytest -q tests/x.py`, while the executor's shell runs
    `pytest -q tests/x.py#`, then `|| true`. Python's `shlex` has no `$'…'` quoting: it reads
    `pytest $'\'';true #'` as one command, which `sh` runs as `pytest "'"`, then `true`. Either way the call exits 0
    whether the tests passed or not, and an earlier draft proved `tests_passed` for it. **Rule:** a suite holds none
    of the characters on which a shell and a word splitter can differ: no `#`, `$`, backquote, backslash, operator,
    brace or glob character, and balanced quotes (6.8 step 1). Vectors: `reject-claim-hash-inside-word`,
    `reject-claim-tests-passed-ansi-c-quote`, `reject-claim-tests-passed-comment`,
    `reject-claim-tests-passed-unbalanced-quote`.
20. **Host spellings.** A host has many spellings, and two readers of one URL can disagree on its host
    (`http://a.example\@b.example/`; `faß.example` is `fass.example` to IDNA 2003 and `xn--fa-hia.example` to a
    browser). **Rule:** hosts are compared in one canonical form, and a host that won't parse, that two readers read
    apart or that holds a deviation character gives `unproven`, never `proven`; a URL of a scheme without a host
    reaches none (6.7). Vectors: the `reached-host` vectors of 6.6.
21. **Signature malleability.** With lenient base64, one signature had several texts that verified, so a grant's
    text, and its hash in a child's `parent`, could change without a new signature. **Rule:** canonical base64 only
    (4.3). Vectors: `reject-sig-non-canonical-base64`, `reject-claim-proof-non-canonical-base64`.
22. **`approved_by` without a person.** Matched against the answering identity, the claim was `proven` by any
    identity of the tenant when the signer had no approvals configuration. **Rule:** it proves only a configured
    person (6.6). Vector: `reject-claim-approved-by-unmapped-identity`.
23. **A runner by its base name.** Compared by base name, the first word `/tmp/x/pytest` passed as `pytest`: the agent
    could write a file of that name that exits 0 and run it through the executor. **Rule:** the first word is
    compared exactly, so it is a bare name the executor's `PATH` resolves (6.8 step 2). The executor's `PATH` and
    working directory remain the deployment's to keep out of the agent's reach (6.6). Vectors:
    `reject-claim-tests-passed-dot-slash`, `reject-claim-tests-passed-runner-path`.

Also: PCM authenticates the signer, not the agent's intentions. A compromised agent can send any message its grants
allow. The receiver's own policy decides what to do with an `accept`.

## 15. Privacy considerations

- **What a receiver learns from a message:** the sender's identity, run id and tenant; the intent and its args; the
  payload; every grant in the chain, with the approving person's identity and name, approval ids and run ids.
- **What it learns from evidence:** the full records sent: their types, times, tool names, `tool_use_id`s, approver
  identities and names, policy outcomes, observed hosts, the log's id and its size at the checkpoint. Opened decisions
  disclose their args in clear.
- **What it does not learn:** records not sent, and args of decisions not opened. Commitments without a salt hide
  their args.

Minimisation: a sender SHOULD send only the records a claim needs, open only the decisions it would show the
receiver, and put nothing in `payload` it would not send in clear. Openings are permanent: a receiver can keep and
show them to others, and the signature on the message makes them attributable.

## 16. Versioning

- The envelope field `pcm` is `0` for every 0.x draft (this is PCM 0.1). `pcm_grant` and `pcm_schema` are `0` too.
- The signature tags `pcm.message.v0` and `pcm.grant.v0` name the signed-bytes format, and they are bound to the wire
  version: `"pcm": 0` is signed with `pcm.message.v0` and `pcm.grant.v0`, and only with them. The `t` tag changes
  only with a new wire version (`"pcm": 1` gets new tags), never within one, so a verifier knows the tag from the
  `pcm` value alone. A change to what is signed, or how, therefore needs a new wire version.
- 0.x drafts MAY change anything, including incompatibly. A verifier for one 0.x draft rejects what it does not know,
  because every object is closed.
- PCM 1.0 will use `"pcm": 1` and new tags. A verifier MUST reject a `pcm` value it does not implement.
- New claim types, new evidence profiles, new payload kinds and new transport bindings are added through the
  registries in section 17.

## 17. Registrations

The registries below are kept in this repository until PCM has a registration authority.

### 17.1 Media type

```
Type name: application
Subtype name: vnd.pcm+json
Required parameters: none
Optional parameters: none
Encoding considerations: binary; UTF-8 JSON text [RFC8259]
Security considerations: section 14 of this document
Interoperability considerations: section 13 of this document
Published specification: this document
Applications that use this media type: AI agents, agent gateways and verifiers exchanging proof-carrying messages
Fragment identifier considerations: as for application/json
Additional information: Magic number(s): none. File extension(s): none. Macintosh file type code(s): none
Person and email address to contact for further information: Cygnux Labs, through this repository
Intended usage: COMMON
Restrictions on usage: none
Author: Cygnux Labs
Change controller: Cygnux Labs
```

### 17.2 Claim types

| Name | Args | Defined in | Status |
|---|---|---|---|
| `tests_passed` | `suite` | 6.6 | [Tracekit] |
| `approved_by` | `person`, `call` | 6.6 | [Tracekit] |
| `reached_host` | `host` | 6.6 | [Tracekit] |
| `file_written` | `path`, `digest` | 6.6 | [Tracekit] |

A new claim type needs: its args in the schema language (5.2), an exact checker over a named evidence profile with
`proven`, `unproven` and `failed` rules, and test vectors for each result.

### 17.3 Signature tags

| Tag | Signs |
|---|---|
| `pcm.message.v0` | a PCM 0.x message |
| `pcm.grant.v0` | a PCM 0.x grant |

A new tag MUST differ from every tag the same key signs for any purpose, and comes only with a new wire version (16).

### 17.4 Tool classes

| Class | Meaning | Read by |
|---|---|---|
| `shell` | runs a shell command line | `tests_passed` |
| `http` | makes an HTTP request to a URL | `reached_host` |
| `fs` | reads or writes files | (`file_written` uses its own write-tool table: `Write`) |
| `payment` | moves money | none in 0.1 |
| `email` | sends email | none in 0.1 |
| `sql` | runs SQL | none in 0.1 |

The table from tool name to class is `registry/tools.json` (10.2).

### 17.5 Payload kinds

| Kind | Status |
|---|---|
| `text` | [Tracekit] |
| `data` | [Tracekit] |
| `transfer` | [Draft], section 12 |

### 17.6 Evidence profiles

| Name | Defined in | Status |
|---|---|---|
| `tracekit.event.v2` | 6.4 | [Tracekit] |

## 18. References

### 18.1 Normative

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, 1997.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, 2017.
- [RFC8785] Rundgren, A., Jordan, B., Erdtman, S., "JSON Canonicalization Scheme (JCS)", RFC 8785, 2020.
- [RFC8032] Josefsson, S., Liusvaara, I., "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, 2017.
- [RFC6962] Laurie, B., Langley, A., Kasper, E., "Certificate Transparency", RFC 6962, 2013.
- [RFC9162] Laurie, B., Messeri, E., Stradling, R., "Certificate Transparency Version 2.0", RFC 9162, 2021.
- [RFC2104] Krawczyk, H., Bellare, M., Canetti, R., "HMAC: Keyed-Hashing for Message Authentication", RFC 2104, 1997.
- [RFC4648] Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648, 2006.
- [RFC8259] Bray, T., "The JavaScript Object Notation (JSON) Data Interchange Format", RFC 8259, 2017.
- [RFC3490] Faltstrom, P., Hoffman, P., Costello, A., "Internationalizing Domain Names in Applications (IDNA)",
  RFC 3490, 2003.
- [RFC3491] Hoffman, P., Blanchet, M., "Nameprep: A Stringprep Profile for Internationalized Domain Names (IDN)",
  RFC 3491, 2003.
- [RFC3492] Costello, A., "Punycode: A Bootstring encoding of Unicode for Internationalized Domain Names in
  Applications (IDNA)", RFC 3492, 2003.
- [FIPS180-4] NIST, "Secure Hash Standard (SHS)", FIPS 180-4, 2015.
- [FIPS205] NIST, "Stateless Hash-Based Digital Signature Standard", FIPS 205, 2024.
- [C2SP-NOTE] C2SP, "signed-note", https://c2sp.org/signed-note
- [C2SP-CKPT] C2SP, "tlog-checkpoint", https://c2sp.org/tlog-checkpoint
- [C2SP-COSIG] C2SP, "tlog-cosignature", https://c2sp.org/tlog-cosignature

### 18.2 Informative

- [A2A] Agent2Agent (A2A) Protocol, https://a2a-protocol.org/
- [MCP] Model Context Protocol specification, https://modelcontextprotocol.io/specification
- [RFC9110] Fielding, R., Nottingham, M., Reschke, J., "HTTP Semantics", RFC 9110, 2022.
- [WHATWG-URL] WHATWG, "URL Standard", https://url.spec.whatwg.org/
- [UTS46] Unicode Technical Standard #46, "Unicode IDNA Compatibility Processing", https://www.unicode.org/reports/tr46/
- [RFC6838] Freed, N., Klensin, J., Hansen, T., "Media Type Specifications and Registration Procedures", RFC 6838, 2013.
- [Tracekit] Cygnux Labs, Tracekit, https://github.com/Cygnux-Labs/Tracekit (the reference implementation:
  `tracekit/pcm/`, `tracekit/signer/rpc_schema.py`, `tracekit/signer/service.py`, `docs/pcm.md`).
- [C2C] "Cache-to-Cache: Direct Semantic Communication Between Large Language Models", 2025 (the latent transfers
  of section 12).

## Appendix A. Where this document departs from Tracekit's docs and design

The code wins. These places differ from Tracekit's design notes at the time of writing. Tracekit's user docs
(`docs/pcm.md`, `docs/limits.md`) already match the code on each of them.

- **Signature tags.** The design says `tracekit.pcm.v2` and `tracekit.pcm-grant.v2`. The code (`format/sigmsg.py`
  `TAGS`) signs `pcm.message.v0` and `pcm.grant.v0`. This document follows the code.
- **Media type.** The design says `application/vnd.tracekit.pcm+json`. The code (`pcm.MEDIA_TYPE`) says
  `application/vnd.pcm+json`.
- **Tool placement.** The design says any opened call with a `command` field is a shell call (and a `url` field an
  http call). The code places tools with the fixed table (`claims.placed()`).
- **Root grants.** The design first let agent approvers issue root grants. The code (and the design's binding
  amendment) requires a person.
- **Grant issuer tenant and `delegable`.** Not in the design's first grant shape; both are required in the code.
- **Evidence origin.** The design checks evidence against the sender's run only. The code also requires the
  checkpoint origin to be the log that signed the message.
- **`file_written`.** The design reads the file operation from the args. The code reads it from the tool name only.
- **`tests_passed`.** The design matched a test-command pattern. The code requires a single simple command from a
  fixed list of test runners (6.8).
- **Held runs.** The design refused quarantined runs only; the code refuses held runs too.

## Appendix B. Open issues

A review of the previous draft found an attack on its verifier rules: a `tests_passed` suite with `$'…'` quoting,
`&` or a file named like a runner was proven though its exit status was not the tests' (14.10, 14.19, 14.23). This
draft closes those; it has no other known open attack on its verifier rules. What `tests_passed` proves still rests
on the receiver reading `suite` (6.6). Questions earlier drafts left open are now decided rules, each marked
"(decided, 0.1)": canonical base64 (4.3), the PCM key (4.5), only a configured person for `approved_by` (6.6),
absolute paths for `file_written` (6.6), host comparison and deviation characters (6.7), test commands and plain
words (6.8), the sender pair and one acceptance per receiver (9). What remains:

**In the reference implementation.** Places where Tracekit does less than this document asks; each is a `lean:`
limit in its code and a row of its `docs/limits.md`.

1. **Replay state is per process** (9, 14.14). `pcm.Replay` keeps its state in memory, so a deployment with several
   replicas per receiver identity must route each sender to one replica until Tracekit shares the state.
2. **One grant per approval holds only after the call's result** (14.8).
3. **Messages and grants are signed with the log key** (4.5), as the SHOULD for a dedicated key allows.

**Questions for a later draft.**

1. **Host reading leans on Python's `urllib`, `unicodedata` and `idna`** (6.7). A verifier in another language must
   reproduce `urlsplit(url).hostname` and when `urlsplit` raises (its bracket checks changed in Python 3.11.4 and in
   patch releases since), NFKC at Python's Unicode version, and the IDNA 2003 codec. A statement of the rule that
   needs none of them, closer to the WHATWG host parser and UTS 46, is open; until then the vectors pin the cases
   that matter and senders keep to ASCII hosts and plain URLs.
2. **A dedicated PCM key is pinned like a log key** (4.5). It sits in trust.json `logs`, so a verifier would also
   take it on that log's checkpoints. A trust member that pins a key for messages and grants only would separate the
   two; it changes the trust document, so it waits for a later draft.
3. **The regular expression dialect of `id` patterns** (5.2) is not fixed. Schema authors keep to what ECMAScript and
   Python `re` read alike.
