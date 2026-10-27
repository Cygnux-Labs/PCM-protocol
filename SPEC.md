# PCM 0.1 (draft): Proof-Carrying Messages

Status: draft 0.1, experimental. Wire version `"pcm": 0`. This text can change before 1.0 without notice.

Editor: Cygnux Labs. Reference implementation: Tracekit [Tracekit], described in Appendix C.

Each part of this document carries one of two marks:

- **[Implemented]**: the reference implementation implements it, and produced the test vectors in `vectors/`.
- **[Draft]**: specified here, implemented nowhere yet.

A rule marked **(decided, 0.1)** settles a question an earlier draft left open, by the stricter and less ambiguous
choice. It is normative. Where it constrains a verifier, the reference implementation implements it and the vectors
pin it.

Examples, notes and rationales are informative, and so are Appendices A, B and C. Appendix A records the choices this
draft made where earlier designs differed, Appendix B lists the questions still open, and Appendix C describes the
reference implementation, including where it does less than this document asks. Where a step is what a particular
library does, a note names the library; the step, not the library, is the rule.

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
Appendix A. Design choices
Appendix B. Open issues
Appendix C. Reference implementation

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
- **Tool placement table**: PCM 0.1's fixed map from tool name to tool class (`shell`, `http`, ...),
  `registry/tools.json` (section 10.2).
- **Control character**: a code point below U+0020 (the C0 controls), as [C2SP-NOTE] uses the term. U+007F (DEL) is
  not one: a rule that refuses it names it (6.8).
- **White space**: a code point whose Unicode general category is Zs or whose bidirectional class is WS, B or S:
  U+0009 to U+000D, U+001C to U+001F, U+0020, U+0085, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F,
  U+205F and U+3000. (Python's `str.isspace()` and its regular expressions' `\s` match this set.)

## 3. The message envelope

### 3.1 Media type

A PCM message is one JSON object, UTF-8 encoded, of media type `application/vnd.pcm+json` **[Implemented]**.

### 3.2 Fields

The object is closed: a member not listed here makes the envelope invalid. The JSON Schema of this shape is
`schemas/message.schema.json`.

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
time", and MUST NOT raise. **[Implemented]** (vector `reject-replay-no-real-time`: month 13, re-signed with the test log
key, since a signer takes `ts` from its clock.)

Note: regular expression dialects disagree on `.`: Python's refuses only U+000A, ECMAScript's also `\r`, U+2028 and
U+2029. That is why IDENTITY is written with `[^\n]`, and the published JSON Schemas write it the same way. Vector
`accept-identity-line-break-chars` sends to `uid:990102\r x`.

### 3.3 Parsing

A receiver MUST parse the message strictly: valid UTF-8, no duplicate member names, integers within
±(2^53 − 1), no lone surrogates, nesting at most 128 deep. A message that does not parse this way MUST NOT be
accepted. **[Implemented]**

### 3.4 Example

The examples in this document are real. Unless a section says otherwise, they come from the test vector
`vectors/accept-approved-by.json`, which the reference implementation's signer produced (agent A is `uid:990101`, agent
B `uid:990102`, alice `uid:990001`). Regenerating the vectors changes ids, times and signatures.

The message, with its claim and grant shown in sections 6.6 and 7.1:

```json
{
 "from": {"agent": "uid:990101", "run": "ca4ca057363ca9d4028c7dd8b6bc5084", "tenant": "default"},
 "to": {"agent": "uid:990102"},
 "intent": {"type": "refund.request@sha256:d8636b6fbbd07430d057ea9ead9c27f0df1b918b10d34ab9257a4971d487846c",
            "args": {"amount": 12000, "order": 81}},
 "claims": ["... one approved_by claim, section 6.6 ..."],
 "grants": ["... alice's root grant, section 7.1 ..."],
 "pcm": 0,
 "id": "ee4a6471b915e045f702dbb510f20c6e",
 "ts": "2026-10-27T18:03:28.036966Z",
 "nonce": "384f379ffc2524d63ab12057b19e6465",
 "sig": {"key": "example.com/pcm-test-log+0bb91e66",
         "sig": "91qFTtYibJ9vTNUjSfl5aDKn49M0j5/Q26QSmjaAGzDKzv6W5BUldEK47avP/LhLHKFQOzZ+stCdjwpVauzvCA=="}
}
```

A message may also carry a payload, such as `"payload": {"kind": "text", "text": "please refund order 81"}`.

## 4. Canonical form and signatures

### 4.1 Canonical form

PCM hashes and signs the JSON Canonicalization Scheme (JCS) [RFC8785] encoding of a value. `H(v)` below is
`"sha256:" + lowercase hex(SHA-256(JCS(v)))`. **[Implemented]**

### 4.2 Signatures

Messages and grants are signed with Ed25519 [RFC8032] by the signer's log key (4.5). The signed bytes are:

```
JCS( the object without its "sig" member, plus the member "t": TAG )
```

| Object | TAG |
|---|---|
| message | `pcm.message.v0` |
| grant | `pcm.grant.v0` |

The signature covers every member except `sig`, including `claims`, `grants` and `payload` in full. `"t"` is never a
member on the wire: both objects are closed, so a `"t"` member makes the envelope invalid. **[Implemented]**

The bytes signed for the message in 3.4 start:

```
{"claims":[{"args":{"call":"grant-1","person":"alice"},"evidence":{"checkpoint":"example.com/pcm-test-log\n9\n...
```

and further on, in JCS key order:

```
..."nonce":"384f379ffc2524d63ab12057b19e6465","pcm":0,"t":"pcm.message.v0","to":{"agent":"uid:990102"},"ts"...
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
signature, not an error. **[Implemented]**

**Canonical base64 (decided, 0.1).** Every base64 value in PCM (`sig.sig`, evidence proof entries, checkpoint note roots
and signature lines, vkeys) MUST be canonical: the standard alphabet of [RFC4648], padded, no white space or line break,
and the unused bits of the last character zero: decoding it and encoding the bytes again gives back the same text. A
verifier MUST decode it so, and MUST treat text that is not canonical as invalid: a bad signature in `sig.sig`, "not in
the checkpoint" in a proof entry, a failed note in a checkpoint. Rationale: a value has one text form, so a signed
object can't be rewritten into another text that still verifies (and hashes differently, as a grant's `parent` would).
**[Implemented]** (vectors `reject-sig-non-canonical-base64`, `reject-claim-proof-non-canonical-base64`.)

Ed25519 verification MUST follow these rules, so two verifiers agree on every signature: the signature is 64 bytes; its
S value is below the group order L; the public key is a canonical encoding (y below 2^255 − 19) of a point that is not
of small order; and the cofactorless equation [S]B = R + [k]A holds. **[Implemented]** Common libraries skip the key
checks. Without them, a pinned small-order key verifies a forged signature on any message: vector
`reject-small-order-key` pins the identity point and signs with R = identity, S = 0.

PCM 0.1 signatures are Ed25519 only. A log that also pins a hybrid SLH-DSA key (10.1) gets no second signature on
messages or grants. **[Implemented]**

### 4.4 The attesting signer

The agent never holds a signing key. It sends the message body to the signer, and the signer signs. **[Implemented]**

- The signer MUST sign only as the calling run's own identity. It MUST refuse a body whose `from` is not exactly
  `{"agent": <the identity that registered the run>, "run": <its id>, "tenant": <its tenant>}`.
- The signer MUST refuse a caller that holds the run's credential but is not the run's owner (an identity the
  credential was delegated to, such as a reader of the run's log or an observer).
- The signer MUST set `pcm`, `id`, `ts` and `nonce` itself, from its own clock and randomness. A body that holds
  them, or `sig` or `t`, is refused.
- The signer MUST refuse to sign while the run is held or quarantined (section 14.9).
- The signer SHOULD record each message it signs as a record in the sender's run, holding the message hash, id,
  receiver and intent reference, never the args. An auditor of the run then sees every message the agent had signed,
  in order among its tool calls.
- The signer does not check the claims or grants of a message. The verifier does.

### 4.5 The signing key (decided, 0.1)

A PCM 0.1 signer MUST sign messages and grants with its log key: the one Ed25519 key that trust.json `logs` pins under
the log's name (10.1), which also signs the log's checkpoints. The `pcm.*` tags keep the purposes apart (4.2, 14.5).
A dedicated PCM key, used for nothing else, needs a trust member of its own beside `logs`, so it is left to a later
draft (Appendix B question 2). Rationale: with one key per log name, the key that signed a message names exactly one
log, so the replay sender (9) and the evidence origin (6.2 step 2) are unambiguous.

## 5. Intent schemas

### 5.1 The schema document

An intent's args are typed by a schema document. Both sides keep a copy. Example, the refund intent of section 1:

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

The document is closed. The JSON Schema is `schemas/schema-document.schema.json`. **[Implemented]**

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
and Python `re` read the same way, with ASCII classes (`[0-9]`, not `\d`, which some dialects also match to digits
such as `٣`).

A verifier MUST refuse a schema document that does not meet 5.1 and 5.2, or whose `int` field has `min > max`, whose
`enum` values repeat, or whose `id` pattern does not compile. That is a configuration error of the receiver, which the
verifier reports instead of a verdict on a message. **[Implemented]**

### 5.3 Strict matching of args

`intent.args` MUST be an object. Every member MUST be a field of the document. Every field without `optional` MUST be
present. Every present value MUST pass its field's rule. For example (the detail strings are informative):

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
`failed`; it does not make the envelope invalid. **[Implemented]**

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
  call is of a tool the verifier can't place (6.5), or the only matching record shows an attempt to reach a host, not
  a connection (6.6), or the verifier can't tell whether a record matches: a host that won't parse (6.7), a `Write`
  of a relative path, or of a drive path spelled otherwise, that may be the claimed file (6.6).
- **failed**: the claim's args are invalid or malformed (a `file_written` path that is relative or has a `..`
  segment, 6.6; a `tests_passed` suite that is no test command, 6.8), the evidence does not verify, or no record in it
  says what the claim says (an approval without the decision it approved says nothing of what was approved, 6.6).
  The args and malformed checks come before the evidence: a malformed claim is `failed`
  with or without evidence, at every conformance level (vectors `reject-claim-tests-passed-malformed-no-evidence`,
  `reject-claim-file-written-relative-no-evidence`). **[Implemented]**

When several records match, the best result counts: proven, then unproven, then failed.

### 6.2 Evidence items

Evidence is `{"checkpoint", "records"}`, closed (`schemas/evidence.schema.json`):

- `checkpoint`: a C2SP tlog-checkpoint signed note [C2SP-CKPT], 1 to 16384 characters:

  ```
  <origin>\n<tree size>\n<base64 root hash>\n\n— <key name> <base64(key id || signature)>\n ...
  ```

  PCM 0.1 accepts exactly the three body lines (no extension lines). **[Implemented]**
- `records`: 1 to 16 records, each `{"event", "hash", "proof", "salt"?, "args"?}`, closed:
  - `event`: the log record, as the signer wrote it;
  - `hash`: DIGEST, `H(event)`;
  - `proof`: at most 64 base64 strings (each at most 44 characters), the RFC 9162 inclusion proof;
  - `salt` (64 hex) and `args` (any JSON value): an opening (6.3).

A verifier checks an evidence item in this order. The first failure makes the claim `failed`, with the reason.
**[Implemented]**

1. **Note.** The note verifies against the pinned keys (section 10). These are the rules of [C2SP-NOTE],
   [C2SP-CKPT] and [C2SP-COSIG] as PCM applies them; breaking any one fails the note:
   - The note ends with `\n` and holds no control character (section 2) but `\n`; U+007F is allowed. Its text is
     everything up to the first blank line, with its final `\n`. The text is exactly three lines: the origin, the tree
     size and the root.
   - The origin, and every key name, is 1 to 255 UTF-8 bytes with no `+`, no white space and no control character.
     The tree size is ASCII decimal, at most 20 digits, with no leading zero. The root is 32 bytes.
   - After the blank line come 1 to 64 signature lines. Each is `— `, a key name, one space and base64 of at least
     5 bytes: a 4-byte key id, then the signature. Base64 here MUST be canonical. Every line MUST be well formed, even
     one of a key trust does not pin (vector `reject-claim-malformed-unpinned-note-line`).
   - No (key name, key id) appears twice.
   - A line whose (name, key id) no pinned key has is skipped. A line of a pinned Ed25519 log key MUST verify over the
     text (4.3). A line of a pinned witness key is exactly 72 bytes after the key id: an 8-byte big-endian time `t`,
     then an Ed25519 signature over `cosignature/v1\ntime <t>\n` followed by the text.
   - A key in `logs` that is a cosignature key, or a key in `witnesses` that is not, fails the note (vector
     `reject-claim-witness-key-in-logs`: a witness key pinned in `logs`).
   - The Ed25519 log key trust pins under the origin's name (one at most, 10.1) MUST have a valid line. When trust
     pins a hybrid key named after the origin, its line MUST be present and valid (10.1).
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
   3. `event.tenant == from.tenant` and `event.run_id == from.run`: the record is from the sender's own run. Run ids
      are the client's, unique only per log and tenant, so both are compared (vectors
      `reject-claim-evidence-from-another-run`, `reject-claim-evidence-from-another-tenant`: a run of another tenant
      registered under the sender's run id).
   4. `event` is a valid event of the evidence profile (6.4): `schema_version` is `tracekit.event.v2` and the event
      matches that profile's event schema, `registry/tracekit.event.v2.json`; else "record i: not a valid event". A
      pinned log can still be hostile, and a checker must not meet a record without the fields it reads.
      **[Implemented]** (vector `reject-claim-record-not-an-event`: an approval whose `prev_hash` is the number 5, a
      field no checker reads, under a checkpoint the test log key signs offline.)
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
args are read by a claim checker. **[Implemented]**

### 6.4 The evidence profile `tracekit.event.v2`

Claim checkers read records. Which fields they read, and what the fields mean, is an **evidence profile**. PCM 0.1
defines one profile, `tracekit.event.v2`: the v2 event format of [Tracekit] (`schema_version: "tracekit.event.v2"`),
whose event schema this repository ships as `registry/tracekit.event.v2.json`. **[Implemented]**

The profile's trust assumptions. A verifier relies on them, and a log that offers this profile MUST meet them:

- `approval` records are written by the signer only, from the answer of an identity it authenticated. `data.approver`
  is that identity. `data.person` is there only when the signer's approvals configuration maps that identity to a
  person's name. An agent approver's answer carries `approver_kind: "agent"`. A signer without an approvals
  configuration lets any identity of the run's tenant but the run's own answer, and records no `approver_kind`: such
  an answer may come from another agent process (6.6, `approved_by`). `data.self_approved` is `true` when the
  answering identity, or the person it maps to, is the run's own agent or that agent's person.
- `approval.request` records are written by the signer only, when it asks for an answer about a `policy.decision` it
  recorded: `data.decision_id` names that decision, and `data.approval_id` is the id the answer's `approval` record
  carries.
- `effect.observed` records are written by the signer only, from an observer's report. The signer gives a report to
  the run whose token came with it, or else to the latest open run of the identity the observer names, by time. With
  two runs of one identity open at once, an effect can land in the other run. A `net` record is an egress observer's
  count of the run's traffic to one host in one minute: `data.connections` is the number of connections it opened to
  the host, 0 when every connect failed (or for a later minute of a connection opened before). A `connect` record is a
  kernel sensor's report that a process of the run called connect to the host: an attempt, which may have failed.
  `data.denied` appears on `connect` records only: the sensor blocked the attempt.
- A `tool.result` record's top-level `source` and `tier` are set by the signer from the authenticated caller. They are
  `"gateway"` and `"T2"` only when an attesting gateway or executor ran the call and recorded its result. Nothing in
  `data` sets them.
- A T2 record's tool name means its class. The verifier places a call by `data.tool` alone (6.5, 10.2), so it trusts
  the attesting gateway or executor that ran the call to run, under a name the placement table places, only a tool
  of that class. An executor that runs actions under names its operator chooses breaks this when an action takes the
  name of a tool of another class: an HTTP action named `Bash` is placed as `shell`, and its `ok` says only that the
  HTTP request succeeded, yet a call of it whose `command` arg is a suite proves `tests_passed` for that suite though
  no runner ran (14.26).
- A `policy.decision` record's `args_commitment` commits to the args the signer decided.

The fields each checker reads:

| Record type | Fields read |
|---|---|
| every record | `seq` (log index), `tenant`, `run_id`, `type`, `data` |
| `policy.decision` | `data.tool`, `data.decision` (`allow`, `ask`, `deny`), `data.decision_id`, `data.tool_use_id`, `data.args_commitment` |
| `tool.result` | top-level `source` and `tier`; `data.decision_id`, `data.tool_use_id`, `data.ok`; `data.via` (detail text only) |
| `approval` | `data.decision`, `data.tool_use_id`, `data.approval_id`, `data.person`, `data.approver_kind` (absent means `person`), `data.self_approved` |
| `approval.request` | `data.approval_id`, `data.decision_id` |
| `effect.observed` | `data.host`, `data.kind` (`net` or `connect`), `data.connections` (`net`), `data.denied` (`connect`); `data.observer` (detail text only) |

A real `approval` record, as evidence carries it:

```json
{"schema_version": "tracekit.event.v2", "id": "c3dce747e850569b74e3891aba636393", "seq": 5,
 "prev_hash": "sha256:b7bfb9e79279fb53a9150a44703370a7b638b87f74eb35badd72dce8508eec24",
 "ts": "2026-10-27T18:03:28.018920Z", "run_id": "ca4ca057363ca9d4028c7dd8b6bc5084", "agent_id": "main",
 "parent_id": null, "source": "sdk", "type": "approval",
 "data": {"tool_use_id": "grant-1", "approval_id": "apr-1d2c2e92bc8d5d9eeef19ecfd943aa94", "decision": "approve",
          "approver": "uid:990001", "approver_identity": {"scheme": "uid", "subject": "990001", "attested": true},
          "channel": "rpc", "self_approved": false, "person": "alice"},
 "tenant": "default", "log_id": "b92395338b39e901fa25715a224ab0eb", "run_seq": 3,
 "run_prev_hash": "sha256:b7bfb9e79279fb53a9150a44703370a7b638b87f74eb35badd72dce8508eec24",
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
   call: vector `reject-claim-decision-without-id`), and where `data.decision != "deny"` (a denied call matches
   nothing, even with a result: vector `reject-claim-tests-passed-denied-call`): `match(data.tool, args)`
   answers yes, no, or can't tell. Can't tell: candidate `unproven` ("the verifier can't tell whether call …"); next
   record. No: next record. Yes:
   1. If `class` is set and the placement table does not map `data.tool` to `class`: candidate `unproven`; next record.
   2. For each `tool.result` record whose `(data.decision_id, data.tool_use_id)` equals the decision's:
      - `data.ok` is not `true`: candidate `failed` ("… and failed");
      - else top-level `source == "gateway"` and `tier == "T2"`: result `proven`; stop;
      - else: candidate `unproven` ("the result is the agent's own report (T1)").
3. The result is the best candidate.

From vector `accept-tests-passed-t2`: the evidence for `tests_passed {"suite": "pytest -q tests/test_refund.py"}`
holds an opened decision and its result, both recorded through an attesting executor:

```json
[{"event": {"type": "policy.decision", "seq": 10, "source": "gateway", "tier": "T2", "...": "...",
            "data": {"tool_use_id": "call-9", "tool": "Bash", "decision": "allow",
                     "decision_id": "dec-b2aed75524671c455994060babfe77c6", "via": "mtls:spiffe://example/executor",
                     "args_commitment": "hmac-sha256:a63fb58a71f320704ce7d261fdb2c2b1d5abc9558994ed04a7310a61817816fb",
                     "...": "..."}},
  "salt": "72f361d4f482f64aa98783623c1cd020c807e193d2f72656f0ee71198788f9d3",
  "args": {"command": "pytest -q tests/test_refund.py"}, "hash": "...", "proof": ["..."]},
 {"event": {"type": "tool.result", "seq": 11, "source": "gateway", "tier": "T2", "...": "...",
            "data": {"tool_use_id": "call-9", "ok": true, "decision_id": "dec-b2aed75524671c455994060babfe77c6",
                     "via": "mtls:spiffe://example/executor", "...": "..."}},
  "hash": "...", "proof": ["..."]}]
```

Result: `proven`, "call call-9 ran 'pytest -q tests/test_refund.py', run by mtls:spiffe://example/executor (T2)".
The same claim with a result the agent reported itself is `unproven` (`accept-unproven-t1-result`), and so is one
run through `mcp:ci/run`, a tool the table does not place as `shell` (`accept-unproven-unplaced-tool`).

### 6.6 The four claim types

**`tests_passed {suite}`** **[Implemented]**

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

**`approved_by {person, call}`** **[Implemented]**

`call` is the agent's own name for a call (a `tool_use_id`), so an approval alone says nothing of what was approved.
The claim is `proven` when the records of one evidence item hold all three of:

1. an `approval` record with `data.decision == "approve"`, `data.tool_use_id == call`, `data.person == person`,
   `data.approver_kind` absent or `"person"`, and `data.self_approved` not `true`;
2. an `approval.request` record whose `data.approval_id` equals that approval's `data.approval_id`;
3. a `policy.decision` record whose `data.decision_id` equals that request's `data.decision_id`, with
   `data.tool_use_id == call` and a `data.tool` that is not empty: the decision the request asked about.

Else `failed`. An approval that meets item 1 without the other two is `failed` too, not `unproven` ("… the evidence
holds no decision of the call it approved"): the sender chooses its evidence and can always add them, and without them
the agent's call id is all that would say what was approved (vectors `reject-claim-approved-by-without-decision`;
`reject-claim-approved-by-other-decision`, where the agent decided two calls under one id and the evidence holds the
decision the request does not name). No T2 is needed: the signer writes all three records. An agent approver's answer
(`reject-claim-approved-by-agent-approver`) and a self-approval (`reject-claim-approved-by-self-approval`: erin
approves a call of her own agent's run) prove no person's approval.

**What was approved (decided, 0.1).** The `detail` of a proven claim MUST name the decision's `data.tool` and, when the
evidence opens the decision (6.3), its opened args, in full, as JCS: `approval seq 5 by alice of pcm.grant call
grant-1`, or `approval seq 7 by alice of read_file call refund-81-approved with args {"path":"/etc/motd"}`. A receiver
MUST read the tool and args in the detail, not only the result. Rationale: the agent names its calls, so a claim that
alice approved `refund-81-approved` can be proven by her approval of a `read_file` call the agent named so; only the
decision says what she saw. The args are never cut short, so padding can't push a field out of sight.

**Only a configured person (decided, 0.1).** `person` is compared with `data.person` only, never with
`data.approver`. `data.person` is there only when the signer's approvals configuration maps the answering identity
to a person's name (6.4), so a claim that names a raw identity, or an identity no person maps to, is `failed`.
Rationale: without an approvals configuration any identity of the tenant may answer, so a raw identity proves no
human looked. **[Implemented]** (vector `reject-claim-approved-by-unmapped-identity`: `uid:990009` answers and no person
maps to it.)

What `proven` means: the person the signer's approvals configuration names `person` answered "approve" when the
signer asked about the decision the detail names: a call `call` of that tool, with those args when opened.

The claim of `accept-approved-by`, with its evidence (the decision, the request and the approval of 6.4; events
shortened to the fields the checker reads):

```json
{"type": "approved_by", "args": {"person": "alice", "call": "grant-1"},
 "evidence": {
  "checkpoint": "example.com/pcm-test-log\n9\n/PdGPT4fz2Qqik7tDD+59ec2+roL3q+25cFqZzX5HCQ=\n\n— example.com/pcm-test-log C7keZim/1AcIBBK2FDzACejPPJnYomqvV5YeLHAf7hcw3bOLcp/Ljkq0Z0ZXI6eVUi0Oy6qWbyokRbUHCFo9o7mI5gE=\n",
  "records": [
   {"event": {"type": "policy.decision", "seq": 3, "...": "...",
              "data": {"tool_use_id": "grant-1", "tool": "pcm.grant", "decision": "ask",
                       "decision_id": "dec-2e2a9d71b749a89e9cffe63add596a76", "...": "..."}},
    "hash": "sha256:9e38ce5476297488576fb62725aed11943a9708c22472fbc41f41a049b502afe",
    "proof": ["wef20f80k8WeOsGoGUOn4R+z1W9NhKnFZ/I6eGcVonQ=", "ouTsrhuiukTEQfy0YtNc60lSsTwyt6aKxR+gpkvBEVk=",
              "ysORMuiFrvAH/6VringqIYAMnB/B5Sb46qfmTneRgz0=", "qwNLUg28jmVldV3QwzWpx7ymvLv4MkL4bEoFIsAzM2w="]},
   {"event": {"type": "approval.request", "seq": 4, "...": "...",
              "data": {"approval_id": "apr-1d2c2e92bc8d5d9eeef19ecfd943aa94",
                       "decision_id": "dec-2e2a9d71b749a89e9cffe63add596a76", "...": "..."}},
    "hash": "sha256:b7bfb9e79279fb53a9150a44703370a7b638b87f74eb35badd72dce8508eec24",
    "proof": ["1s8xpq57AtJUYul2YyP7DFeHdN3NHxZWvuqNfFGtGkA=", "7oIg3wsiWUySx219/g+dK2De4Oi2IBbmuKn2YFj4Nns=",
              "1BIwB/g9zRm8MwAwlRjogiUXj/WoB+HPW6gbzuEGm/c=", "qwNLUg28jmVldV3QwzWpx7ymvLv4MkL4bEoFIsAzM2w="]},
   {"event": {"...": "the approval record of 6.4"},
    "hash": "sha256:0f3241ada46c102736f2531a440e3bb942c426bd8800acf15549995de97f64ea",
    "proof": ["tsoD/Lx6qYUuOqo1BTmgDMxGfnyoxxo9y6qMWx59L6A=", "7oIg3wsiWUySx219/g+dK2De4Oi2IBbmuKn2YFj4Nns=",
              "1BIwB/g9zRm8MwAwlRjogiUXj/WoB+HPW6gbzuEGm/c=", "qwNLUg28jmVldV3QwzWpx7ymvLv4MkL4bEoFIsAzM2w="]}]}}
```

Result: `{"type": "approved_by", "result": "proven", "detail": "approval seq 5 by alice of pcm.grant call grant-1"}`:
alice approved the `pcm.grant` call that asked for the grant of 7.1. The vectors
show the other outcomes: one hex digit of `hash` changed (`reject-claim-changed-record-hash`: "record 1: hash does not
match the event"), the proof's last hash cut (`reject-claim-cut-proof`), another person named
(`reject-claim-wrong-person`), the approval of another call (`reject-claim-approval-of-another-call`), a proof entry
that is not canonical base64 (`reject-claim-proof-non-canonical-base64`).

**`reached_host {host}`** **[Implemented]**

Hosts are compared in the form of 6.7.

1. If the claim's `host` won't parse (6.7): `unproven` ("… is no host the verifier can read"). Vector
   `accept-unproven-reached-host-unreadable-claim` (`a..example`, an empty label).
2. **A connection, not an attempt (decided, 0.1).** `proven` when a record has `type == "effect.observed"`,
   `data.kind == "net"`, `data.connections` above 0, and a `data.host` that has the claim's compared form: an egress
   observer saw the run open a connection to the host (vector `accept-reached-host-observed`). Candidates `unproven`:
   a `net` record of that host with `data.connections` 0 ("saw no connection to … open"; vector
   `accept-unproven-reached-host-no-connection`), a `connect` record of that host whose `data.denied` is absent or
   false (an attempt; vector `accept-unproven-reached-host-sensor-connect`), and a `net` or `connect` record, not
   denied, whose `data.host` is absent or won't parse. A `connect` record with `data.denied == true` counts for
   nothing (vector `reject-claim-reached-host-denied-connect`). Rationale: a kernel sensor reports the call to
   connect, which can fail, and an egress observer counts a minute with no connection when its connect upstream failed;
   either says the run tried the host, not that it reached it.
3. Else the best of the candidates and `Ran(match, "http")`, where `match` reads the args member `url`: not a string,
   or a URL with no host (6.7 step 2: a scheme other than `http`, `https`, `ws`, `wss` and `ftp`, such as `file:`,
   `mailto:` or `gopher:`, or no host at all): no; a URL whose host won't parse: can't tell; else yes when the URL's
   host has the claim's compared form.

Vectors: `accept-reached-host-http` (`https://API.Example.COM:8443/v1` is `api.example.com`),
`accept-reached-host-claim-port`, `accept-reached-host-trailing-dot`, `accept-reached-host-short-ipv4`,
`accept-reached-host-idn`, `accept-reached-host-unassigned`, `reject-claim-reached-host-other-host`,
`reject-claim-reached-host-file-url`, `accept-unproven-reached-host-bracket`, `accept-unproven-reached-host-ambiguous`,
`accept-unproven-reached-host-deviation`, `accept-unproven-reached-host-no-ipv6`, `accept-unproven-reached-host-nul`,
`accept-unproven-reached-host-claim-bad-port`, `accept-unproven-reached-host-no-connection`,
`accept-unproven-reached-host-sensor-connect`, `reject-claim-reached-host-denied-connect`.

**`file_written {path, digest}`** **[Implemented]**

**Path rules (decided, 0.1).** The claim's `path` picks one of two sets of rules, and a call's path is read by the
claim's rules:

- **Windows rules**, when `path` is a **drive path**: an ASCII letter, `:`, then `\` or `/` (`C:\work\a.txt`,
  `C:/work/a.txt`). `\` and `/` both separate segments. A path is absolute when it is a drive path.
- **POSIX rules**, for any other `path`. Only `/` separates segments; `\` is part of a segment, so `/work\a.txt` is the
  file `work\a.txt` in `/`. A path is absolute when it starts with `/`, so `C:/x` is relative here.

A path is **rewritten** this way: under Windows rules every `\` becomes `/` first; then the path is split into
segments at `/`. An absolute path with no `..` segment keeps its segments but the empty and `.` ones, joined by `/`,
behind `//` when it starts with exactly two slashes, behind `/` when it starts with one or with three or more, and
behind nothing when it starts with a drive letter: `//a//b/./` is `//a/b`, `///a/` is `/a`, `C:\x//y` is `C:/x/y`.
(This is POSIX `normpath`, Python's `posixpath.normpath`.) Any other path keeps only its segments after its last `..`
segment, without the empty and `.` ones, joined by `/`. Paths are compared as they are written, case included:
`c:\work\a.txt` is not `C:\work\a.txt`. Rationale: the record does not say on which system the call ran, so a path is
read the one way that holds on the system its claim names: a POSIX path never has `\` as a separator, and a drive path
names one file only on Windows.

Steps 1 and 2 make a claim malformed, so they apply with or without evidence (6.1).

1. If `path`, split by its rules, has a `..` segment: `failed` ("name the file's own path"). (`/work\..\a.txt` has
   none: under POSIX rules `work\..\a.txt` is one segment.)
2. **Absolute paths only (decided, 0.1).** If `path` is not absolute by its rules: `failed` ("… is relative: name the
   file's absolute path"). So `\work\a.txt`, `C:a.txt` and `\\server\share\a.txt` are relative. Rationale: a relative
   path names a different file from each working directory, so it can't say which file was written. Vectors
   `reject-claim-file-written-relative` (a Write of the same relative path, which would match without this rule),
   `reject-claim-file-written-relative-no-evidence`.
3. Else `Ran(match)` with no class. `match` is no unless all of these hold:
   - the tool is a write tool: its name maps to the file operation `write` in the reference table, which in 0.1 is the
     tool `Write` only (an `op` member in the args is the agent's word and is ignored);
   - the file path of the args (the first non-null of `file_path`, `notebook_path`, `path`) is a string;
   - the args member `content` is a string, and `"sha256:" + hex(SHA-256(UTF-8 content)) == digest` (what `sha256sum`
     prints for the file, with `sha256:` in front). Edits without the full content never count.

   Then, with `want` the claim's rewritten `path`, `raw` the args' file path and `got` that path rewritten by the
   claim's rules:
   - `got` absolute and `got == want`: yes under POSIX rules. Under Windows rules, yes only when `raw` is the claim's
     `path` exactly, else can't tell: `C:/work/a.txt` is the claim's file `C:\work\a.txt` on Windows but a relative
     path on POSIX, and the record does not say which system ran the call (vectors `accept-file-written-drive-path`,
     `accept-unproven-file-written-drive-separators`).
   - `got` not absolute, where `"/" + want` ends with `"/" + got`: can't tell: the record does not hold the working
     directory, so it may be this file or another (`unproven`, never `proven`; vector
     `accept-unproven-file-written-relative-call`).
   - Anything else is no. A Write of `/work\report.txt` does not write `/work/report.txt` (vector
     `reject-claim-file-written-backslash`).

Vectors: `accept-file-written`, `reject-claim-file-written-wrong-digest`, `reject-claim-file-written-dotdot`,
`reject-claim-file-written-relative`, `accept-unproven-file-written-relative-call`, `reject-claim-file-written-backslash`,
`accept-unproven-file-written-drive-separators`, `accept-file-written-drive-path`.

### 6.7 Hosts (decided, 0.1)

`reached_host` compares hosts in one canonical form: the claim's `host`, an effect's `data.host` and a call's URL
host alike. Two hosts match when their compared forms are equal. Ports are ignored. A host that won't parse has no
compared form, and gives `unproven`, never `proven` or `failed`. Rationale: a host has many spellings
(`API.Example.COM:8443`, `api.example.com.`, `bücher.example`, `127.1`); comparing one canonical form makes every
spelling of the same host match. Where two readers this section names disagree on a host (the browser and generic
readings of step 2, IDNA 2003 and UTS 46), the host won't parse rather than match a host the call may not have
reached, and a host the verifier can't read proves nothing either way. **[Implemented]**

The intent is the WHATWG URL host parser [WHATWG-URL] followed by IDNA. PCM 0.1 specifies the reading step by step,
so that verifiers in any language agree. Notes name the Python standard-library functions that behave as a step says,
since the reference implementation uses them. The vectors were made on CPython 3.11.15, whose Unicode version is
14.0.0.

1. **A URL.** Remove tabs and line breaks (U+0009, U+000A, U+000D). If the URL, with leading control characters and
   spaces skipped, does not start with `http:`, `https:`, `ws:`, `wss:`, `ftp:` or `file:` (in any case), another
   scheme (`[A-Za-z][A-Za-z0-9+.-]*` and `:`) not followed by a digit (so `localhost:` at the end is a scheme), or
   two slashes (`/` or `\`), put `http://` in front: `example.com:8080/x` is `http://example.com:8080/x`.
2. **The scheme, then the host read two ways.** Read the URL as a browser does: drop tabs and line breaks, strip
   leading and trailing control characters and spaces, and peel any number of leading `view-source:` and `blob:` (in
   any case, each with the control characters and spaces after it). Its scheme is the leading
   `[A-Za-z][A-Za-z0-9+.-]*` before a `:`, in lower case, or none. A URL whose scheme is not `http`, `https`, `ws`,
   `wss` or `ftp`, and not none, has no host, whatever the generic reading finds (`file://api.example.com/x`,
   `gopher://g.example/`; vector `reject-claim-reached-host-file-url`); neither has a URL with no scheme that does
   not start with two slashes (`/` or `\`). Otherwise read the host two ways:
   - **The browser reading.** Take what follows the scheme's `:` (all of the URL when it has no scheme), read every
     `\` as `/`, skip the leading slashes, and keep what comes before the first `/`, `?` or `#`, then what follows
     its last `@`. If that starts with `[` and holds a `]`, the reading is it up to and including the first `]`;
     else it is what comes before its first `:` (the port dropped).
   - **The generic reading**, of the URL of step 1:
     1. Strip leading control characters and spaces, then remove every tab and line break.
     2. If the text before the first `:` is not empty, starts with an ASCII letter and holds only ASCII letters,
        digits, `+`, `-` and `.`, remove it and that `:`.
     3. If what remains does not start with `//`, there is no host. Else the authority is what follows the `//` up
        to the first `/`, `?` or `#` (`\` is no delimiter here).
     4. The URL is refused when the authority holds a `[` but no `]`, or a `]` but no `[`; when it holds both and
        fails the bracket check below; and when it holds a code point outside ASCII and, with every `@`, `:`, `#`
        and `?` removed, its NFKC form [UAX15] differs from it and holds a `/`, `?`, `#`, `@` or `:`.
     5. The reading is the part of the authority after its last `@`: when that holds a `[`, what lies between its
        first `[` and the next `]` (or the end); else what comes before its first `:`. Its text before its first
        `%` is put in lower case (the Unicode lower case mapping).

     The **bracket check** takes the part of the authority after its last `@`. If that part holds a `[`, nothing may
     come before its first `[`, and after the next `]` there must be nothing or a `:`; the text between the two (up to
     the end when no `]` follows) is checked. Else its text before its first `:` is checked. The checked text passes
     when it is an IPv6 address (a text form of [RFC4291] section 2.2, optionally followed by `%` and a zone id of one
     or more characters other than `%`) or an IPvFuture address [RFC3986] written as a lowercase `v`, one or more hex
     digits, `.` and one or more characters. A verifier MAY instead check, by the same test, the text between the
     first `[` of the whole authority and the next `]`. The two checks differ only when the authority holds brackets
     other than one pair around its host (`http://[::1]@good.com/` passes the second and fails the first), so senders
     SHOULD NOT send such URLs (Appendix B question 1). Both refuse `http://[x]@good.com/` (vector
     `accept-unproven-reached-host-bracket`).

     **A reader without the bracket check (decided, 0.1).** A verifier whose generic reading makes neither bracket
     check MUST instead take a call's URL that holds a `[` or `]` anywhere, other than one `[` and one `]` around a
     host whose canonical form (step 3) is an IPv6 address, as a URL whose host won't parse. An IPv4-mapped or NAT64
     address in brackets has an IPv4 canonical form, so its brackets count. Such a verifier can give `unproven` where
     one that checks gives `proven` or `failed` (`http://good.com/a[1]`), never the reverse. Rationale: a reader
     without the check reads a host from `http://[x]@good.com/`, which a checking reader refuses, so the bracket is a
     place where the two readers differ, and a host two readers read apart proves nothing.

     Note: the generic reading is Python's `urllib.parse.urlsplit(url).hostname`, which refuses a URL by raising
     `ValueError`. CPython 3.11.12 and later make the first bracket check, 3.11.4 to 3.11.11 the second, and earlier
     releases neither, so a verifier that uses `urlsplit` on a release before 3.11.4 applies the rule above.

   An empty reading counts as none. A URL the generic reading refuses: the host won't parse. Else put each reading
   that is not none in canonical form (step 3). Neither reading: the URL has no host. Two readings whose canonical
   forms differ: the host won't parse, since the call may have reached either (`http://a.example\@b.example/` is
   `a.example` to the browser reading and `b.example` to the generic one; vector
   `accept-unproven-reached-host-ambiguous`). Else the host is the browser reading, or the generic one when the
   browser reading is none.
3. **Canonical form.** Percent-decode as UTF-8 (a `%` and two hex digits is a byte; a `%` without them stays as it
   is; an invalid byte sequence becomes U+FFFD, which step 4 refuses) and apply Unicode NFKC [UAX15].
   **Deviation characters (decided, 0.1).** If the result holds U+00DF `ß`, U+03C2 `ς`, U+200C ZWNJ or U+200D ZWJ,
   it won't parse. For a call's URL this check is made once, on the whole URL, percent-decoded and NFKC-normalised,
   not on each reading, so one in the path also gives `unproven` where a check of the host alone could match.
   Rationale: these are the four characters UTS 46 nontransitional processing, which browsers use, keeps where
   IDNA 2003 maps them away, so `faß.example` is `xn--fa-hia.example` to a browser and `fass.example` to the
   conversion of step 4; with them refused, the two either agree or one refuses (vector
   `accept-unproven-reached-host-deviation`). Then read U+3002 as `.` and apply Unicode full case folding.

   A result that holds a `:` won't parse unless, with every `[` and `]` at its ends removed and its zone id (from its
   first `%` on) dropped, it is an IPv6 address. Otherwise split it at `.`, leaving out one empty last part. When the
   last part is a number (`0x` and zero or more hex digits, or one or more decimal digits), the host won't parse
   unless it is an IPv4 address as `inet_aton` reads one: 1 to 4 parts, each `0x` and zero or more hex digits
   (hexadecimal; `0x` alone is 0), `0` and one or more octal digits (octal), or `0` or 1 to 10 decimal digits not
   starting with `0` (decimal); every part but the last at most 255, and the last below 256 to the power of (5 minus
   the number of parts). So `127.1` is `127.0.0.1` (vector `accept-reached-host-short-ipv4`). An address is written
   in canonical form: IPv4 in dotted decimal; IPv6 as `[`, its text form of [RFC5952] section 4 (never mixed
   notation), `]`; an IPv4-mapped (`::ffff:0:0/96`) or NAT64 (`64:ff9b::/96`) IPv6 address as the IPv4 address
   inside. NFKC follows the verifier's Unicode version: a host with a code point one version leaves unassigned can
   read differently in a verifier with another, so senders SHOULD claim ASCII hosts.

   Note: in Python this step is `urllib.parse.unquote`, `unicodedata.normalize("NFKC", …)`, `str.casefold` and
   `ipaddress`; the IPv4 rule is C's `inet_aton`.
4. **A-label.** A host that starts with `[` stays as it is if it is `[`, an IPv6 address and `]`; else it won't
   parse (`http://%5b::1%5d/` decodes to the host `[`; vector `accept-unproven-reached-host-no-ipv6`). Otherwise drop
   one trailing dot (vector `accept-reached-host-trailing-dot`); if the rest is empty or still ends with `.`, it won't
   parse. Then convert it to ASCII by IDNA 2003 [RFC3490]: an all-ASCII name is kept as it is, and each label must
   be 1 to 63 characters; any other name is split at `.` and each label goes through ToASCII [RFC3490] with Nameprep
   [RFC3491] (Unicode 3.2) and Punycode [RFC3492], with AllowUnassigned on (so a code point Unicode 3.2 leaves
   unassigned is taken: `x` and U+0378 then `.example` is `xn--x-qib.example`, vector
   `accept-reached-host-unassigned`) and UseSTD3ASCIIRules off: an ASCII label stays, a non-ASCII one becomes `xn--`
   and its Punycode, and every label must end up 1 to 63 characters. What this conversion refuses won't parse. The
   result MUST be labels of `a`-`z`, `0`-`9`, `_` and `-`, joined by single dots; else it won't parse (a NUL or `%`
   after percent-decoding; vector `accept-unproven-reached-host-nul`). `bücher.example` is `xn--bcher-kva.example`
   (vector `accept-reached-host-idn`).

   Note: this conversion is Python's `idna` codec (`name.encode("idna")`), which takes unassigned code points because
   it does not check Nameprep's table A.1.

**A claim's or an effect's host** is a name or address, maybe with a port. It won't parse if it is not a string, if
it holds `/`, `\`, `?`, `#`, `@`, `[`, `]` or white space (section 2), if it holds a deviation character
(step 3), or if it has exactly one `:` and what follows it is not 1 to 5 ASCII digits (`api.example.com:abc`,
`api.example.com:`; vector `accept-unproven-reached-host-claim-bad-port`). Otherwise it is read as the host of the
URL `http://[<host>]/` when it has more than one `:` (a bare IPv6 address), else `http://<host>/`, by steps 2 to 4,
except that the two readings are not compared: the browser's reading counts. So the claim `api.example.com:443` is
`api.example.com` (vector `accept-reached-host-claim-port`).

Where IDNA 2003 and UTS 46 [UTS46] still differ, PCM 0.1 follows IDNA 2003 (step 4): an `xn--` label is not checked to
be valid Punycode, `_` is allowed, unassigned code points are taken, ZWSP, soft hyphen and the other characters Nameprep
maps to nothing are dropped (`exam` U+00AD `ple.com` is `example.com`), and Nameprep uses Unicode 3.2. A verifier MUST
implement the steps above as written, not UTS 46. Senders SHOULD claim hosts in ASCII, as DNS names them.

### 6.8 Test commands (decided, 0.1)

A `tests_passed` suite is a **test command** when all of these hold. Rationale: every verifier must recognise the same
commands, so the list is part of the protocol, not a guess at what a command does; the suite must read the same to
every verifier and to `sh`, so it may hold nothing on which a shell and a word splitter can differ; and a flag that
runs no tests must not prove that tests passed. **[Implemented]**

1. **Plain words (decided, 0.1).** `suite` MUST NOT hold any of the characters `;` `&` `|` `(` `)` `<` `>` `$` `` ` ``
   `\` `#` `{` `}` `*` `?` `[` `]`, nor a control character (section 2) other than tab, nor U+007F (DEL): so no
   operator, background `&`, redirection, expansion, escape, comment, brace expansion, glob or second line. Its quotes
   MUST balance: each `'` or `"` outside quotes opens a quote that the next same character closes. Split it into words
   at the spaces and tabs outside quotes; the quote characters are removed, and what they enclose, spaces and tabs too,
   stays in its word (`a"b c"d` is the one word `ab cd`, and `""` alone is an empty word). Note: this is how `sh` and
   Python's `shlex.split` split such a line. Rationale: an earlier draft cut a line at operators with a word splitter
   that reads `$'\''` apart from `sh` (`pytest $'\'';true #'` is one command to it and `pytest "'"; true` to `sh`), kept
   `pytest &` and `(pytest &)` as one command, and let a glob or brace expansion turn into a flag in the working
   directory (`pytest -[h]`). With none of these characters, inside double quotes nothing is special, and every splitter
   reads the same words as `sh`. Vectors `reject-claim-tests-passed-background`,
   `reject-claim-tests-passed-ansi-c-quote`, `reject-claim-tests-passed-unbalanced-quote`,
   `reject-claim-tests-passed-comment`, `reject-claim-hash-inside-word`, `reject-claim-pytest-or-true`.
2. **A listed runner.** The words MUST begin with one of these word sequences, compared exactly, so the first word is
   a bare program name a shell looks up on `PATH` (`./pytest`, `/tmp/x/pytest` and `.venv/bin/pytest` are not
   `pytest`; vectors `reject-claim-tests-passed-dot-slash`, `reject-claim-tests-passed-runner-path`). The list is
   deliberately strict (no `./gradlew test`, `./mvnw test`, `gmake test`, `make tests`, `npm t` or
   `npm run test:unit`):

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
(`schemas/grant.schema.json`). **[Implemented]**

| Member | Value |
|---|---|
| `pcm_grant` | the integer `0` |
| `ts` | TS, when the signer signed it |
| `issuer` | `{"kind": "person" \| "agent", "id": string <= 256, "person"?: string <= 256, "run": ID, "tenant": ID, "approval_id"?: ID}`, closed. `tenant` is the issuing run's tenant. A root grant's issuer (`kind: "person"`) carries `person`, the name the signer's approvals configuration gives the approver (7.4); a child's (`kind: "agent"`) has none. |
| `subject` | IDENTITY, who may use the grant |
| `intent` | SCHEMA_REF |
| `caveats` | at most 16 `{"field", "op", "value"}`; `field` at most 64, `^[a-z][a-z0-9_]*$`; `op` one of `==` `<=` `>=` `<` `>` `in` |
| `expires_at` | TS |
| `delegable` | boolean: may the subject pass it on, only narrower |
| `parent` | `null` for a root grant, else `H(parent grant)`, the hash of the full signed parent including its `sig` |
| `sig` | as in 4.3, with TAG `pcm.grant.v0` |

The root grant of `accept-approved-by`, signed after alice approved it:

```json
{"pcm_grant": 0, "ts": "2026-10-27T18:03:28.020197Z",
 "issuer": {"kind": "person", "id": "uid:990001", "run": "ca4ca057363ca9d4028c7dd8b6bc5084", "tenant": "default",
            "approval_id": "apr-1d2c2e92bc8d5d9eeef19ecfd943aa94", "person": "alice"},
 "subject": "uid:990101",
 "intent": "refund.request@sha256:d8636b6fbbd07430d057ea9ead9c27f0df1b918b10d34ab9257a4971d487846c",
 "caveats": [{"field": "amount", "op": "<=", "value": 20000}, {"field": "order", "op": "==", "value": 81}],
 "expires_at": "2026-10-27T19:03:28.017815Z", "delegable": false, "parent": null,
 "sig": {"key": "example.com/pcm-test-log+0bb91e66",
         "sig": "3WA/xsSrUSzDwrt17cpjSSswaWhFQ/27SWU5AgeoMzwp1EuGI8fC7+prsC6yHlx79CW7oL2Z0PuKALUIrXYmAw=="}}
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

For example, against `refund.request` (the detail strings are informative):

```
amount in [1, 2]: in does not apply to a money field
note == "x": no field note in refund.request
amount <= 20000.0: not a valid money value
```

For comparison, each caveat is rewritten as one of `== v`, `in S`, `<= b`, `>= b`: `< b` (an integer) becomes
`<= b-1`, and `> b` becomes `>= b+1`.

**Args satisfy a caveat** when the field is present in `intent.args` and the single-value caveat `== args[field]`
implies the caveat by the table in 7.3. So types must match exactly: `true` does not pass `<= 5`, and `"81"` does not
pass `== 81`. A missing field never passes. A signer need not know the intent's schema document, so it can sign a
grant whose caveat value has another JSON type than its field; a verifier rejects it twice over, as no valid caveat
and as one no args satisfy (vectors `reject-grant-caveat-string-for-int`: `order == "81"`; `reject-grant-caveat-bool-for-int`:
`order == true` with order 1, which a comparison that converts would pass).

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

Consequences (parent `amount <= 20000, order == 81`):

| Child | Result |
|---|---|
| `amount <= 15000, order == 81` | narrows |
| `amount < 20001, order == 81` | narrows (`<` is `<=` one lower; vector `accept-delegation-less-than`) |
| `amount <= 15000` | `order == 81: dropped or widened` (missing counts as widening) |
| `amount <= 30000, amount >= 100, order == 81` | `amount <= 20000: dropped or widened` (widen and tighten fails) |
| `amount <= 20000, order >= 81, order <= 81` | `order == 81: dropped or widened` (bounds never imply an equality) |
| parent `k in ["a","b"]`, child `k in ["a","b","c"]` | `k in ["a", "b"]: dropped or widened` |

Vectors for an `in` set and a `time` bound, under a parent with `region in ["eu","us"]` and
`due <= "2026-12-31T00:00:00.000000Z"`: `accept-delegation-in-set` (child `region in ["eu"]`),
`reject-grant-in-set-widened-child` (`region in ["eu","us","apac"]`), `accept-delegation-time-bound` (child
`due <= "2026-11-30T00:00:00.000000Z"`), `reject-grant-time-bound-widened-child` (`due <= "2027-01-31T00:00:00.000000Z"`).
A `time` value compares as a string (3.2).

Also: the intent is fixed (a child is for its parent's intent), and expiry only shrinks (a child's `expires_at` is
no later than its parent's).

### 7.4 Root grants come from a person

A caveat-free grant is the widest grant. So a root grant (`parent: null`) MUST come from a person's approval. A
signer MUST refuse to issue a root grant unless all of these hold **[Implemented]**:

- the signer has an approvals configuration that names who may answer, so an answer comes from a named person;
- the agent made a tool call `pcm.grant` whose args are exactly the grant's `subject`, `intent`, `caveats`,
  `expires_at` and `delegable`, and that call was approved and the approval consumed with exactly these args;
- the approver is a person, not an agent approver; not the run's own agent (self-approved); not the grant's subject;
- the approvals configuration maps the approving identity to a person's name: an identity it lets answer but names
  no person for (an OIDC subject included) can't approve a root grant;
- `expires_at` is after now and at most 24 hours from now;
- the `pcm.grant` call has no result yet (one grant per approval: section 14.8);
- the run is not held or quarantined.

The grant's `issuer` is `{"kind": "person", "id": <approver identity>, "person": <the name the approvals configuration
gives>, "run", "tenant", "approval_id"}`. A policy that does not ask a person about `pcm.grant` leaves nothing to
consume, so no root grant can be made (fail closed).

The signer SHOULD record each grant it signs as a record in the issuing run, as it does for messages (4.4), holding
the grant's hash, subject and intent, and the approval id (a root) or the parent's hash (a child).

### 7.5 Delegation

`delegable` is the approving person's choice: they see it in the args they approve. The subject of a delegable grant
MAY ask the signer for a child. A signer MUST refuse a child unless **[Implemented]**:

- the parent verifies under this signer's own log key;
- the parent's `issuer.tenant` is the caller's tenant (no cross-tenant delegation);
- the caller is the parent's `subject`;
- the parent is `delegable`;
- the parent has not expired, and the child's `expires_at` is after now and no later than the parent's;
- the child's caveats narrow the parent's (7.3).

The child gets `issuer: {"kind": "agent", "id": <the caller>, "run", "tenant"}`, the parent's `intent`, `parent:
H(parent)` and its own `delegable`. A child needs no approval, since it only narrows.

### 7.6 Chain rules

`grants` is the chain, root first. A verifier checks it against the intent's schema document. Each failing rule adds
one problem; any problem makes the grants result `failed`. **[Implemented]**

| Rule | Check | Vectors (`reject-` left out) |
|---|---|---|
| needed | no grants: result `none`, or `failed` ("the intent needs a grant") when the document has `grant: true` | `grant-needed` |
| signature | every grant's `sig.key` equals the message's `sig.key` ("signed by …, not the log that signed the message"), and the grant verifies (4.3) with TAG `pcm.grant.v0` under that pinned key (14.18) | `grant-tampered`, `grant-unpinned-key`, `grant-from-another-log` |
| intent | every grant's `intent` equals `intent.type` | `grant-other-intent` |
| caveats | every grant's caveats are valid for the intent's document (7.2) | `grant-bad-caveat` |
| expiry | the message's `ts` is not after any grant's `expires_at` (a message signed at `expires_at` passes) | `grant-expired`; `accept-grant-expires-at-ts` passes |
| tenant | every grant's `issuer.tenant` equals `from.tenant` | `grant-cross-tenant` |
| args | `intent.args` satisfies every caveat of every grant, not only the last | `grant-amount-over-caveat`, `delegation-over-child-cap`, `grant-caveat-string-for-int`, `grant-caveat-bool-for-int` |
| root | grant 0 has `parent: null`, `issuer.kind == "person"`, an `issuer.person` that is not empty, and `issuer.id != subject` | `grant-root-with-parent`, `grant-root-by-agent`, `grant-root-without-person`, `grant-issuer-is-subject` |
| link | each later grant's `parent` is `H(the grant before it)` | `grant-broken-parent` |
| delegable | the grant before each later grant is `delegable` | `grant-below-non-delegable` |
| who delegates | each later grant's issuer is `{"kind": "agent", "id": <the previous grant's subject>}` | `grant-child-wrong-issuer` |
| expiry shrinks | each later grant's `expires_at` is no later than the previous grant's | `grant-child-outlives-parent` |
| narrows | each later grant's caveats narrow the previous grant's (7.3) | `grant-widening-child`, `grant-widen-and-tighten-child`, `grant-missing-caveat-child`, `grant-in-set-widened-child`, `grant-time-bound-widened-child` |
| subject | the last grant's `subject` equals `from.agent` | `grant-subject-not-sender` |

The result is `{"result": "none" | "ok" | "failed", "steps": <number of grants>, "root": <grant 0's issuer kind, id
and person> or null, "problems": [...]}`. A problem from the refund example, a $500 refund under a $200 grant:
`grant 0: amount 50000 breaks amount <= 20000`.

The verifier reports the root issuer but does not decide whether the receiver trusts that person. A receiver SHOULD
check `grants.root` against the people it accepts.

## 8. Verification algorithm

Inputs: the message (parsed as in 3.3), the trust anchors (section 10), the schema documents the receiver agreed on,
and optionally the receiver's replay state, the receiver's own identity `me`, the flag `strict`, and the time `now`.

Output **[Implemented]**:

```json
{"verdict": "accept" | "accept-unproven" | "reject",
 "signature": {"ok": bool, "key": string} | null,
 "replay": {"ok": true | false | null, "detail": string} | null,
 "schema": {"ok": bool, "ref": string, "errors": [string]} | null,
 "grants": <7.6 result> | null,
 "claims": [{"type", "result", "detail"}] | null,
 "reasons": [string],
 "skipped": [string]}
```

**Skipped checks (decided, 0.1).** `skipped` lists the checks the caller did not ask for, in this order: `"replay"`
when no replay state was given, `"recipient"` when `me` was not given. It is in every result, a rejected envelope's too
(vector `accept-skipped-replay-and-recipient`: neither given). A result whose `skipped` is not empty is an audit
result: a receiver MUST NOT act on it (9). Rationale: an `accept` without the replay or recipient check says less than
one with them, and the result itself must say so, not only the caller's memory of how it called.

Steps, in this order:

1. **Envelope.** The message MUST match section 3.2. If not: `reject`, every other part `null`, reasons
   `envelope: …`. Stop.
2. **Signature.** Verify `sig` as in 4.2 and 4.3 with TAG `pcm.message.v0`. If it fails: `reject`, `signature.ok`
   false, the later parts `null`. Stop. No claim work is done for a forged message.
3. **Schema.** Check every given schema document (5.2; a bad one is a configuration error). Find the document whose
   reference equals `intent.type`, and check the args (5.3).
4. **Recipient, then replay.** If `me` is given and `to.agent != me`, the replay part fails with "addressed to
   <to.agent>, not <me>", and the replay state is neither checked nor changed. Else, if replay state is given, check
   it (section 9); it records the message only when step 3 found no error. With neither: `{"ok": null, "detail": "not
   checked"}`.
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
 "claims": [{"type": "approved_by", "result": "proven", "detail": "approval seq 5 by alice of pcm.grant call grant-1"}],
 "verdict": "accept", "reasons": [], "skipped": []}
```

Each step stops a different vector: the envelope `reject-envelope-pcm-false` ("envelope: $.pcm: expected integer,
got bool"), the signature `reject-forged-signature` and `reject-unpinned-key`, replay `reject-replay-duplicate-nonce`,
the recipient `reject-wrong-recipient`, the schema `reject-schema-bool-as-int`, the grants
`reject-grant-amount-over-caveat`, a claim `reject-claim-changed-record-hash`, and `strict`
`reject-strict-required-unproven`.

## 9. Replay and recipient checks

Replay state is per receiver. A receiver keeps one replay state for its whole life and passes every message through
it. **[Implemented]** Parameters: `window_s` (default 300 seconds; `null` for an auditor reading a saved
conversation), `per_sender` (default 4096), and `started`, the time the state was created.

**The sender (decided, 0.1).** A sender is the pair (`sig.key`, `from.agent`), never `from.agent` alone. Rationale:
an identity is a name inside one signer, so `uid:990101` of one log and `uid:990101` of another are two senders, and
one must not raise the other's floor or spend its nonces. **[Implemented]** (vector
`accept-replay-same-agent-other-log`: a message of the other log with the same agent name and the same nonce was seen
first, and this one still passes.)

For a message whose signature passed, with `t = ts` and `sender = (sig.key, from.agent)`:

1. If `ts` names no real time (3.2): refuse ("which is no real time").
2. If `window_s` is set: refuse when `|now − t| > window_s` ("more than … s from this receiver's clock"); refuse when
   `t < started` ("sent before this receiver started: ask for it again").
3. Refuse when `t <= floor[sender]` ("older than the messages this receiver remembers from the sender").
4. Refuse when `nonce` is in `seen[sender]` ("replayed: this nonce was seen before").
5. Else, if the message is to be recorded (below), append `(nonce, t)` to `seen[sender]`; either way it passes
   ("fresh"). Entries stay in the order the messages arrived, not in `ts` order.
   If `window_s` is set: while the first entry's `t` is older than `now − window_s`, remove it (the window refuses it
   anyway); stop at the first entry that is not. Then, while `seen[sender]` has more than `per_sender` entries,
   remove the first and set `floor[sender]` to the larger of the floor and its `t`.

The order matters. With `per_sender` 1 and no window, a receiver that takes the messages signed at :05 and then :01
removes :05 and sets the floor to :05, so it then refuses one signed at :03. A receiver that removed the smallest
`ts` would accept it. Vector `reject-replay-floor-arrival-order` pins this.

Refusing messages signed before the receiver started is what lets a receiver restart with no saved state. The sender
asks again.

A receiver that acts on a message MUST check it with its replay state. Grant expiry is judged at the message's `ts`
(7.6), not at the receiver's clock, so without replay state a message captured while its grant was valid stays `accept`
forever. Verifying without replay state, as a command-line audit does, is for audit only and MUST NOT lead to action.

**One acceptance per receiver (decided, 0.1).** A receiver MUST accept each (sender, `nonce`) at most once within
its window, per receiver identity (`me`), across every replica or process that answers for that identity. How
replicas share the state (one store, a database, routing each sender to one replica) is implementation-defined.
Rationale: a replica that keeps its own state takes a message another replica already took, so a captured message
could be acted on once per replica (14.14).

The recipient check: a receiver MUST pass its own identity as `me`. A message addressed to another fails ("addressed to
uid:990102, not uid:990103").

**Which messages spend their nonce (decided, 0.1).** The recipient check runs before the replay check, and a message
it fails leaves the replay state as it was. The replay check records a message (step 5) only when its schema check
passed. A message rejected for its grants or claims is recorded all the same. Rationale: a message addressed to
another receiver is not this receiver's to spend, and one whose schema the receiver lacks or refuses may come again
once the receiver has the right document; a message rejected for its grants or claims would be rejected again, so
spending its nonce costs nothing. Vectors `accept-replay-misaddressed-spends-no-nonce`,
`accept-replay-schema-rejected-spends-no-nonce`, `reject-replay-grant-failure-spends-nonce`.

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
| `logs` | yes | one or more log vkeys (4.3), one Ed25519 key per log name. They verify messages, grants and evidence checkpoints. |
| `witnesses` | no | witness keys, each `{"name", "vkey"}`, the vkey of type 0x04 (C2SP tlog-cosignature). Default none. |
| `witnesses_required` | no | how many pinned witness cosignatures each evidence checkpoint needs. Default 0. |

A verifier MUST ignore members it does not know, so a trust document written for other uses too works as it is
(Appendix C gives one). A verifier reads only each witness's `vkey`; the key name inside the vkey is the one that
counts. **[Implemented]**

A trust document with any vkey in `logs` or `witnesses` that does not parse as 4.3 says (a malformed vkey, a key id
that does not match, non-canonical base64) is a configuration error. The verifier MUST report it before it checks
any message, as for a bad schema document (5.2), wherever the vkey sits in the list. Rationale: otherwise a bad vkey
listed before the key that verifies a message stops the check, and one listed after it fails only the evidence, so
the result would depend on the order of the list. **[Implemented]**

**One key per log (decided, 0.1).** A trust document MUST pin at most one Ed25519 key under each log name in `logs`.
A verifier MUST refuse a trust document that pins two or more, as a configuration error, reported like a bad vkey
before any message ("trust pins 2 Ed25519 keys of log …"). A hybrid key (below) under the same name does not count.
Rationale: PCM 0.1 declares no key rotation, so two keys under one name may be two logs; the evidence check compares
log names (6.2 step 2) while a message names its key, so two logs under one name would let one log's evidence pass for
the other's (14.1), and the replay sender (9) would split one log in two. With one key per name, the key that signed a
message names one log. To rotate a log key, replace it in the trust document (14.24). A configuration error is no
vector (13.2); the standalone verifier's tests cover this rule.

A log may also pin a hybrid key: a vkey of type 0xff whose key bytes are the ASCII text `tracekit/slh-dsa-sha2-128s`
followed by the 32-byte SLH-DSA-SHA2-128s public key [FIPS205], under the log's own name. When trust pins one, every
evidence checkpoint of that origin needs a valid SLH-DSA line from it too (its signature is over the note text, as
the Ed25519 line's). Messages and grants stay Ed25519 only (4.3). **[Implemented]** A verifier that does not
implement SLH-DSA MUST fail evidence whose origin has a pinned hybrid key, and evidence whose note carries a line of
any pinned hybrid key.

### 10.2 The tool placement table

The verifier places tools with a fixed table, `{tool name: class}`.

**The table is protocol data (decided, 0.1).** PCM 0.1's table is `registry/tools.json` in this repository, 54 tool
names, frozen: the SHA-256 of the file is `15f8410f513344e4c60327d4fc3dd14949ebeaf7722f641d985d3ca721c8fe07`. A
verifier MUST place tools with exactly this table, which it ships, and MUST NOT take a table from a message, a bundle,
a sender or its operator. For example `Bash`, `bash`, `shell` and `container.exec` are `shell`; `WebFetch`, `fetch`
and `http_get` are `http`. A tool not in the table is unplaced, so a custom shell or http tool gives `unproven` until a
later PCM version adds its name. Rationale: two verifiers with different tables give one claim different results, so
the table is part of the protocol, like the runner list of 6.8; an earlier draft derived it from an implementation's
policy packs, where adding a pack changed verdicts. **[Implemented]**

## 11. Transport bindings

PCM authenticity does not depend on the transport. Confidentiality does: use TLS. Each binding carries the message
JSON unchanged. All three bindings are **[Draft]**: no implementation carries PCM in them yet.

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

**[Draft]** No verifier implements this extension yet, and a PCM 0.1 verifier rejects a `transfer` payload at the
envelope, because `payload` is closed to `text` and `data`. That is fail-closed by design.

### 12.1 The problem

Some agents exchange model state instead of text: one model's KV cache fused into another's through a projector
(Cache-to-Cache, C2C). The bytes are large, opaque and not meant to be read. A receiver still needs to know who sent
which bytes, through which adapter, and that the sender's signer allowed it before it happened.

### 12.2 The transfer record

Before a transfer, the sender's process asks its signer to decide a call of the tool `a2a:transfer`, giving the
sender and receiver model ids, the modality, an optional projector, and the size and digest it computed from the
payload bytes. The signer records a `policy.decision` whose committed args are:

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

### 13.2 Test vectors

The vectors are in `vectors/`, produced by the reference implementation (Appendix C). `vectors/index.json` is a JSON
list of `{"name", "file", "description", "verdict"}`. Each `vectors/<name>.json` is:

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
              "reasons": [], "skipped": []}}
```

- `tools` is the table the vectors were made with: PCM 0.1's table, `registry/tools.json` (10.2), the same in every
  vector. A verifier places tools with its own copy of that table, which equals it.
- `options.replay` is `null` (no replay state) or `{"window_s": seconds or null, "started": TS, "per_sender": n,
  "seen": [earlier messages]}`. The verifier creates one replay state with these parameters and verifies each message
  of `seen` in order with it (same trust, schemas, `me`, `strict` and `now`; their results are ignored, and each is
  recorded or not as section 9 says: not when its signature, recipient or schema check fails), then verifies
  `message`. `now` is the receiver's clock for all of them.
- `expected` is the full result the reference implementation returned for that input.

A trust document or schema document the verifier must refuse as a configuration error (5.2, 10.1) is no vector: it
has no result to compare. Those rules are covered by the standalone verifier's tests.

**Conformance rule.** A verifier conforms on a vector when its `verdict`, `signature.ok`, `replay.ok`, `schema.ok`,
`grants.result`, every `claims[i].result` and `skipped` equal the expected ones (a part that is `null` in `expected`
must be absent or `null`). The `detail`, `reasons` and `problems` strings are for people, not compared.

A vector is a Level 2 vector when any claim of its message carries `evidence`; otherwise it is a Level 1 vector. A
verifier conforms to a level when it conforms on every vector of that level.

## 14. Security considerations

Each item below is an attack or a mistake found while building or reviewing the reference implementation, or an
assumption PCM rests on, with the rule that closes or bounds it.

1. **Cross-log evidence replay.** An agent on another signer reused a victim's run id and tenant, then replayed the
   victim's evidence in its own messages. Run ids are chosen by clients and are unique only per log. **Rule:** the
   evidence checkpoint's origin MUST equal the log name of the key that signed the message (6.2 step 2), and a trust
   document pins one key per log name (10.1). Within one log, records must be of the sender's run and tenant (6.2
   step 4.3). Vectors: `reject-claim-evidence-from-another-log`, where trust pins both logs;
   `reject-claim-evidence-from-another-run`, `reject-claim-evidence-from-another-tenant`. Grants and replay state have
   the same problem: 14.18.
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
5. **Key reuse.** The log key signs checkpoints and also PCM messages and grants. **Rule:** domain separation by the `t`
   tag. The tags `pcm.message.v0` and `pcm.grant.v0` differ from every other purpose the key or the signer signs, and
   the signed bytes are a JCS object, which starts with `{` and holds no raw line break, so they can never parse as a
   checkpoint note's text. PCM 0.1 signs with the log key (4.5), so a fault in PCM signing that exposes the key means
   rotating the log key (14.24); a key for messages and grants only is future work (Appendix B question 2). Vector:
   `reject-grant-signature-as-message`.
6. **Person-rooted grants.** A caveat-free grant is the widest grant. **Rule:** a root grant MUST come from a person's
   approval, never an agent approver's, never self-approved, never by the grant's subject, and only from an approver
   the signer's approvals configuration names a person for; the signer MUST require an approvals configuration (7.4).
   The verifier MUST reject a root whose issuer kind is not `person`, that names no person, that has a parent, or
   whose issuer is its subject (7.6). Vectors: `reject-grant-root-by-agent`, `reject-grant-root-without-person`,
   `reject-grant-root-with-parent`, `reject-grant-issuer-is-subject`.
7. **Delegation.** **Rule:** `delegable` is set by the approving person. A non-delegable grant cannot be passed on, by
   the signer or in a chain a verifier accepts. Children only narrow (7.3): a missing caveat is widening; widening one
   caveat while tightening another fails; an equality is narrowed only by the same equality; enum sets shrink only by
   subset; a time bound only tightens; expiry only shrinks, and a signer makes no child that has already expired
   (7.5); the intent is fixed. Vectors: `accept-delegation-narrowing`, `accept-delegation-less-than`,
   `accept-delegation-in-set`, `accept-delegation-time-bound`, `reject-delegation-over-child-cap`,
   `reject-grant-below-non-delegable`, `reject-grant-widening-child`, `reject-grant-widen-and-tighten-child`,
   `reject-grant-missing-caveat-child`, `reject-grant-in-set-widened-child`, `reject-grant-time-bound-widened-child`,
   `reject-grant-broken-parent`, `reject-grant-child-outlives-parent`, `reject-grant-child-wrong-issuer`.
8. **One grant per approval.** **Rule:** the signer MUST refuse a second root grant once the `pcm.grant` call has its
   result. A signer that does not also track grants per approval can, until then, mint more grants from the same
   consumed approval, the same but for `ts` (the reference implementation is one: Appendix C).
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
    evidence; a `Write` of a relative path is `unproven`, never `proven` (6.6). An earlier draft read every `\` as
    `/`, so a Write of the POSIX file `/work\report.txt` (one file named `work\report.txt` in `/`) proved
    `/work/report.txt`. **Rule:** a path from `/` is read by POSIX rules, a drive path by Windows rules, and a drive
    path is proven only by a call of its very string, since the record does not say which system ran the call (6.6).
    Vectors: `accept-file-written`, `reject-claim-file-written-wrong-digest`, `reject-claim-file-written-dotdot`,
    `reject-claim-file-written-relative`, `reject-claim-file-written-relative-no-evidence`,
    `accept-unproven-file-written-relative-call`, `reject-claim-file-written-backslash`,
    `accept-unproven-file-written-drive-separators`, `accept-file-written-drive-path`.
12. **Hostile input.** A pinned log can be hostile, and a caller can pass any object. **Rule:** a verifier MUST NOT
    crash on hostile input: args that are not an object, wrong JSON types, invalid or non-canonical base64, non-ASCII
    proof entries, events that are not objects or not valid events of the profile, records without a field a checker
    reads, a `ts` that is no real time, values nested deeper than the recursion limit where an error message would show
    them (an error names a deep list or object by its type, never by its text). Each is a `failed` claim or a `reject`;
    a verifier returns a verdict for every message and never fails with an error. Integer `const` checks MUST reject
    `false` and `0.0`. Envelope and claim-arg patterns MUST match the whole value and use ASCII classes (`[0-9]`, not
    Unicode digits); a schema's own `id` patterns are its author's, in a dialect 0.1 does not fix (5.2). Public keys
    MUST be checked as in 4.3. Vectors: `reject-envelope-pcm-false`, `reject-envelope-extra-field`,
    `reject-schema-bool-as-int`, `reject-schema-int-as-string`, `reject-schema-field-types`,
    `reject-claim-reached-host-too-long`, `reject-small-order-key`, `accept-jcs-payload`,
    `reject-sig-non-canonical-base64`, `reject-claim-proof-non-canonical-base64`, `reject-claim-record-not-an-event`,
    `reject-claim-decision-without-id`, `reject-replay-no-real-time`. Non-object args, non-object events and deep values
    are covered by the standalone verifier's tests, not by vectors: a signer never makes them, and a value past the
    recursion limit is no portable JSON.
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
    **Rule:** the signer hands out salts only to the run's own agent, for the records it names. A
    sender MUST NOT send a salt for a decision it does not open, and opens only the decisions it chooses to show. (A
    verifier also fails a record that has one of `salt` and `args` without the other: vector
    `reject-claim-salt-without-args`.) See section 15.
17. **No revocation.** PCM 0.1 has no revocation: a grant holds until `expires_at`. **Rule:** the signer MUST cap a
    grant's lifetime (24 hours, 7.4); a verifier checks expiry against the signer-set message `ts`, not the
    receiver's clock, so a later audit reaches the same answer. So a receiver that acts MUST also check replay
    (section 9): else a captured message stays `accept` after its grant expired. Grant per task, not per agent.
    Vector: `reject-grant-expired`.
18. **Cross-log grant replay.** Identities and tenants are names inside one signer: the default tenant is `default`
    everywhere, and `uid:990101` on one host is not `uid:990101` on another. When a grant was checked under any pinned
    log key, a grant signed by log X could ride in a message signed by log Y, sent by an agent on Y whose identity
    string is the grant's subject; anyone who saw the grant could hand it on. **Rule:** every grant in a chain MUST be
    signed by the key that signed the message (7.6), and a sender is the pair (`sig.key`, `from.agent`), never
    `from.agent` alone (section 9, decided 0.1). A signer delegates only grants it signed itself (7.5). Vectors:
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
24. **Key compromise and rotation.** Whoever holds a log key a receiver pins is that log's signer to the receiver.
    They can sign messages as any identity, run and tenant of the log, with any `ts` and `nonce`, so neither the
    replay window nor grant expiry holds them back; root grants with any issuer, caveats and expiry (the 24-hour cap
    of 7.4 binds only an honest signer: a verifier does not check how long a grant lives); and checkpoints over
    records they made up, so evidence proves whatever they wrote. PCM 0.1 signs all three with the one log key (4.5),
    so a leak of it forges all three (Appendix B question 2). Witnesses (10.1)
    help with checkpoints only: with `witnesses_required` set, forged evidence needs a checkpoint the witnesses
    cosigned, which they give only to a log consistent with the one they saw, so a forgery either fails or forks the
    log in a way the honest signer's next checkpoint exposes. Messages and grants carry no cosignature. PCM 0.1 has
    no revocation and no key validity period: a pinned key verifies until the receiver removes it, and the `ts` of a
    forged message, which the key's holder chose, can't tell it from an honest one. **Rule:** a receiver that learns
    a pinned key leaked SHOULD remove it from its trust document at once, which fails every message and grant the key
    signed, honest ones too (their senders ask for new grants), and SHOULD treat what it accepted under that key
    since the leak as unverified, dating messages by its own record of when they arrived, not by `ts`. PCM 0.1
    declares no rotation: a trust document pins one key per log name (10.1). To rotate a key that did not leak,
    switch the signer to the new key and replace the old key with the new one in each receiver's trust document.
    From then on whatever the old key signed fails there: its senders ask for new grants and send again, and the
    signer's next checkpoints, signed with the new key, cover the old records too, so evidence can be made again. A
    receiver that still pins the old key refuses what the new key signs until it switches. An auditor checks old
    messages with a trust document that pins the old key.
25. **The signer is the trusted computing base.** Every guarantee in this document rests on the signer: that it signs
    only as the calling run (4.4); that it alone sets a message's `id`, `ts` and `nonce` and assigns each record's
    `seq` in its log; that it sets a record's `source` and `tier`, and writes approvals and effects, only from callers
    it authenticated (6.4); and that no agent can read its keys or write its log. A verifier checks that the signer
    signed, never that the signer was right. A compromised signer, or a caller that can make it sign as another
    identity, can mint anything: messages as any run of its log, root grants with no person behind them, and records
    and checkpoints that prove any claim. Witnesses do not change this: they check that the log does not fork, not
    what the signer appends to it. **Rule:** an agent MUST NOT be able to read the signer's keys or write its log
    (2, 4.4); a deployment SHOULD run the signer as another user, on another host or in another trust domain than the
    agents it records, with every caller authenticated by the transport (2, Identity); and a receiver SHOULD pin a
    signer's keys only as far as it trusts that signer and its operator.
26. **A T2 tool's name stands for its class.** A verifier places a call by its tool name (6.5) and takes a T2 result
    as the attesting party's word on what ran. An executor that runs actions its operator names, such as HTTP
    actions, can record an HTTP request under the name `Bash`: the table places it as `shell`, its result is `ok`
    when the request succeeded (Appendix C), and a `tests_passed` claim whose suite equals the call's `command` arg
    is `proven` though no runner ran. **Rule:** a log that offers the evidence profile MUST NOT record, under a tool
    name the placement table places, a tool of another class (6.4), so an operator does not name an executor action
    after a placed tool. Future work: a trust member that pins which attesting parties (`data.via`) may attest each
    tool class, so a receiver need not trust every executor of a pinned log (Appendix B question 4).
27. **An approval of a call the agent named.** The agent names its calls: it can decide a `read_file` call under the
    id `refund-81-approved`, have a person approve it, and claim that the person approved `refund-81-approved`. An
    earlier draft proved `approved_by` from the approval record alone, so the claim was `proven`, and nothing in the
    result said what was approved. **Rule:** `approved_by` needs the `approval.request` the approval answers and the
    `policy.decision` that request names, and a proven claim's detail names the decision's tool and, when opened, its
    args in full; a receiver reads them (6.6). An agent that decided two calls under one id can't pass the approval
    of one off as the other's, since the request names one decision. Vectors:
    `reject-claim-approved-by-without-decision`, `reject-claim-approved-by-other-decision`.
28. **An attempt is not a connection.** A kernel sensor reports a process's call to connect, and an egress observer
    records a minute with no connection when its connect upstream failed; an earlier draft took either as proof that
    the run reached the host. **Rule:** only an egress observer's `net` record with `data.connections` above 0
    proves `reached_host`; a `connect` record or a `net` record with none gives `unproven`, and a denied `connect`
    gives nothing (6.6). Vectors: `accept-unproven-reached-host-no-connection`,
    `accept-unproven-reached-host-sensor-connect`, `reject-claim-reached-host-denied-connect`.
29. **A placement table that moves.** An earlier draft took the table of 10.2 from the tool names an implementation's
    policy packs mapped, so a pack added or edited changed which calls were placed and so the verdicts of messages
    already sent; two verifiers of different versions disagreed. **Rule:** PCM 0.1's table is frozen protocol data
    with a stated digest, and a verifier uses exactly it (10.2).

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
| `tests_passed` | `suite` | 6.6 | [Implemented] |
| `approved_by` | `person`, `call` | 6.6 | [Implemented] |
| `reached_host` | `host` | 6.6 | [Implemented] |
| `file_written` | `path`, `digest` | 6.6 | [Implemented] |

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
| `text` | [Implemented] |
| `data` | [Implemented] |
| `transfer` | [Draft], section 12 |

### 17.6 Evidence profiles

| Name | Defined in | Status |
|---|---|---|
| `tracekit.event.v2` | 6.4 | [Implemented] |

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
- [RFC3986] Berners-Lee, T., Fielding, R., Masinter, L., "Uniform Resource Identifier (URI): Generic Syntax", STD 66,
  RFC 3986, 2005.
- [RFC4291] Hinden, R., Deering, S., "IP Version 6 Addressing Architecture", RFC 4291, 2006.
- [RFC5952] Kawamura, S., Kawashima, M., "A Recommendation for IPv6 Address Text Representation", RFC 5952, 2010.
- [UAX15] Unicode Standard Annex #15, "Unicode Normalization Forms", https://www.unicode.org/reports/tr15/

### 18.2 Informative

- [A2A] Agent2Agent (A2A) Protocol, https://a2a-protocol.org/
- [MCP] Model Context Protocol specification, https://modelcontextprotocol.io/specification
- [RFC9110] Fielding, R., Nottingham, M., Reschke, J., "HTTP Semantics", RFC 9110, 2022.
- [WHATWG-URL] WHATWG, "URL Standard", https://url.spec.whatwg.org/
- [UTS46] Unicode Technical Standard #46, "Unicode IDNA Compatibility Processing", https://www.unicode.org/reports/tr46/
- [RFC6838] Freed, N., Klensin, J., Hansen, T., "Media Type Specifications and Registration Procedures", RFC 6838, 2013.
- [Tracekit] Cygnux Labs, Tracekit, https://github.com/Cygnux-Labs/Tracekit (the reference implementation,
  Appendix C).
- [C2C] "Cache-to-Cache: Direct Semantic Communication Between Large Language Models", 2025 (the latent transfers
  of section 12).

## Appendix A. Design choices

Earlier designs of PCM made other choices in these places. This draft settles each one as shown; an implementation
built from an earlier design changes to match.

- **Signature tags.** `pcm.message.v0` and `pcm.grant.v0` (4.2), bound to the wire version (16), not tags named after
  one product.
- **Media type.** `application/vnd.pcm+json` (3.1), not one in a product's vendor tree.
- **Tool placement.** By a fixed table of tool names (10.2), not by the args: an opened call with a `command` member
  is not therefore a shell call, nor one with a `url` member an http call (14.3). The table is frozen protocol data,
  not derived from an implementation's policy (14.29).
- **Signing key.** The log's one pinned key signs checkpoints, messages and grants (4.5, 10.1), not a dedicated PCM
  key pinned beside it under the log's name.
- **`approved_by`.** Proven by the approval with its request and decision, and the detail names what was approved
  (6.6, 14.27), not by the approval alone.
- **`reached_host`.** Only by a connection an egress observer saw opened (6.6, 14.28), not by an attempt.
- **`file_written` paths.** By POSIX or Windows rules, picked by the claim's path (6.6), not with every `\` read as
  `/`.
- **Nonces.** Spent only by a message whose recipient and schema checks pass (9), not by every message whose
  signature verifies.
- **Root grants.** Only from a person's approval (7.4), never from an agent approver.
- **Grant issuer tenant and `delegable`.** Both required in every grant (7.1).
- **Evidence origin.** Evidence must come from the sender's run and from the log that signed the message (6.2 step 2,
  14.1), not from the sender's run alone.
- **`file_written`.** The file operation is read from the tool name (6.6), never from the args.
- **`tests_passed`.** A single command from a fixed list of test runners (6.8), not a match against a test-command
  pattern.
- **Held runs.** The signer refuses held runs as well as quarantined ones (4.4, 14.9).

## Appendix B. Open issues

A review of the previous draft found an attack on its verifier rules: a `tests_passed` suite with `$'…'` quoting,
`&` or a file named like a runner was proven though its exit status was not the tests' (14.10, 14.19, 14.23). This
draft closes those; it has no other known open attack on its verifier rules. What `tests_passed` proves still rests
on the receiver reading `suite` (6.6), and what a T2 result proves rests on how the deployment names its tools (6.4,
14.26). Questions earlier drafts left open are now decided rules, each marked "(decided, 0.1)": canonical base64
(4.3), the signing key (4.5), only a configured person for `approved_by` and what it names (6.6), connections, not
attempts, for `reached_host` (6.6), absolute paths and path rules for `file_written` (6.6), host comparison,
deviation characters and a reader without the bracket check (6.7), test commands and plain words (6.8), skipped
checks (8), the sender pair, one acceptance per receiver and which messages spend their nonce (9), one key per log
(10.1) and the frozen tool table (10.2). Where the reference implementation does less than this document asks,
Appendix C.4 says so. What remains are questions for a later draft:

1. **Host reading follows particular readers** (6.7). Step 2's generic reading is what Python's `urlsplit` does, and
   it allows two bracket checks, and a stricter rule for a reader with neither, because CPython releases differ; NFKC
   runs at the verifier's Unicode version; and step 4 is IDNA 2003. A statement of the rule closer to the WHATWG host
   parser and UTS 46, with one bracket rule, is open; until then the vectors pin the cases that matter and senders
   keep to ASCII hosts and plain URLs.
2. **A key for messages and grants only, and key rotation** (4.5, 10.1). PCM 0.1 signs messages and grants with the
   log key and pins one key per log name. A trust member that pins a key for messages and grants only would let a
   fault in PCM signing leave the log key alone, and a way to declare a rotation (two keys of one log, each with the
   time from which it is valid) would let receivers rotate without a gap and give a key a validity period (14.24).
   Both change the trust document, so they wait for a later draft.
3. **The regular expression dialect of `id` patterns** (5.2) is not fixed. Schema authors keep to what ECMAScript and
   Python `re` read alike.
4. **Which attesting party may attest each tool class** (6.4, 14.26). A verifier trusts every attesting gateway or
   executor of a pinned log to record a tool only under a name of its class. A trust member that pins which
   attesting parties (`data.via`) may attest each class would let a receiver trust one executor's `shell` calls
   without trusting every action of another.

## Appendix C. Reference implementation

This appendix is informative and is not part of the protocol. It records facts about the reference implementation,
Tracekit [Tracekit], and about the standalone verifier in this repository, as of this draft. Where either disagrees
with the normative text, that is a bug in one of them: open an issue.

### C.1 What and where

- **Version.** Tracekit after 1.4.2, with its PCM 0.1 work: signer RPC contract version 20. The module `tracekit.pcm`
  holds the verifier (`tracekit.pcm.verify`), the claim checkers (`tracekit/pcm/claims.py`) and the CLI
  (`tracekit pcm verify`, `tracekit pcm demo`). The signer serves the RPC calls `pcm_sign` (4.4), `pcm_grant` (7.4),
  `pcm_delegate` (7.5) and `pcm_evidence` (6.2, 14.16) in `tracekit/signer/service.py`, with their shapes in
  `tracekit/signer/rpc_schema.py`. Its user docs are `docs/pcm.md` and the PCM 0.1 rows of `docs/limits.md`.
- **Generated files.** `tools/gen_schemas.py` writes `schemas/` from Tracekit's RPC shapes (`PCM_MESSAGE`,
  `PCM_GRANT`, ...) and `registry/tracekit.event.v2.json` from its event schema. `registry/tools.json` is not
  generated: it was made from the tool names the policy packs of Tracekit 1.4 mapped to a class, leaving out patterns
  and names two packs class differently, and then frozen (10.2). Tracekit ships the same file as
  `tracekit/pcm/tools.json`, which `tracekit.pcm.claims.placed()` reads; `tools/gen_schemas.py` stops when the two
  tables differ and copies the registry's into the standalone verifier. `tools/gen_vectors.py` writes `vectors/` by
  running a Tracekit signer and `tracekit.pcm.verify` on CPython 3.11.15 (Unicode 14.0.0), gives every vector the
  registry's table, and checks that it equals `placed()`.
- **Verifiers.** Tracekit's `tracekit.pcm.verify` and the standalone `pcm_verify` in `verifier/python` (Python, with no
  Tracekit code) are Level 2 verifiers (13.1). The standalone verifier ships a copy of `registry/tools.json` and places
  tools with it; its tests check the file's digest and that every vector carries that table. It does not implement
  SLH-DSA, so it fails evidence that needs a hybrid line (10.1). Neither CLI keeps replay state: both are for audit
  (9), and both print the skipped checks as `not checked: replay` (8).

### C.2 Where each rule lives in Tracekit

| Section | Tracekit code |
|---|---|
| 3.1 media type | `tracekit.pcm.MEDIA_TYPE` |
| 3.3 strict parsing | `tracekit.format.canon.loads_strict`; the CLI reports such input as unreadable (exit 2) |
| 4.1 JCS and `H` | `tracekit.format.canon.canonical`, `event_hash` |
| 4.2 signature tags | `tracekit.format.sigmsg.TAGS`; Tracekit's other signed objects use tags `tracekit.<purpose>.v2` (14.5) |
| 4.3 signatures | `tracekit.pcm.check_sig`; canonical base64 in `tracekit.format.checkpoint._unb64`; Ed25519 in `tracekit.crypto.verify_v2`, the rules of Tracekit's v2 evidence format |
| 5 schema documents | `tracekit.pcm.SCHEMA_DOC`, `check_schema`; a bad document makes `verify` raise `ValueError` |
| 6.2 evidence | `tracekit.pcm.claims.evidence`; notes in `tracekit.format.checkpoint.open_note` |
| 6.6 `approved_by`, `reached_host` | `tracekit.pcm.claims.approved_by`, `reached_host` |
| 6.6 paths | `tracekit.pcm.claims._path`, `malformed`, `file_written`; Tracekit's policy rules read paths with `tracekit.policy2.classes.fs_path`, which reads every `\` as `/`, so policy verdicts don't follow 6.6 |
| 6.7 hosts | `tracekit.policy2.classes.url_info`; `tracekit.pcm.claims._host`, `_a_label`, `_deviant`; the rule for a reader without the bracket check in `_old_brackets`, on when `URLSPLIT_CHECKS_BRACKETS` is false |
| 6.8 test commands | `tracekit.pcm.claims.test_command`, `TEST_RUNNERS`, `NO_TESTS` |
| 7.3 narrowing | `tracekit.pcm.narrows` |
| 7.6 grant chains | `tracekit.pcm.verify_grants` |
| 8 verification | `tracekit.pcm.verify` (an invalid envelope lists up to 8 reasons) |
| 9 replay | `tracekit.pcm.Replay`; `Replay.check(record=False)` checks without recording |
| 10.1 one key per log | `tracekit.pcm.verify`, which raises `ValueError` |
| 10.2 tool placement | `tracekit.pcm.claims.placed()`, reading `tracekit/pcm/tools.json` |

### C.3 Behaviour beyond the protocol

- **Signing.** The signer refuses a body whose `from` is not the calling run with `forbidden: the signer signs only as
  the calling run's own agent (uid:990101, run …, tenant default)`, and refuses a caller that holds the run token but
  is not the run's owner, such as a tailer or an observer (4.4). It writes an `ext` record with `name: pcm.sent` for
  each message it signs (4.4) and one with `name: pcm.grant` for each grant (7.4).
- **Root grants.** The signer refuses a root grant whose approver `approvals.persons` in `signer.yaml` maps to no
  person, with `forbidden: a root grant needs the approval of a person signer.yaml's approvals.persons names: <id>
  maps to none`; an OIDC approver that `approvals.persons` does not map is one (7.4). It refuses a child whose
  `expires_at` is not after now with `invalid_request` (7.5). No policy pack shipped with Tracekit asks a person about
  `pcm.grant`, so a deployment adds the rule itself (7.4). `docs/pcm.md` shows:

  ```yaml
  tools:
    pcm.grant: app
  ask:
    - {id: PCM-GRANT, tool: pcm.grant, pattern: "^"}
  ```
- **Trust documents.** Tracekit's `trust.json` also has `algs`, `rekor`, `monitors`, and witnesses as
  `{"vkey", "class"}`; a PCM verifier ignores what it does not read (10.1). Tracekit names a log
  `tracekit.local/<log id>` by default, which is unique, but an operator can choose any origin (10.1). After a key
  rotation, the `trust.json` Tracekit keeps for its bundles pins the log's old keys beside the new one; that one is no
  PCM trust document, and `tracekit.pcm.verify` refuses it (10.1): a receiver needs one that pins only each log's
  current key.
- **`id` patterns** run with Python `re` in its default Unicode mode, where `\d` also matches digits such as `٣` (5.2).
- **Hosts.** Tracekit reads hosts with Python's `urllib.parse.urlsplit`, `unicodedata` and `idna` codec (6.7). It still
  runs on Python 3.9, whose `urlsplit` makes neither bracket check; there it applies the rule of 6.7 for a reader
  without the check. The standalone verifier needs CPython 3.11.4 or later.
- **The tool executor** (`tracekit/executor.py`, tier T2) runs HTTP actions its operator names in its configuration,
  and records a call as `ok` when the upstream's HTTP status is under 400. A T2 call of a tool named `Bash` can
  therefore be such an action (6.4, 14.26).
- **Transports and transfers.** Tracekit's receivers call `tracekit.pcm.verify` themselves; no binding of section 11
  is built. The transfer record of section 12 is Tracekit work not yet merged, in which the SDK call
  `RunHandle.transfer` takes the payload bytes, the model ids, the modality, an optional projector and the options
  `measured` and `keep`.
- **The demo.** `tracekit pcm demo` runs the refund example of section 1 with a real signer (a separate run from the
  vectors):

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

### C.4 Where it does less than this document asks

Each is marked `lean:` in Tracekit's code and has a row in its `docs/limits.md`.

1. **Replay state is per process** (9, 14.14). `tracekit.pcm.Replay` keeps its state in memory, so a deployment with
   several replicas per receiver identity must route each sender to one replica until Tracekit shares the state.
2. **One grant per approval holds only after the call's result** (7.4, 14.8). Until the `pcm.grant` call has its
   result, repeated `pcm_grant` calls on the same consumed approval can mint grants that differ only in `ts`.
   Tracekit's SDK completes the call at once.

Also marked `lean:` in its code, though this document asks no more: messages and grants carry no SLH-DSA signature
(4.3); the deviation check covers a call's whole URL (6.7 step 3); hosts follow IDNA 2003, not UTS 46 (6.7); and the
tool table is PCM 0.1's frozen one, so a custom shell or http tool stays unplaced (10.2).
