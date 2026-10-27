# PCM 0.1 test vectors

Two verifiers must give the same verdict on the same message. Otherwise a sender can't know what a receiver will
accept. Each file here is one message, everything a verifier needs to check it, and the result Tracekit (the
reference implementation) gives. Run your verifier on every input and compare.

## Format

`index.json` lists the vectors: `[{"name", "file", "description", "verdict"}]`.

Each `<name>.json`:

```json
{"name": "reject-grant-expired",
 "description": "Signed after its root grant expired (a grant made to expire in 3 s).",
 "input": {
   "message": {"pcm": 0, "id": "…", "ts": "…", "nonce": "…", "from": {…}, "to": {…}, "intent": {…}, "sig": {…}},
   "schemas": [{"pcm_schema": 0, "name": "refund.request", "fields": {…}, "claims": ["approved_by"], "grant": true}],
   "trust": {"logs": ["example.com/pcm-test-log+0bb91e66+ASiESUZl…"], "witnesses": [], "witnesses_required": 0},
   "tools": {"Bash": "shell", "WebFetch": "http", "…": "…"},
   "options": {"me": "uid:990102", "strict": false, "now": "2026-10-27T13:35:08.912345Z", "replay": null}},
 "expected": {"verdict": "reject", "signature": {…}, "replay": {…}, "schema": {…}, "grants": {…}, "claims": […],
              "reasons": ["grant: grant 0: expired at 2026-10-27T13:35:07.676535Z"]}}
```

- `schemas`: the schema documents the receiver agreed on. The message's `intent.type` names one by
  `name@sha256:<hex>`, the SHA-256 of its JCS.
- `trust`: the pinned log keys (signed-note verifier keys), the witness keys and how many witness cosignatures each
  evidence checkpoint needs.
- `tools`: the table that places a tool name as a class (`shell`, `http`, …). It is `registry/tools.json`. A
  `tests_passed` claim needs a `shell` tool, a `reached_host` claim through a call needs an `http` tool; any other
  tool makes the claim `unproven`.
- `options.me`: the receiver's own identity, or `null` to skip the recipient check.
- `options.strict`: when true, a claim type the schema lists must be proven.
- `options.now`: the receiver's clock. Only the replay check reads it.
- `options.replay`: `null` skips the replay check (`replay.ok` is `null`). Otherwise the receiver's replay state:
  `window_s` (seconds, or `null` to skip the clock checks), `started` (when the receiver started), `per_sender` (how
  many nonces it keeps per sender) and `seen`: earlier messages. Start one fresh replay state, verify each `seen`
  message with it (same trust, schemas, me, strict and now; ignore their results), then verify `message`.

## Conformance

A verifier conforms on a vector when these match `expected`:

- `verdict`
- `signature.ok`
- `replay.ok`
- `schema.ok`
- `grants.result`
- `claims[i].result`, for every claim, in order

Where `expected` has `null` for a part (the check stopped before it), your result must have no value there too.
The `detail`, `reasons` and `problems` strings are informative: they say why, and need not match.

## How the vectors are made

`tools/gen_vectors.py` runs a real Tracekit signer in a temp dir. The signer signs every message and grant, and
writes the records that claims point to. `expected` is what `tracekit.pcm.verify` returns for the input.

Some cases can't come from the signer, because it refuses to make them: a widening child grant, a child below a
grant that can't be passed on, a root grant issued by an agent. These are a valid output edited, then re-signed with
the test log key. Envelope and signature cases are edited without re-signing. Each one's description says so.

The log, other-log and witness keys come from a fixed seed, so `trust` is the same on every run. Run ids, message
ids, nonces and timestamps come from the signer's clock and randomness, so they and the signatures change each time
the vectors are made. Nothing here depends on the date you run them: every time a verifier reads comes from the
message, the grants or `options.now`.

## Regenerate

With a Tracekit checkout:

```sh
cd <this repo>
PYTHONPATH=<tracekit checkout> python tools/gen_schemas.py   # schemas/ and registry/tools.json
PYTHONPATH=<tracekit checkout> python tools/gen_vectors.py   # vectors/
```

`gen_vectors.py` stops if a vector's verdict does not match its name (`accept-`, `accept-unproven-`, `reject-`), or
if the reasons don't name the cause the vector is for.
