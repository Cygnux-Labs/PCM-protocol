# Plan: a TypeScript PCM verifier

## The problem

PCM has one verifier today, Tracekit's Python `tracekit.pcm.verify`, and the Python reference verifier in this repo.
Many agents run on Node.js, Deno, Bun or in a browser. They can't check a message without a Python process. A
second, independent verifier also tests the spec: where the two disagree on a vector, the spec is unclear or one of
them is wrong.

## What we can reuse

Tracekit's TypeScript SDK already has an independent v2 bundle verifier, `sdk/typescript/src/verify/` (MIT, the same
copyright). It has no dependencies and runs on WebCrypto. These parts cover PCM's primitives as they are:

| Need (SPEC section) | Tracekit TS code | Notes |
|---|---|---|
| strict parsing (3.3) | `jcs.ts` `strictParse`, `strictParseBytes` | rejects duplicate keys, unsafe integers, lone surrogates, deep nesting; its `Floats` map tells `0.0` from `0` |
| JCS (4.1) | `jcs.ts` `canonicalize` | |
| SHA-256, base64 (canonical, 4.3) | `primitives.ts` `sha256`, `unb64` | every PCM base64 value is canonical: use `unb64` for `sig.sig` and proof entries too, never the lenient `b64decode` |
| Ed25519 with the v2 rules (4.3) | `primitives.ts` `ed25519Verify`, `verifyV2` | S < L, canonical non-small-order key, as Python |
| vkeys, key ids (4.3) | `primitives.ts` `parseVkey`, `keyId` | |
| checkpoint notes, cosignatures (6.2) | `primitives.ts` `openNote` | always with `anchored` true. WebCrypto has no SLH-DSA, so a pinned hybrid key's line comes back `unchecked`: the PCM verifier must then fail the evidence, not pass it |
| inclusion proofs (6.2) | `primitives.ts` `leafHash`, `verifyInclusion` | |
| the JSON Schema subset (3.2) | `schema.ts` `check` | today bound to the event schema's `$defs`; needs a root argument to resolve `urn:pcm:0.1:schema:*` refs from `schemas/` |

We copy these files, not import the SDK, so the verifier stays small and has no runtime dependency. A header in each
copied file names its source commit.

## What is missing

About 600 to 800 lines, mapping one to one onto `tracekit/pcm/__init__.py` and `tracekit/pcm/claims.py`:

1. **Envelope and signature** (3, 4): validate against `schemas/message.schema.json`; `checkSig` with the tags
   `pcm.message.v0` and `pcm.grant.v0`.
2. **Schema documents** (5): `checkSchema`, `schemaRef`, `checkArgs` and the seven value rules. Two traps:
   - "is an int" must use the `Floats` map from `strictParse`, so `120.0` fails, as in Python's `type(v) is int`;
     the map has to reach the args, the caveat values and the event fields;
   - string lengths count code points (`[...s].length`), not UTF-16 units.
3. **Caveats and grants** (7): `checkCaveats`, `norm`, `implies`, `narrows`, `satisfies`, `verifyGrants`. Small and
   exact; the vectors cover each narrowing rule.
4. **Replay** (9): the `Replay` class with `window_s`, `started`, `per_sender`, the floor, each sender keyed by
   (`sig.key`, `from.agent`), a `ts` that is no real date refused, not thrown, and a check that does not record.
5. **Verdict** (8): the order of checks (the schema before the recipient and replay checks, so a misaddressed or
   schema-rejected message spends no nonce), the `reasons` order and `skipped`; a trust document with two Ed25519
   keys of one log is a configuration error (10.1).
6. **Evidence and claims** (6): the note origin rule, inclusion, the sender's run, each record a valid event of
   `registry/tracekit.event.v2.json`, openings (HMAC-SHA256 with WebCrypto, compared in constant time), `Ran` with
   its "can't tell" answer, and the four checkers with PCM 0.1's frozen tool table, `registry/tools.json` (10.2).
   `approved_by` links the approval to its `approval.request` and that request's `policy.decision`; `reached_host`
   is proven by an egress `net` record with connections above 0 only.
7. **CLI**: `pcm-verify MESSAGE --trust TRUST --schema SCHEMA`, exit 0 accept, 3 accept-unproven, 1 reject, 2 for
   unreadable input, matching the Python verifier.

## The hard parts

Three checkers lean on Tracekit helpers that are not small. A TypeScript port must give the same answer on every
vector, so each is ported with its own tests:

- **`tests_passed`**: SPEC 6.8: refuse a suite with any of its listed characters, split the rest at spaces and tabs
  with `'…'` and `"…"` grouping (no escapes or expansions are left to handle; unbalanced quotes refuse), then the
  words begin with one of the fixed runner sequences (first word compared exactly) and carry none of the flags that
  run no tests or their long prefixes. A table, no shell parser to port.
- **`reached_host`**: the compared form of SPEC 6.7, step by step. Don't use `new URL()` or `URL.hostname` for it:
  they apply UTS 46, which differs from the IDNA 2003 the spec fixes (the spec refuses the four deviation characters
  where the two disagree), refuse some hosts the spec reads, and know nothing of `urlsplit`'s refusals or the
  rule that a browser's and `urlsplit`'s readings must agree. Port the two readings, the canonical form and the
  A-label step as the spec writes them: the browser reading is a few regular expressions; `urlsplit(url).hostname`
  (netloc after `//` up to `/?#`, after the last `@`, before the port, lower case) and the cases where it raises
  (unbalanced `[`/`]`, a bracketed host that is no IPv6 address, a non-ASCII netloc whose NFKC form gains one of
  `/?#@:`) need their own tests; the IDNA 2003 step needs Nameprep with Unicode 3.2 tables and Punycode (a small
  vendored port; the vectors only exercise `bücher.example`, so add Tracekit's own host cases as tests).
- **`file_written`**: the path rules of SPEC 6.6 (POSIX rules for a path from `/`, where `\` is part of a name;
  Windows rules for a drive path, proven only by a call of its own string), the suffix after the last `..`, the
  absolute-path rule and the "can't tell" results. Small, but easy to get subtly wrong.
- **`id` patterns**: schema documents' patterns run as JavaScript `RegExp`. Python `re` and JavaScript differ (`\d`
  is Unicode in Python, ASCII in JavaScript). Until the spec fixes a dialect, the verifier uses the `u` flag and the
  vectors avoid patterns the two read differently.

## Tests

The vectors in `vectors/` are the test suite. One test per vector: parse `input`, build the replay state from
`options.replay` and run `seen` through it, verify `message`, and compare the conformance fields (SPEC 13.2). Level 1
vectors (no claim has evidence) pass after steps 1 to 5; Level 2 vectors after step 6. CI runs the same vectors
against the Python and TypeScript verifiers, so a vector change that one of them fails is caught.

## Effort

| Step | Days |
|---|---|
| copy and adapt the primitives, schema validator with a root | 0.5 |
| envelope, signature, schema documents, grants, replay, verdict (Level 1 vectors pass) | 1.5 |
| evidence, openings, approved_by, the `Ran` rule | 1 |
| tests_passed (shell splitting, runner list), reached_host (two host readings, IDNA 2003), file_written | 2 |
| CLI, package, README | 0.5 |
| **total** | **about 5.5 days** |

## Open choices

- Where it lives: here, as `verifier/typescript` (independent of Tracekit's release cycle), or in Tracekit's SDK
  (one npm package for users). The plan assumes here.
- Whether to publish it to npm before PCM 0.2.
