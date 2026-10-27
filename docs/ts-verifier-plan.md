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
| SHA-256, base64 (strict and canonical) | `primitives.ts` `sha256`, `b64decode`, `unb64` | |
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
4. **Replay** (9): the `Replay` class with `window_s`, `started`, `per_sender`, the floor.
5. **Verdict** (8): the order of checks and the `reasons` order.
6. **Evidence and claims** (6): the note origin rule, inclusion, the sender's run, openings (HMAC-SHA256 with WebCrypto,
   compared in constant time), `Ran`, and the four checkers with the tool placement table from
   `registry/tools.json`.
7. **CLI**: `pcm-verify MESSAGE --trust TRUST --schema SCHEMA`, exit 0 accept, 3 accept-unproven, 1 reject, 2 for
   unreadable input, matching the Python verifier.

## The hard parts

Three checkers lean on Tracekit helpers that are not small. A TypeScript port must give the same answer on every
vector, so each is ported with its own tests:

- **`tests_passed`**: splitting a command line into simple commands (Python `shlex` in POSIX mode with
  `punctuation_chars`) and the test-runner recognizer (`findings_text.command_facts`). Port only what the claim needs:
  "exactly one simple command" and "its program, after wrappers, is a test runner".
- **`reached_host`**: the canonical host of a URL. `new URL()` gives the WHATWG host; Tracekit then canonicalises it
  (`classes._canonical_host`). Compare on the vectors and on Tracekit's own URL test cases.
- **`file_written`**: `fs_path` normalisation (`\` as `/`, the suffix after the last `..`). Small, but easy to get
  subtly wrong.
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
| tests_passed (shell splitting, recognizer), reached_host (URL host), file_written | 1.5 |
| CLI, package, README | 0.5 |
| **total** | **about 5 days** |

## Open choices

- Where it lives: here, as `verifier/typescript` (independent of Tracekit's release cycle), or in Tracekit's SDK
  (one npm package for users). The plan assumes here.
- Whether to publish it to npm before PCM 0.2.
