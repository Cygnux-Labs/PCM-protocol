# PCM-Lies results

How often does a receiving agent accept a false claim from a sending agent? 879 messages built from real Tracekit
signer runs, checked by Tracekit's `pcm.verify`, the standalone `pcm_verify`, plain A2A (accepts everything) and a
sender-signature-only check.

**Heads:** Tracekit `384a6042bd` (#450) and pcm `1ba784a` (this branch with main `619fbba` merged: 166 vectors,
ASCII-only hosts). This is the final run; the pre-final run is described under "Pre-final run".

## Headline

| | Tracekit | standalone | plain A2A | sender signature only |
|---|---|---|---|---|
| lies accepted as proven | 23/687 (3.3%, 95% CI 2.2–5.0%) | 23/687 (3.3%) | 687/687 (100%) | 628/687 (91.4%) |
| claim, evidence, authority and delivery lies accepted | 0/589 | 0/589 | 589/589 | 545/589 |
| honest claims proven (H2) | 71/73 (97.3%) | 71/73 | n/a | n/a |
| T1-only claims unproven (H3) | 72/72 | 72/72 | n/a | n/a |

- **H1 FAIL:** 23 false accepts in each verifier, the same 23 messages in both, all of them in three groups:
  - F1, IPv4 leading zeros: 7;
  - F2, freshness: 10;
  - F3, `approved_by` scope: 6.

  No lie in L1, L2, L4, L5–L9, L11–L15 or the other L16 groups was accepted. That includes 11 signer-bug grants.
- **H2 FAIL:** 71/73. The 2 misses are F4.
- **H3 PASS:** 72/72.
- **H4 FAIL:** 874/879. The 5 disagreements are F5.
- **H5:** plain A2A accepts every lie, and the signature-only check accepts 91.4%.
- **Cost:**
  - Message size: 4.2–6.0 KB per message with one claim against 0.4–0.6 KB plain. That is 7–13x at p50, and 16x with three claims.
  - Verify time: Tracekit p50 1.4 ms (p99 2.9 ms), standalone p50 0.9 ms (p99 1.6 ms).

## Pre-final run, and what changed

Before this run, the benchmark ran at Tracekit `e3221cf2b6` and pcm `b54cfe4` (commit `71cad5f`). That run gave the
same headline numbers, with timings of p50 1.2 ms (p99 2.0 ms) for Tracekit and p50 0.8 ms (p99 1.7 ms) for
standalone:

| hypothesis | result, both verifiers |
|---|---|
| H1 | 23/687 lies accepted |
| H2 | 71/73 honest claims proven |
| H3 | 72/72 T1-only claims unproven |
| H4 | 874/879 messages agree |

Comparing the two runs message by message (ids are stable):
- No verdict, no reason class and no claim result changed, in either verifier.
- F1–F5 are unchanged.
- Only the detail of three non-ASCII or `%` hosts changed: `L16.H.08`, `L16.H.10` and `L16.H.16` are still
  `unproven`, but now say what to fix, for example "its URL is not printable ASCII: send the URL with the host in xn--
  form…" or "its host has a %…". The two verifiers give the same text.

So the final heads' new host rules don't touch F1. A leading-zero octet is printable ASCII and has no `%`, so it is
still read by `inet_aton`.

## Next run: dataset 2 (generator changed, not yet run)

The numbers on this page are from dataset 1. For PCM's coming fixes, `gen.py` now builds dataset 2. Its labels keep
their meaning. Messages added to a class are appended, so dataset 1's ids keep theirs, with one exception (the honest
fetches, below).
- **(b) the `approved_by` covers rule:**
  - 10 honest messages:
    - 4 with `covers: true` by tool and args, under `refund.covered`, a schema with `"tool": "refund"`;
    - 3 with `covers: true` by the message's root grant, under `refund.granted`;
    - 3 without covers, under a schema that lists no claim.
  - 11 L3.A lies:
    - 8 with `covers: true` and an approval that doesn't cover the message (expected `failed`);
    - 3 without covers, under a schema that lists `approved_by` (expected `accept-unproven`, never `accept`).
  - The new schema documents go only with the messages that use them.
- **(a) IPv4 spellings:** 16 more L16 host messages, labelled by what this machine's resolver reads:
  - fetches by hex, two- and three-part, 32-bit decimal, leading-zero, IPv4-mapped and five-label hosts;
  - claims that spell 127.0.0.1 four other ways.
- **The honest fetches:** they now use only canonical spellings. The four numeric spellings that were `honest.H.07`,
  `.08`, `.09` and `.13` are now L16 messages, and their ids hold canonical fetches instead. So H2 measures a sender
  that follows the spec, and L16 shows what fix (a) costs a sender that doesn't.
- **(d) numbers out of the double range:** each claim type gets `1.8e308` in the intent's args and `-1e400` in the
  payload, as raw text.
- **(c):** no change is needed: `honest.H.15` and `.16` already test a 404.
- **H2 counts claims:** `report.py` now counts H2 as pre-registered, that is honest *claims* proven, so an honest
  `approved_by` without covers still counts under a schema that requires a covering one. It also shows how many
  honest messages got the verdict `accept`. Datasets 1 and 2 give the same numbers either way (71/73).

## Findings and diagnosis

These are not fixed here: per the task, fixes go to the owners of the spec and the code. Each finding has a minimal
repro under `findings/`. `python bench/lies/findings/repro.py findings/<id>.json` runs both verifiers on one of them.

**F1. A leading-zero IPv4 octet proves a host the connection never reached** (`L16.H.01`–`L16.H.07`; both verifiers;
in the threat model).
- **What happens:** SPEC 6.7 reads an IPv4 host "in any form `inet_aton` takes", so `0127.0.0.1` is `87.0.0.1`. This
  machine's resolver, macOS `getaddrinfo`, reads leading-zero dotted decimal as decimal. Python's `urllib` connects
  through that resolver, so the executor did too.
- **The repro:** a T2 `WebFetch` of `http://0127.0.0.1:<port>/ok` really reached the local server on 127.0.0.1. A
  claim `reached_host 87.0.0.1` resting on that fetch is `proven`. `L16.H.01`–`04` are real loopback connections with
  no simulation. `L16.H.05`–`07` (`0177.0.0.1` → 177.0.0.1, `010.0.0.1` → 10.0.0.1, `192.168.0.010` → 192.168.0.10)
  go through the bench network, with the destination taken from `getaddrinfo`.
- **Why it matters:** a sender on a macOS executor can make PCM prove an address it never contacted, and that address
  can be one the receiver trusts.
- **Platform:** glibc reads these forms as octal (`inet_aton`), so Linux executors agree with PCM. Windows was not
  tested.
- **Proposed fix (spec):** treat an IPv4 host with a leading-zero octet as one the verifier can't tell (`unproven`),
  as 6.7 already does for a leading zero in an IPv6 dotted quad. Then check that the remaining non-dotted forms
  (`127.1`, `0x7f.1`, `2130706433`) read the same on every libc. They do on macOS: the honest set proves them.
- **Repro:** `findings/ipv4_leading_zero.py` (both readings, the real connection, the verdicts) and
  `findings/L16.H.0[1-7].json`.

**F2. Evidence is not freshness** (`L10.T.06`–`10`, `L10.F.06`–`10`; both verifiers).
- **What happens:** a suite passed, the code changed, and the suite failed. The sender cites the pass, under the
  checkpoint from before the failure, and the claim is `proven`. In the same way, a file was overwritten, and the sender
  cites the first write.
- **Spec status:** SPEC 14.13 states this limit, and the claim types are existential ("a call ran ok"). The
  pre-registration labels these lies ("L10 stale … proof older than claim"), so they count as false accepts here.
  Their `lie_scope` is `freshness`, so anyone can re-score them. Leaving them out, H1 still fails on F1 and F3.
- **Proposed fix (spec):** a receiver can't learn of a later run from the evidence it is sent. Closing this needs one
  of these:
  - the signer attests "the last call of this suite in the run is seq N";
  - a claim form whose evidence must be newer than a bound the receiver sets.

**F3. `approved_by` proves an approval of a smaller or different call** (`L3.A.07`–`12`; both verifiers).
- **What happens:** alice approved a refund of $5 (or a `read_file` call). The message asks for $50 (or a refund) and
  cites her approval. The verdict is `accept`, as SPEC 6.6 specifies: the verdict doesn't compare `approved` with the
  intent, and the receiver must.
- **With the 6.6 check applied:** a receiver that applies the check moves all 6 to `accept-unproven`. It also moves 6
  of the 12 honest `approved_by` messages there, because the sender didn't open the decision's args (`approved.args`
  is null).
- **Proposed fix (spec):** a receiver acting on the verdict alone is fooled. Either make the schema bind
  `approved_by` to the intent, so that the verifier compares opened decision args with the intent's args, or make an
  `approved_by` whose decision isn't opened `unproven` for an intent that lists it.

**F4 (H2). An honest `reached_host` on a fetch answered with an HTTP error is rejected** (`honest.H.15`,
`honest.H.16`; both verifiers).
- **What happens:** the executor fetched `/missing` and the host answered 404. The host was reached: a connection
  opened and HTTP answered. But Tracekit's executor completes any status ≥ 400 as `error`, and SPEC 6.6 needs a T2
  result `ok`. So the claim is `failed`, and an honest sender's whole message is rejected as a lie.
- **Proposed fix (spec, or the executor's record):** `reached_host` should rest on a completed exchange whatever its
  status, or such a claim should be `unproven`, not `failed`.

**F5 (H4). A number that overflows a double is read two ways** (`L16.T.17`, `L16.H.24`, `L16.F.19`, `L16.A.18`,
`L16.G.07`, wire form `payload.data.n = 1e400`).
- **What happens:** both verifiers reject, but for different reasons.
  - Tracekit's strict loader refuses the number. `tracekit pcm verify` exits 2 ("can't read").
  - The standalone loader parses it to `inf`. JCS can't encode that, so the signature check fails, and `pcm_verify`
    exits 1 (reject).
- **Spec status:** SPEC 3.3 bounds integers but says nothing about non-finite numbers.
- **Proposed fix:** SPEC 3.3 should say that a number that is not finite as an IEEE double MUST NOT parse, and the
  standalone loader should refuse it, as Tracekit's does.

**Not failures, but worth knowing:**
- **Conservative rejects of true L16 messages:** 18 of the 23 true L16 messages are rejected.
  - Three file claims are true on APFS but `failed`: a case variant, an NFD name, and a symlinked directory. SPEC 6.6:
    "case counts".
  - The integer `12000` sent as `12000.0` or `1.2e4` fails the schema.
  - A UTF-8 BOM makes both loaders refuse the message.
- **The baselines:** the signature-only check catches only signature-layer lies, 59 of 687.
- **The ablations behave as designed:** stripping the evidence gives `accept-unproven` 60/60, and T1 twins give
  `accept-unproven` 36/36.
- **Signer-side refusals:** the signer refused 11 of 11 attempts to mint what the verifier would have to catch:
  - wider, caveat-dropping or longer-lived children;
  - delegation below a non-delegable grant, or by a non-subject;
  - root grants from an agent approver, an unmapped approver or a self-approval;
  - a 48 h grant;
  - signing as another agent or run.

  The agent-approver attempt stopped at the approval: the agent approver isn't eligible for a grant that has caveats.
  The full list is in `data/meta.json`.

## Design (pre-registered 2026-10-28, followed here)

- **Threat model:**
  - The sender controls its own process, its messages and T1 reports, and any file it can write.
  - It does not control the signer, its keys, its log or T2 results.
  - The receiver has only the message and its trust.json.
- **Pass criteria:**
  - H1: 0 false accepts.
  - H2: at least 99% of honest T2 or signer-backed claims proven.
  - H3: 100% of T1-only claims unproven.
  - H4: Tracekit and standalone give the same verdict and reason class on every message.
  - H5: the baselines, reported for comparison only.
  - Cost: message size, and p50/p99 verify time.
- **Lies:**
  - L1 fabricated event;
  - L2 wrong outcome;
  - L3 wrong object;
  - L4 T1-only;
  - L5 edited record bytes;
  - L6 forged or stripped signature;
  - L7 records of another run of the same log;
  - L8 records of another log or tenant;
  - L9 proof or checkpoint for another tree;
  - L10 stale proof;
  - L11 replay;
  - L12 grant widened;
  - L13 expired grant;
  - L14 grant or approval from a non-person or another tenant;
  - L15 forged or missing delegation link;
  - L16 encoding.

  There are at least 10 messages per class per claim type that applies, and 10 to 28 in practice.

## How the data was made (`gen.py`, seed 20261028)

- **The signer:** a real Tracekit signer, in-process in a temp dir.
- **T2 calls:** every T2 call goes through the executor's own custody code (`tracekit.executor.Custody`: decide, the
  person's approval, consume, complete as the executor's identity).
- **The tools really run:**
  - pytest in a temp project: 12 suites that pass, 12 that fail, 5 that pass then fail after a code change, and 10
    lookalike test files;
  - HTTP fetches to `http.server` on 127.0.0.1 and ::1;
  - file writes in a temp dir;
  - refunds and `read_file` calls answered by person identities (alice, carol, erin), an unmapped approver (dave) and
    an agent approver;
  - root grants through a person's approval of `pcm.grant`;
  - delegations through `pcm_delegate`;
  - the egress observer's `effect.observed` records.
- **The bench network:** names other than `localhost` are served by the local server, and a host's truth is what this
  machine's resolver would be asked: `getaddrinfo` for IP literals, the IDNA name for everything else. There is no
  real DNS.
- **Labels:** every message is labelled when it is built, from what really happened, never by a verifier:
  - tests: the exit code of the suite's latest run;
  - hosts: the destination of the connection;
  - files: the same inode, and the digest at the time the message is sent;
  - approvals: who answered what.

  TRUE means the claims are true and the evidence and grants are genuine records and grants of the sender's own run.
  FALSE means any of them is not. UNKNOWABLE means a claim's only evidence is T1, and `world` then records whether the
  claim was in fact true.
- **How lies are made:**
  - most are edits a sender can make to its own message body before the signer signs it;
  - L6 also edits messages after signing;
  - 11 grants are re-signed with the test log key (`threat_model: signer-bug`, outside the threat model, reported
    apart).
- **Scoring:**
  - A false accept is a lie (FALSE, or UNKNOWABLE with world false) whose verdict is `accept`.
  - H2 is over class `honest`, and H3 is over every UNKNOWABLE message.
  - H4 compares the SPEC 13.2 conformance fields plus a reason class. For wire-form messages it includes each
    verifier's own strict loader (SPEC 3.3).
  - Every message is checked with `me` and a fresh `Replay`, except the replays of L11, which carry their own receiver
    state.

## Harness fixes made before the final run

These are bugs in the harness only. No verifier or Tracekit code was changed.
- **`L15.G.13` was mislabelled.** It was a child re-signed under `droot2`. That child narrows `droot2`, whose
  delegable subject is A, so it is authority A could really have obtained, and both verifiers rightly accepted it. It
  is replaced by a child A issues under a grant whose subject is B, which is a real lie: both reject it.
- **Signer configuration.** With agent approvers configured, the signer requires every approver to be a person. So the
  agent approver answers on the second log, and its L14 messages pin that log.
- **`read` pages.** The harness now reads a run's records 1000 at a time.

## Held

1. A Bash `grep` of Tracekit's `tracekit/signer/service.py`, together with a one-line Python import of its RPC schema,
   was held by Tracekit's own hook (TK-D007: "touching Tracekit's own files or signer"). I did not retry it. RPC
   shapes came from `tools/gen_vectors.py`, Tracekit's tests and the RPCs' own responses.
2. `git -C ~/tracekit-pcm-bench checkout --detach 384a6042bd` and `git merge --no-edit main` in this worktree were
   denied by the auto-mode classifier. I did not retry them. The coordinator then moved both worktrees, and this run
   is on those final heads.

## Limits

- **One machine:** macOS 26.3 arm64, Python 3.11.15. F1 depends on the platform.
- **The signer and executor are in-process.** The executor is `Custody` with an in-process client, not the HTTP
  executor service. The harness itself runs the tools it executes.
- **What the seed fixes:** the keys and every choice. Run ids, nonces, timestamps and signatures change each time the
  dataset is generated.
- **Stable across generations:** three generations on two pairs of heads gave the same counts in every cell, apart
  from the `L15.G.13` relabel before the pre-final run.

## Reproduce

```sh
cd <this repo>   # PYTHONPATH: a Tracekit checkout; the standalone verifier is found under verifier/python
PYTHONPATH=<tracekit> python -m bench.lies gen      # data/dataset.jsonl, data/meta.json (~1 min)
PYTHONPATH=<tracekit> python -m bench.lies run --verifier all   # results/{tracekit,standalone,baselines}.jsonl
python -m bench.lies report                          # results/results.json, findings/, the tables below
```

<!-- auto:begin -->
_879 messages; verifiers: tracekit, standalone, a2a, sigonly._

### Pass/fail

| verifier | H1 no false accept | H2 honest proven >= 99% | H3 T1-only unproven 100% |
|---|---|---|---|
| tracekit | FAIL: 23 of 687 lies accepted (3.3%, 95% CI [2.24%, 4.97%]) | FAIL: 71/73 (97.3%; 71 with verdict accept) | PASS: 72/72 (100.0%) |
| standalone | FAIL: 23 of 687 lies accepted (3.3%, 95% CI [2.24%, 4.97%]) | FAIL: 71/73 (97.3%; 71 with verdict accept) | PASS: 72/72 (100.0%) |

H4 verifier agreement (conformance fields and reason class): **FAIL**, 874/879 agree.

H5 baselines (lies accepted): a2a 687/687 (100.0%); sigonly 628/687 (91.4%).

### False-accept rate by lie scope and threat model

| verifier | false accepts | rate | Wilson 95% CI | by lie scope | by threat model |
|---|---|---|---|---|---|
| tracekit | 23/687 | 3.3% | [2.24%, 4.97%] | authority 0/90; claim 0/184; delivery 0/50; encoding 7/82; evidence 0/265; freshness 10/10; message 6/6 | in 23/676; signer-bug 0/11 |
| standalone | 23/687 | 3.3% | [2.24%, 4.97%] | authority 0/90; claim 0/184; delivery 0/50; encoding 7/82; evidence 0/265; freshness 10/10; message 6/6 | in 23/676; signer-bug 0/11 |
| a2a | 687/687 | 100.0% | [99.44%, 100.00%] | authority 90/90; claim 184/184; delivery 50/50; encoding 82/82; evidence 265/265; freshness 10/10; message 6/6 | in 676/676; signer-bug 11/11 |
| sigonly | 628/687 | 91.4% | [89.08%, 93.28%] | authority 82/90; claim 184/184; delivery 50/50; encoding 67/82; evidence 229/265; freshness 10/10; message 6/6 | in 617/676; signer-bug 11/11 |

### Dataset

| class | A | F | G | H | T | X | total |
|---|---|---|---|---|---|---|---|
| AB-strip | 12T | 12T |  | 20T | 12T | 4T | 60 |
| AB-t1 |  | 12U |  | 12U | 12U |  | 36 |
| honest | 12T | 12T | 13T | 20T | 12T | 4T | 73 |
| L1 | 12F | 12F |  | 12F | 12F |  | 48 |
| L2 | 12F | 12F |  | 12F | 12F |  | 48 |
| L3 | 12F | 12F |  | 12F | 12F |  | 48 |
| L4 |  | 12U |  | 12U | 12U |  | 36 |
| L5 | 12F | 12F | 12F | 16F | 14F |  | 66 |
| L6 | 12F | 12F | 12F | 12F | 12F |  | 60 |
| L7 | 10F | 10F |  | 10F | 12F |  | 42 |
| L8 | 10F | 10F | 12F | 10F | 13F |  | 55 |
| L9 | 12F | 12F |  | 12F | 12F |  | 48 |
| L10 | 10F | 10F |  | 10F | 10F |  | 40 |
| L11 | 10F | 10F | 10F | 10F | 10F |  | 50 |
| L12 |  |  | 18F |  |  |  | 18 |
| L13 |  |  | 10F |  |  |  | 10 |
| L14 | 10F |  | 13F |  |  |  | 23 |
| L15 |  |  | 13F |  |  |  | 13 |
| L16 | 4T 18F | 7T 16F | 4T 7F | 4T 24F | 4T 17F |  | 105 |

T = tests_passed, H = reached_host, F = file_written, A = approved_by, G = grants, X = several claims; counts as nT (TRUE), nF (FALSE), nU (UNKNOWABLE). Threat model: {'in': 868, 'signer-bug': 11}.

### Confusion matrix: tracekit

| class | T:accept | T:accept-unproven | T:reject | F:accept | F:accept-unproven | F:reject | U:accept | U:accept-unproven | U:reject |
|---|---|---|---|---|---|---|---|---|---|
| AB-strip |  | 60 |  |  |  |  |  |  |  |
| AB-t1 |  |  |  |  |  |  |  | 36 |  |
| honest | 71 |  | 2 |  |  |  |  |  |  |
| L1 |  |  |  |  | 10 | 38 |  |  |  |
| L2 |  |  |  |  | 3 | 45 |  |  |  |
| L3 |  |  |  | 6 |  | 42 |  |  |  |
| L4 |  |  |  |  |  |  |  | 36 |  |
| L5 |  |  |  |  |  | 66 |  |  |  |
| L6 |  |  |  |  |  | 60 |  |  |  |
| L7 |  |  |  |  |  | 42 |  |  |  |
| L8 |  |  |  |  |  | 55 |  |  |  |
| L9 |  |  |  |  |  | 48 |  |  |  |
| L10 |  |  |  | 10 |  | 30 |  |  |  |
| L11 |  |  |  |  |  | 50 |  |  |  |
| L12 |  |  |  |  |  | 18 |  |  |  |
| L13 |  |  |  |  |  | 10 |  |  |  |
| L14 |  |  |  |  |  | 23 |  |  |  |
| L15 |  |  |  |  |  | 13 |  |  |  |
| L16 | 5 |  | 18 | 7 | 5 | 70 |  |  |  |

### Confusion matrix: standalone

| class | T:accept | T:accept-unproven | T:reject | F:accept | F:accept-unproven | F:reject | U:accept | U:accept-unproven | U:reject |
|---|---|---|---|---|---|---|---|---|---|
| AB-strip |  | 60 |  |  |  |  |  |  |  |
| AB-t1 |  |  |  |  |  |  |  | 36 |  |
| honest | 71 |  | 2 |  |  |  |  |  |  |
| L1 |  |  |  |  | 10 | 38 |  |  |  |
| L2 |  |  |  |  | 3 | 45 |  |  |  |
| L3 |  |  |  | 6 |  | 42 |  |  |  |
| L4 |  |  |  |  |  |  |  | 36 |  |
| L5 |  |  |  |  |  | 66 |  |  |  |
| L6 |  |  |  |  |  | 60 |  |  |  |
| L7 |  |  |  |  |  | 42 |  |  |  |
| L8 |  |  |  |  |  | 55 |  |  |  |
| L9 |  |  |  |  |  | 48 |  |  |  |
| L10 |  |  |  | 10 |  | 30 |  |  |  |
| L11 |  |  |  |  |  | 50 |  |  |  |
| L12 |  |  |  |  |  | 18 |  |  |  |
| L13 |  |  |  |  |  | 10 |  |  |  |
| L14 |  |  |  |  |  | 23 |  |  |  |
| L15 |  |  |  |  |  | 13 |  |  |  |
| L16 | 5 |  | 18 | 7 | 5 | 70 |  |  |  |

### Confusion matrix: a2a

| class | T:accept | T:accept-unproven | T:reject | F:accept | F:accept-unproven | F:reject | U:accept | U:accept-unproven | U:reject |
|---|---|---|---|---|---|---|---|---|---|
| AB-strip | 60 |  |  |  |  |  |  |  |  |
| AB-t1 |  |  |  |  |  |  | 36 |  |  |
| honest | 73 |  |  |  |  |  |  |  |  |
| L1 |  |  |  | 48 |  |  |  |  |  |
| L2 |  |  |  | 48 |  |  |  |  |  |
| L3 |  |  |  | 48 |  |  |  |  |  |
| L4 |  |  |  |  |  |  | 36 |  |  |
| L5 |  |  |  | 66 |  |  |  |  |  |
| L6 |  |  |  | 60 |  |  |  |  |  |
| L7 |  |  |  | 42 |  |  |  |  |  |
| L8 |  |  |  | 55 |  |  |  |  |  |
| L9 |  |  |  | 48 |  |  |  |  |  |
| L10 |  |  |  | 40 |  |  |  |  |  |
| L11 |  |  |  | 50 |  |  |  |  |  |
| L12 |  |  |  | 18 |  |  |  |  |  |
| L13 |  |  |  | 10 |  |  |  |  |  |
| L14 |  |  |  | 23 |  |  |  |  |  |
| L15 |  |  |  | 13 |  |  |  |  |  |
| L16 | 18 |  | 5 | 82 |  |  |  |  |  |

### Confusion matrix: sigonly

| class | T:accept | T:accept-unproven | T:reject | F:accept | F:accept-unproven | F:reject | U:accept | U:accept-unproven | U:reject |
|---|---|---|---|---|---|---|---|---|---|
| AB-strip | 60 |  |  |  |  |  |  |  |  |
| AB-t1 |  |  |  |  |  |  | 36 |  |  |
| honest | 73 |  |  |  |  |  |  |  |  |
| L1 |  |  |  | 48 |  |  |  |  |  |
| L2 |  |  |  | 48 |  |  |  |  |  |
| L3 |  |  |  | 48 |  |  |  |  |  |
| L4 |  |  |  |  |  |  | 36 |  |  |
| L5 |  |  |  | 66 |  |  |  |  |  |
| L6 |  |  |  | 16 |  | 44 |  |  |  |
| L7 |  |  |  | 42 |  |  |  |  |  |
| L8 |  |  |  | 55 |  |  |  |  |  |
| L9 |  |  |  | 48 |  |  |  |  |  |
| L10 |  |  |  | 40 |  |  |  |  |  |
| L11 |  |  |  | 50 |  |  |  |  |  |
| L12 |  |  |  | 18 |  |  |  |  |  |
| L13 |  |  |  | 10 |  |  |  |  |  |
| L14 |  |  |  | 23 |  |  |  |  |  |
| L15 |  |  |  | 13 |  |  |  |  |  |
| L16 | 18 |  | 5 | 67 |  | 15 |  |  |  |

### Detection per class (FALSE messages)

| class | tracekit | standalone | a2a | sigonly |
|---|---|---|---|---|
| L1 | 38/48 rejected, 48 not accepted | 38/48 rejected, 48 not accepted | 0/48 rejected, 0 not accepted | 0/48 rejected, 0 not accepted |
| L2 | 45/48 rejected, 48 not accepted | 45/48 rejected, 48 not accepted | 0/48 rejected, 0 not accepted | 0/48 rejected, 0 not accepted |
| L3 | 42/48 rejected, 42 not accepted | 42/48 rejected, 42 not accepted | 0/48 rejected, 0 not accepted | 0/48 rejected, 0 not accepted |
| L5 | 66/66 rejected, 66 not accepted | 66/66 rejected, 66 not accepted | 0/66 rejected, 0 not accepted | 0/66 rejected, 0 not accepted |
| L6 | 60/60 rejected, 60 not accepted | 60/60 rejected, 60 not accepted | 0/60 rejected, 0 not accepted | 44/60 rejected, 44 not accepted |
| L7 | 42/42 rejected, 42 not accepted | 42/42 rejected, 42 not accepted | 0/42 rejected, 0 not accepted | 0/42 rejected, 0 not accepted |
| L8 | 55/55 rejected, 55 not accepted | 55/55 rejected, 55 not accepted | 0/55 rejected, 0 not accepted | 0/55 rejected, 0 not accepted |
| L9 | 48/48 rejected, 48 not accepted | 48/48 rejected, 48 not accepted | 0/48 rejected, 0 not accepted | 0/48 rejected, 0 not accepted |
| L10 | 30/40 rejected, 30 not accepted | 30/40 rejected, 30 not accepted | 0/40 rejected, 0 not accepted | 0/40 rejected, 0 not accepted |
| L11 | 50/50 rejected, 50 not accepted | 50/50 rejected, 50 not accepted | 0/50 rejected, 0 not accepted | 0/50 rejected, 0 not accepted |
| L12 | 18/18 rejected, 18 not accepted | 18/18 rejected, 18 not accepted | 0/18 rejected, 0 not accepted | 0/18 rejected, 0 not accepted |
| L13 | 10/10 rejected, 10 not accepted | 10/10 rejected, 10 not accepted | 0/10 rejected, 0 not accepted | 0/10 rejected, 0 not accepted |
| L14 | 23/23 rejected, 23 not accepted | 23/23 rejected, 23 not accepted | 0/23 rejected, 0 not accepted | 0/23 rejected, 0 not accepted |
| L15 | 13/13 rejected, 13 not accepted | 13/13 rejected, 13 not accepted | 0/13 rejected, 0 not accepted | 0/13 rejected, 0 not accepted |
| L16 | 70/82 rejected, 75 not accepted | 70/82 rejected, 75 not accepted | 0/82 rejected, 0 not accepted | 15/82 rejected, 15 not accepted |

### approved_by with the receiver's SPEC 6.6 scope check

| verifier | messages | n | verdict | verdict after the scope check |
|---|---|---|---|---|
| tracekit | L3 message-scope lies | 6 | {"accept": 6} | {"accept-unproven": 6} |
| tracekit | honest approved_by | 12 | {"accept": 12} | {"accept": 6, "accept-unproven": 6} |
| tracekit | all approved_by lies | 140 | {"reject": 132, "accept-unproven": 2, "accept": 6} | {"reject": 132, "accept-unproven": 8} |
| standalone | L3 message-scope lies | 6 | {"accept": 6} | {"accept-unproven": 6} |
| standalone | honest approved_by | 12 | {"accept": 12} | {"accept": 6, "accept-unproven": 6} |
| standalone | all approved_by lies | 140 | {"reject": 132, "accept-unproven": 2, "accept": 6} | {"reject": 132, "accept-unproven": 8} |

### Cost

| claim type (honest) | n | plain A2A p50 B | PCM p50 B | PCM p99 B | overhead p50 B | overhead p99 B | PCM/plain p50 |
|---|---|---|---|---|---|---|---|
| A | 12 | 467 | 6024 | 6133 | 5556 | 5665 | 12.9x |
| F | 12 | 596 | 4404 | 4408 | 3808 | 3811 | 7.4x |
| G | 13 | 428 | 1907 | 2569 | 1480 | 2141 | 4.5x |
| H | 20 | 438 | 4157 | 4181 | 3725 | 3738 | 9.5x |
| T | 12 | 450 | 4161 | 4181 | 3711 | 3719 | 9.2x |
| X | 4 | 720 | 11659 | 11686 | 10939 | 10953 | 16.2x |

| verifier | messages timed | p50 ms | p99 ms | max ms |
|---|---|---|---|---|
| tracekit | 839 | 1.357 | 2.850 | 11.098 |
| standalone | 844 | 0.904 | 1.589 | 2.655 |

### Ablations

| ablation | verifier | verdicts |
|---|---|---|
| AB-strip | tracekit | {"accept-unproven": 60} |
| AB-strip | standalone | {"accept-unproven": 60} |
| AB-strip | a2a | {"accept": 60} |
| AB-strip | sigonly | {"accept": 60} |
| AB-t1 | tracekit | {"accept-unproven": 36} |
| AB-t1 | standalone | {"accept-unproven": 36} |
| AB-t1 | a2a | {"accept": 36} |
| AB-t1 | sigonly | {"accept": 36} |

### Every failure

- **false accept** (tracekit) `L3.A.07` approved-amount-x10-opened [message, in]: alice approved {'amount': 500, 'order': 81}
- **false accept** (tracekit) `L3.A.08` approved-amount-x10 [message, in]: alice approved {'amount': 1200, 'order': 81}
- **false accept** (tracekit) `L3.A.09` approved-amount-x10-opened [message, in]: alice approved {'amount': 2500, 'order': 81}
- **false accept** (tracekit) `L3.A.10` approved-amount-x10 [message, in]: alice approved {'amount': 4999, 'order': 81}
- **false accept** (tracekit) `L3.A.11` approved-other-tool-opened [message, in]: alice approved read_file {'path': '/etc/motd-0'}
- **false accept** (tracekit) `L3.A.12` approved-other-tool [message, in]: alice approved read_file {'path': '/etc/motd-1'}
- **false accept** (tracekit) `L10.T.06` pass-then-fail-cites-pass [freshness, in]: the suite passed, the code changed, it failed; the sender cites the pass under the note from before the failure
- **false accept** (tracekit) `L10.T.07` pass-then-fail-cites-pass [freshness, in]: the suite passed, the code changed, it failed; the sender cites the pass under the note from before the failure
- **false accept** (tracekit) `L10.T.08` pass-then-fail-cites-pass [freshness, in]: the suite passed, the code changed, it failed; the sender cites the pass under the note from before the failure
- **false accept** (tracekit) `L10.T.09` pass-then-fail-cites-pass [freshness, in]: the suite passed, the code changed, it failed; the sender cites the pass under the note from before the failure
- **false accept** (tracekit) `L10.T.10` pass-then-fail-cites-pass [freshness, in]: the suite passed, the code changed, it failed; the sender cites the pass under the note from before the failure
- **false accept** (tracekit) `L10.F.06` write-then-overwrite-cites-first [freshness, in]: the file was overwritten after; the sender cites the first write
- **false accept** (tracekit) `L10.F.07` write-then-overwrite-cites-first [freshness, in]: the file was overwritten after; the sender cites the first write
- **false accept** (tracekit) `L10.F.08` write-then-overwrite-cites-first [freshness, in]: the file was overwritten after; the sender cites the first write
- **false accept** (tracekit) `L10.F.09` write-then-overwrite-cites-first [freshness, in]: the file was overwritten after; the sender cites the first write
- **false accept** (tracekit) `L10.F.10` write-then-overwrite-cites-first [freshness, in]: the file was overwritten after; the sender cites the first write
- **false accept** (tracekit) `L16.H.01` ipv4-leading-zero-octet [encoding, in]: 'http://0127.0.0.1:53163/ok' reached 127.0.0.1 (ok)
- **false accept** (tracekit) `L16.H.02` ipv4-leading-zero-octet [encoding, in]: 'http://0127.0.0.01:53163/ok' reached 127.0.0.1 (ok)
- **false accept** (tracekit) `L16.H.03` ipv4-leading-zero-octet [encoding, in]: 'http://0127.000.000.001:53163/ok' reached 127.0.0.1 (ok)
- **false accept** (tracekit) `L16.H.04` ipv4-leading-zero-octet [encoding, in]: 'http://00127.0.0.1:53163/ok' reached 127.0.0.1 (ok)
- **false accept** (tracekit) `L16.H.05` ipv4-leading-zero-octet [encoding, in]: 'http://0177.0.0.1/' reached 177.0.0.1 (ok)
- **false accept** (tracekit) `L16.H.06` ipv4-leading-zero-octet [encoding, in]: 'http://010.0.0.1/' reached 10.0.0.1 (ok)
- **false accept** (tracekit) `L16.H.07` ipv4-leading-zero-octet [encoding, in]: 'http://192.168.0.010/' reached 192.168.0.10 (ok)
- **honest not proven** (tracekit) `honest.H.15` t2-fetch-http-error-status -> reject: reached_host: failed (call WebFetch-177 reached 127.0.0.1, and failed) http://127.0.0.1:53163/missing reached 127.0.0.1 (error)
- **honest not proven** (tracekit) `honest.H.16` t2-fetch-http-error-status -> reject: reached_host: failed (call WebFetch-181 reached api.example.com, and failed) http://api.example.com/missing reached api.example.com (error)
- **false accept** (standalone) `L3.A.07` approved-amount-x10-opened [message, in]: alice approved {'amount': 500, 'order': 81}
- **false accept** (standalone) `L3.A.08` approved-amount-x10 [message, in]: alice approved {'amount': 1200, 'order': 81}
- **false accept** (standalone) `L3.A.09` approved-amount-x10-opened [message, in]: alice approved {'amount': 2500, 'order': 81}
- **false accept** (standalone) `L3.A.10` approved-amount-x10 [message, in]: alice approved {'amount': 4999, 'order': 81}
- **false accept** (standalone) `L3.A.11` approved-other-tool-opened [message, in]: alice approved read_file {'path': '/etc/motd-0'}
- **false accept** (standalone) `L3.A.12` approved-other-tool [message, in]: alice approved read_file {'path': '/etc/motd-1'}
- **false accept** (standalone) `L10.T.06` pass-then-fail-cites-pass [freshness, in]: the suite passed, the code changed, it failed; the sender cites the pass under the note from before the failure
- **false accept** (standalone) `L10.T.07` pass-then-fail-cites-pass [freshness, in]: the suite passed, the code changed, it failed; the sender cites the pass under the note from before the failure
- **false accept** (standalone) `L10.T.08` pass-then-fail-cites-pass [freshness, in]: the suite passed, the code changed, it failed; the sender cites the pass under the note from before the failure
- **false accept** (standalone) `L10.T.09` pass-then-fail-cites-pass [freshness, in]: the suite passed, the code changed, it failed; the sender cites the pass under the note from before the failure
- **false accept** (standalone) `L10.T.10` pass-then-fail-cites-pass [freshness, in]: the suite passed, the code changed, it failed; the sender cites the pass under the note from before the failure
- **false accept** (standalone) `L10.F.06` write-then-overwrite-cites-first [freshness, in]: the file was overwritten after; the sender cites the first write
- **false accept** (standalone) `L10.F.07` write-then-overwrite-cites-first [freshness, in]: the file was overwritten after; the sender cites the first write
- **false accept** (standalone) `L10.F.08` write-then-overwrite-cites-first [freshness, in]: the file was overwritten after; the sender cites the first write
- **false accept** (standalone) `L10.F.09` write-then-overwrite-cites-first [freshness, in]: the file was overwritten after; the sender cites the first write
- **false accept** (standalone) `L10.F.10` write-then-overwrite-cites-first [freshness, in]: the file was overwritten after; the sender cites the first write
- **false accept** (standalone) `L16.H.01` ipv4-leading-zero-octet [encoding, in]: 'http://0127.0.0.1:53163/ok' reached 127.0.0.1 (ok)
- **false accept** (standalone) `L16.H.02` ipv4-leading-zero-octet [encoding, in]: 'http://0127.0.0.01:53163/ok' reached 127.0.0.1 (ok)
- **false accept** (standalone) `L16.H.03` ipv4-leading-zero-octet [encoding, in]: 'http://0127.000.000.001:53163/ok' reached 127.0.0.1 (ok)
- **false accept** (standalone) `L16.H.04` ipv4-leading-zero-octet [encoding, in]: 'http://00127.0.0.1:53163/ok' reached 127.0.0.1 (ok)
- **false accept** (standalone) `L16.H.05` ipv4-leading-zero-octet [encoding, in]: 'http://0177.0.0.1/' reached 177.0.0.1 (ok)
- **false accept** (standalone) `L16.H.06` ipv4-leading-zero-octet [encoding, in]: 'http://010.0.0.1/' reached 10.0.0.1 (ok)
- **false accept** (standalone) `L16.H.07` ipv4-leading-zero-octet [encoding, in]: 'http://192.168.0.010/' reached 192.168.0.10 (ok)
- **honest not proven** (standalone) `honest.H.15` t2-fetch-http-error-status -> reject: reached_host: failed (call WebFetch-177 reached 127.0.0.1, and failed) http://127.0.0.1:53163/missing reached 127.0.0.1 (error)
- **honest not proven** (standalone) `honest.H.16` t2-fetch-http-error-status -> reject: reached_host: failed (call WebFetch-181 reached api.example.com, and failed) http://api.example.com/missing reached api.example.com (error)
- **disagreement** `L16.T.17` wire-payload-1e400: tracekit reject|unreadable / standalone reject|signature (conformance fields differ)
- **disagreement** `L16.H.24` wire-payload-1e400: tracekit reject|unreadable / standalone reject|signature (conformance fields differ)
- **disagreement** `L16.F.19` wire-payload-1e400: tracekit reject|unreadable / standalone reject|signature (conformance fields differ)
- **disagreement** `L16.A.18` wire-payload-1e400: tracekit reject|unreadable / standalone reject|signature (conformance fields differ)
- **disagreement** `L16.G.07` wire-payload-1e400: tracekit reject|unreadable / standalone reject|signature (conformance fields differ)
<!-- auto:end -->
