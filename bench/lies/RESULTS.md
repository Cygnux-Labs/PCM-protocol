# PCM-Lies results

How often does a receiving agent accept a false claim from a sending agent? Messages built from real Tracekit signer
runs, checked by Tracekit's `pcm.verify`, the standalone `pcm_verify`, plain A2A (accepts everything) and a
sender-signature-only check. Added after the pre-registration: models of six real agent protocols as receivers ("Real
protocols as receivers").

**This run (after):** dataset 2, 926 messages, at Tracekit `7d843e6377` and pcm `73a287c` (pcm main `0f26c38` merged,
with PCM's fixes for F1, F3 and F5).

**Before:** dataset 1, 879 messages, at Tracekit `384a6042bd` and pcm `1ba784a` (main `619fbba`), commit `9b430ab`.

Dataset 2 is dataset 1 plus 47 messages for the fixes (see "Dataset 2"). The ids are the same, except that the
honest fetches `honest.H.07`, `.08`, `.09` and `.13` now use canonical spellings.

## Before and after, per hypothesis

| | before (dataset 1, final heads) | after (dataset 2, fixed heads) |
|---|---|---|
| H1 lies accepted, both verifiers | **FAIL** 23/687 (3.3%, 95% CI 2.2–5.0%) | **FAIL** 10/712 (1.4%, 95% CI 0.8–2.6%) |
| … of which not freshness | 13 (F1 7, F3 6) | **0** |
| H2 honest claims proven | **FAIL** 71/73 (97.3%) | **FAIL** 81/83 (97.6%); 69 with verdict `accept` |
| H3 T1-only claims unproven | **PASS** 72/72 | **PASS** 72/72 |
| H4 verifiers agree | **FAIL** 874/879 | **PASS** 926/926 |
| H5 plain A2A / signature only accept | 687/687 / 628/687 | 712/712 / 643/712 (90.3%) |
| verify p50 (p99), Tracekit / standalone | 1.4 (2.9) / 0.9 (1.6) ms | 1.2 (2.4) / 0.8 (1.8) ms |

**H1** still fails: only F2 (freshness, 10 messages) is left. Every other lie, 702 of them, is not accepted. That
covers the claim, evidence, authority, delivery, encoding and message scopes, and includes 11 signer-bug grants.

**H2** still fails on F4 alone. "Honest claims proven" counts claims, as pre-registered. Two numbers differ by design:
- 12 messages are new under the covers rule: the honest `approved_by` messages without covers under `refund.approved`,
  a schema that lists `approved_by` (`honest.A.01`–`12`). Their claims are proven, but the verdict is now
  `accept-unproven` ("required, not proven to cover this request: claim it with covers true").
- With `covers: true`, honest messages are accepted: `honest.A.13`–`19`, matching by tool and args or by root grant.
  So are honest messages under a schema that lists no claim (`.20`–`.22`).

**Cost:**

| claim type | PCM message size, p50 | p99 | vs plain A2A |
|---|---|---|---|
| tests_passed | 4.2 KB | | 9.2x |
| reached_host | 4.2 KB | | 9.5x |
| file_written | 4.4 KB | | 7.4x |
| approved_by | 6.1 KB | 8.4 KB | 13.0x |
| grant only | 1.9 KB | | 4.5x |
| three claims | 11.7 KB | | 16.2x |

The p99 for `approved_by` is new. It comes from the root-grant covers evidence, which carries four records.

## Before and after, per finding

| finding | ids | before | after | status |
|---|---|---|---|---|
| F1 leading-zero IPv4 | `L16.H.01`–`07` | `accept`: 87.0.0.1 proven | `accept-unproven`: "an IPv4 address not written as a dotted quad" | **fixed** |
| F2 freshness | `L10.T.06`–`10`, `L10.F.06`–`10` | `accept` | `accept` | **open** |
| F3 `approved_by` scope | `L3.A.07`–`12` | `accept` | `accept-unproven`: the schema needs a covering `approved_by` | **fixed** |
| F4 honest fetch answered 404 | `honest.H.15`, `.16` | `reject`: "and failed" | `reject`: "and failed" | **open** |
| F5 `1e400` | `L16.T.17`, `H.24`, `F.19`, `A.18`, `G.07` | Tracekit `unreadable`, standalone `signature` | both `unreadable` | **fixed** |

**F1 is fixed.** Only a canonical dotted quad counts now. The 16 new IPv4 messages:
- No lie is accepted. `L16.H.39`–`42` are `accept-unproven`: the five-label hosts, and hex or 32-bit forms that reach
  another address.
- The fix costs honest spellings. 11 true spellings come out `unproven`: hex, two- and three-part, 32-bit, both
  leading-zero forms (`L16.H.31`–`37`), and claims that spell 127.0.0.1 another way (`.43`–`.46`). Each tells the
  sender to "send it as four decimal…".
- `[::ffff:127.0.0.1]` (`L16.H.38`) is still `proven`.
- The repro `findings/ipv4_leading_zero.py` still shows the two readings (`getaddrinfo` against `inet_aton`). Now no
  verifier proves the wrong one.

**F2 is open.** Tracekit's latest commit documents how a receiver checks freshness. The verifier still proves a
`tests_passed` or `file_written` claim whose evidence predates a later failure or overwrite (SPEC 14.13). That gap
can't be closed offline without a signer attestation of the latest call.

**F3 is fixed by `covers`.** The eight new liars with `covers: true` and an approval that doesn't cover the message:
- `L3.A.13`, `15`–`19` are rejected. Each fails with "not this request's args", "not of "refund"" or "did not issue
  this message's root grant".
- `L3.A.14` (args not opened) and `L3.A.20` (a schema that names no tool) are `accept-unproven`, because the verifier
  "can't tell". So they are not accepted, though not failed.
- The three liars without covers under a requiring schema (`L3.A.21`–`23`) are `accept-unproven`.
- A receiver no longer needs its own comparison. The auto table below ("with the receiver's SPEC 6.6 scope check") is
  dataset 1's view, and the covers rule now makes it redundant.

**F4 is open.** Fix (c) is not in these heads: a host that answered with an HTTP error is still `failed`, so the honest
sender is rejected.

**F5 is fixed.** Both loaders now refuse a number outside the range of a double. So do the 10 new raw-text cases:
`1.8e308` in the intent's args and `-1e400` in the payload, for each claim type.

**Nothing else moved.** Across the 875 ids the two datasets share, the only verdict changes in either verifier are
accept → accept-unproven (26: F1 7, F3 6, and 13 honest `approved_by` without covers: `honest.A.01`–`12` and the wire
form `L16.A.22`). The only reason-class change is F5's.

## Real protocols as receivers (added after pre-registration)

These six receivers were added after the pre-registered hypotheses, and no hypothesis covers them. Each is a model of
what one protocol lets a receiver check, built from its specification, not a run of its SDK; `protocols.py` cites the
section each check comes from. They read the same 926 messages with the same parse as plain A2A, and are scored as H1
is: a lie is accepted when the verdict is `accept`, with a Wilson 95% CI.

**Who holds the key.** In every protocol here the sender signs with its own key or its platform's, not with an
attesting signer it can't control. So each receiver gets the message the sender would send in that protocol, signed
with the sender's own key wherever the protocol uses one: a lying sender signs its lie. A signature only another party
can make (a person's, a platform's, a log's) has a counterpart only in AP2 and VI (mandates) and SCITT (receipts).
There the sender carries what really exists, and a mandate that no real grant or approval stands behind is one it
signs itself. A replay (L11) is the original message sent again, unchanged.

| receiver | what it checks | lies accepted | 95% CI | honest accepted |
|---|---|---|---|---|
| plain A2A (pre-registered) | nothing | 712/712 (100%) | 99.5–100% | 83/83 |
| A2A + signed card | A2A 1.0: the sender's Agent Card JWS (8.4); messages are unsigned | 712/712 (100%) | 99.5–100% | 83/83 |
| uAgents envelope | Fetch.ai uAgents: the envelope signed by the sender's key, and its target | 702/712 (98.6%) | 97.4–99.2% | 83/83 |
| RFC 9421 + replay | ANP-02, Visa TAP, Web Bot Auth: the sender's HTTP signature over method, target and body digest; a 300 s window; a nonce cache | 682/712 (95.8%) | 94.0–97.0% | 83/83 |
| sender's signature only (pre-registered) | the PCM signer's signature | 643/712 (90.3%) | 87.9–92.3% | 83/83 |
| SCITT receipts | RFC 9943 and 9942: each claim's records are in a pinned log (content hash, inclusion receipt) | 550/712 (77.2%) | 74.0–80.2% | 83/83 |
| Verifiable Intent | Mastercard VI 0.1: AP2's checks, with a person key an issuer certifies (L1) | 509/712 (71.5%) | 68.1–74.7% | 67/83 |
| AP2 mandates | AP2 0.2 (Trusted Agent Provider model): the open mandate's signer, constraints, exp and cnf; checkout mandates; KB-JWT aud, nonce and iat | 504/712 (70.8%) | 67.3–74.0% | 67/83 |
| PCM 0.1 (H1) | SPEC 8 | 10/712 (1.4%) | 0.8–2.6% | 69/83 `accept` (H2: 81/83 claims proven) |

What each catches, and what it misses:

- **A2A 1.0 + signed Agent Card** catches nothing. The card authenticates the sender, and the sender is the liar;
  nothing in a message is signed.
- **uAgents envelope** catches the 10 replays addressed to another receiver (the envelope's target). It has no nonce
  cache and reads `expires` as a reply timeout, so the other 40 replays pass, and the sender signs every other lie
  itself.
- **RFC 9421 + replay** catches 30 replays: the same nonce (10), another receiver (10: the target is in the signature
  base) and outside the window (10). It misses the replays after a receiver restart (10: the cache is in memory) and
  below the floor (10: there is no per-sender floor), and every lie in a message's content, which the sender re-signs.
- **SCITT receipts** catch 162 lies, all at the evidence layer: proofs for another tree (L9, 48 of 48), edited records
  (L5, 45 of 66), forged or stripped checkpoint signatures (L6, 12), records under an unpinned log or not in the
  checkpoint (L8, 17), the old checkpoint with later records (L10, 30) and claims with no records (L1, 10). They miss
  true records cited for false claims (L1 with other evidence, L2, L3: SCITT has no rule that ties a claim to a
  record), the agent's own reports (L4: no tiers), records of another run or tenant (L7, L8), every replay, every grant
  lie (L12–L15, and the 12 grant edits in L5), message-signature lies (L6) and encodings (L16). 8 of L5's other 9
  misses edit the opened args or their salt, which sit outside the signed record, and one writes a field's own value
  back.
- **AP2 mandates** catch 208 lies: 76 of the 109 grant lies and 132 of the 153 approval lies, 63 of them only because
  the dataset doesn't hold what the model needs (below). They reject all of L12 and L13 and 12 of L15's 13, mostly
  because AP2 0.2 has no agent-to-agent delegation: a child grant can't be presented, so a delegated request fails cnf
  (the rule that also rejects the 8 honest delegations); the expired roots fail exp. They also catch edited or forged
  grants, root grants for another agent, approvals that don't exist, were refused or name another person, and replays
  of messages that carry mandates (11 of 20, by aud, nonce or iat). They miss all 450 lies about
  tests, hosts and files, which carry no mandate; root grants of another tenant (5); message-signature and encoding
  lies on messages with mandates; and 3 signer-bug grants.
- **Verifiable Intent** gives AP2's verdicts on all but 7 grants. It accepts the 6 grants of a log the receiver doesn't
  pin (a real person's certified key signed them, whatever the platform), and rejects a signer-bug root that names no
  person, which AP2 accepts.
- **Stacked.** A receiver that runs the AP2, SCITT and RFC 9421 checks and accepts only what all three accept still
  accepts 365 lies (51.3%), and 67 of the 83 honest messages. All of L4 passes, most of L1–L3 and L16, and 18 of the
  20 replays after a restart or below the floor.

**Honest messages.** The other receivers accept all 83. AP2 and VI reject 16:
- 8 delegated grants. AP2 0.2 has no agent-to-agent delegation, so the request can't be authorized. This is AP2's own
  limit.
- 8 approvals whose message doesn't open the approved call's args (`honest.A.02`, `.04` … `.12`, `.21`, `.22`). The
  model needs those values to check that the mandate is for this request, and the dataset doesn't hold them; a sender
  built for AP2 would disclose them. This is a limit of the model.

**What couldn't be modelled faithfully:**
- **Undisclosed approvals.** AP2 and VI bind a person's approval to a request by its values. 53 approval lies (54 for
  VI) don't open the approved call's args, so the model rejects them as undisclosed. 10 L10 approvals are real, but
  their message carries an older checkpoint and the dataset holds none that includes them, so the model can't tell
  them from forged ones and rejects them too. Counting all 63 as accepted gives the most AP2 could accept: 567 (79.6%);
  VI 573 (80.5%). 13 of the 53 ask for another amount, call or tool than the one approved, which the values would
  expose, and one replays a message the receiver has seen; the other 39, and the 10 in L10, cite an approval of the
  very request. So the faithful counts are most likely 553 for AP2 (77.7%) and 559 for VI (78.5%). The chart and the
  README show the measured 504 and 509, the counts that favour AP2.
- **Mappings.** A root grant is an open mandate, a person's approval a checkout mandate, and a child grant has no AP2
  form. AP2 is modelled with its Trusted Agent Provider model (the receiver trusts the platforms whose logs it pins)
  and VI with its L1 issuer (who certifies the persons the signer's configuration names). Other choices give other
  numbers on L8, L14 and the signer-bug grants.
- **Encodings.** Signatures are real Ed25519, over the model's own encodings rather than JWS, SD-JWT, COSE or HTTP
  header syntax; no check here depends on that syntax. The RFC 9421 window is ANP-02's 300 s; TAP allows 480 s, which
  changes nothing here (the replays outside the window are 600 s old).
- **Not modelled.** Transport security (TLS, mTLS, OAuth), which authenticates the liar too; VI's suggested mandate
  lifetimes; the protocols that reduce to plain A2A on these claims (MCP, IBM ACP, LangChain Agent Protocol, Agora,
  Coral, FIPA-ACL) or to RFC 9421 + replay at best (Visa TAP, OpenAI/Stripe ACP).
- **Which code.** The PCM rows are the dataset 2 run at the heads above. The protocol rows are `protocols.py` at this
  commit, over the same dataset (`results/baselines.jsonl`); per-class counts and reject reasons are in
  `results/results.json` (`receivers`, `lies_by_class`).

## Findings in detail (diagnosis from the run before)

The text below explains each finding as it stood before the fixes. F1, F3 and F5 are now fixed; F2 and F4 are open.

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
- **Repro:** `findings/ipv4_leading_zero.py` (both readings, the real connection, the current verdicts). The
  `findings/L16.H.0[1-7].json` files were in commit `9b430ab`.

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

## Dataset 2

For PCM's fixes, `gen.py` builds dataset 2 (926 messages). Its labels keep
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
- **(c):** no change was needed: `honest.H.15` and `.16` already test a 404.
- **H2 counts claims:** `report.py` now counts H2 as pre-registered, that is honest *claims* proven, so an honest
  `approved_by` without covers still counts under a schema that requires a covering one. It also shows how many
  honest messages got the verdict `accept`. For dataset 1 both counts were the same: 71/73.

## Dataset 1: the pre-final run

Before dataset 1's final-head run, the benchmark ran at Tracekit `e3221cf2b6` and pcm `b54cfe4` (commit `71cad5f`).
That run gave the same headline numbers, with timings of p50 1.2 ms (p99 2.0 ms) for Tracekit and p50 0.8 ms (p99 1.7 ms) for
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

  There are at least 10 messages per class per claim type that applies, and 10 to 46 in practice.

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
   denied by the auto-mode classifier. I did not retry them. The coordinator then moved both worktrees, and later
   moved them again, to the fixed heads this run uses.

## Limits

- **One machine:** macOS 26.3 arm64, Python 3.11.15. F1 depended on the platform.
- **The signer and executor are in-process.** The executor is `Custody` with an in-process client, not the HTTP
  executor service. The harness itself runs the tools it executes.
- **What the seed fixes:** the keys and every choice. Run ids, nonces, timestamps and signatures change each time the
  dataset is generated.
- **Stable across generations:** dataset 1, generated three times on two pairs of heads, gave the same counts in
  every cell, apart from the `L15.G.13` relabel before the pre-final run. Dataset 2 was generated once.

## Reproduce

```sh
cd <this repo>   # PYTHONPATH: a Tracekit checkout; the standalone verifier is found under verifier/python
PYTHONPATH=<tracekit> python -m bench.lies gen      # data/dataset.jsonl, data/meta.json (~1 min)
PYTHONPATH=<tracekit> python -m bench.lies run --verifier all   # results/{tracekit,standalone,baselines}.jsonl
# baselines.jsonl holds a2a, sigonly and the six protocol receivers (no extra dependencies)
python -m bench.lies report                          # results/results.json, findings/, the tables below
```

<!-- auto:begin -->
_926 messages; verifiers: tracekit, standalone, a2a, sigonly, a2a-card, uagents, rfc9421, ap2, vi, scitt._

### Pass/fail

| verifier | H1 no false accept | H2 honest proven >= 99% | H3 T1-only unproven 100% |
|---|---|---|---|
| tracekit | FAIL: 10 of 712 lies accepted (1.4%, 95% CI [0.76%, 2.57%]); 626 reject, 76 accept-unproven, 10 accept | FAIL: 76/78 claims (97.4%); 81/83 messages (97.6%; 69 with verdict accept) | PASS: 72/72 (100.0%) |
| standalone | FAIL: 10 of 712 lies accepted (1.4%, 95% CI [0.76%, 2.57%]); 626 reject, 76 accept-unproven, 10 accept | FAIL: 76/78 claims (97.4%); 81/83 messages (97.6%; 69 with verdict accept) | PASS: 72/72 (100.0%) |

H4 verifier agreement (conformance fields and reason class): **PASS**, 926/926 agree.

Baselines (no pass bar), lies accepted: a2a 712/712 (100.0%); sigonly 643/712 (90.3%).

### False-accept rate by lie scope and threat model

| verifier | false accepts | rate | Wilson 95% CI | by lie scope | by threat model |
|---|---|---|---|---|---|
| tracekit | 10/712 | 1.4% | [0.76%, 2.57%] | authority 0/90; claim 0/192; delivery 0/50; encoding 0/96; evidence 0/265; freshness 10/10; message 0/9 | in 10/701; signer-bug 0/11 |
| standalone | 10/712 | 1.4% | [0.76%, 2.57%] | authority 0/90; claim 0/192; delivery 0/50; encoding 0/96; evidence 0/265; freshness 10/10; message 0/9 | in 10/701; signer-bug 0/11 |
| a2a | 712/712 | 100.0% | [99.46%, 100.00%] | authority 90/90; claim 192/192; delivery 50/50; encoding 96/96; evidence 265/265; freshness 10/10; message 9/9 | in 701/701; signer-bug 11/11 |
| sigonly | 643/712 | 90.3% | [87.91%, 92.27%] | authority 82/90; claim 192/192; delivery 50/50; encoding 71/96; evidence 229/265; freshness 10/10; message 9/9 | in 632/701; signer-bug 11/11 |
| a2a-card | 712/712 | 100.0% | [99.46%, 100.00%] | authority 90/90; claim 192/192; delivery 50/50; encoding 96/96; evidence 265/265; freshness 10/10; message 9/9 | in 701/701; signer-bug 11/11 |
| uagents | 702/712 | 98.6% | [97.43%, 99.24%] | authority 90/90; claim 192/192; delivery 40/50; encoding 96/96; evidence 265/265; freshness 10/10; message 9/9 | in 691/701; signer-bug 11/11 |
| rfc9421 | 682/712 | 95.8% | [94.05%, 97.03%] | authority 90/90; claim 192/192; delivery 20/50; encoding 96/96; evidence 265/265; freshness 10/10; message 9/9 | in 671/701; signer-bug 11/11 |
| ap2 | 504/712 | 70.8% | [67.34%, 74.01%] | authority 21/90; claim 146/192; delivery 36/50; encoding 83/96; evidence 208/265; freshness 10/10; message 0/9 | in 501/701; signer-bug 3/11 |
| vi | 509/712 | 71.5% | [68.06%, 74.68%] | authority 26/90; claim 146/192; delivery 36/50; encoding 83/96; evidence 208/265; freshness 10/10; message 0/9 | in 507/701; signer-bug 2/11 |
| scitt | 550/712 | 77.2% | [74.03%, 80.18%] | authority 90/90; claim 182/192; delivery 50/50; encoding 96/96; evidence 113/265; freshness 10/10; message 9/9 | in 539/701; signer-bug 11/11 |

### Dataset

| class | A | F | G | H | T | X | total |
|---|---|---|---|---|---|---|---|
| AB-strip | 12T | 12T |  | 20T | 12T | 4T | 60 |
| AB-t1 |  | 12U |  | 12U | 12U |  | 36 |
| honest | 22T | 12T | 13T | 20T | 12T | 4T | 83 |
| L1 | 12F | 12F |  | 12F | 12F |  | 48 |
| L2 | 12F | 12F |  | 12F | 12F |  | 48 |
| L3 | 23F | 12F |  | 12F | 12F |  | 59 |
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
| L16 | 4T 20F | 7T 18F | 4T 9F | 16T 30F | 4T 19F |  | 131 |

T = tests_passed, H = reached_host, F = file_written, A = approved_by, G = grants, X = several claims; counts as nT (TRUE), nF (FALSE), nU (UNKNOWABLE). Threat model: {'in': 915, 'signer-bug': 11}.

### Confusion matrix: tracekit

| class | T:accept | T:accept-unproven | T:reject | F:accept | F:accept-unproven | F:reject | U:accept | U:accept-unproven | U:reject |
|---|---|---|---|---|---|---|---|---|---|
| AB-strip |  | 60 |  |  |  |  |  |  |  |
| AB-t1 |  |  |  |  |  |  |  | 36 |  |
| honest | 69 | 12 | 2 |  |  |  |  |  |  |
| L1 |  |  |  |  | 10 | 38 |  |  |  |
| L2 |  |  |  |  | 3 | 45 |  |  |  |
| L3 |  |  |  |  | 11 | 48 |  |  |  |
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
| L16 | 5 | 12 | 18 |  | 16 | 80 |  |  |  |

### Confusion matrix: standalone

| class | T:accept | T:accept-unproven | T:reject | F:accept | F:accept-unproven | F:reject | U:accept | U:accept-unproven | U:reject |
|---|---|---|---|---|---|---|---|---|---|
| AB-strip |  | 60 |  |  |  |  |  |  |  |
| AB-t1 |  |  |  |  |  |  |  | 36 |  |
| honest | 69 | 12 | 2 |  |  |  |  |  |  |
| L1 |  |  |  |  | 10 | 38 |  |  |  |
| L2 |  |  |  |  | 3 | 45 |  |  |  |
| L3 |  |  |  |  | 11 | 48 |  |  |  |
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
| L16 | 5 | 12 | 18 |  | 16 | 80 |  |  |  |

### Confusion matrix: a2a

| class | T:accept | T:accept-unproven | T:reject | F:accept | F:accept-unproven | F:reject | U:accept | U:accept-unproven | U:reject |
|---|---|---|---|---|---|---|---|---|---|
| AB-strip | 60 |  |  |  |  |  |  |  |  |
| AB-t1 |  |  |  |  |  |  | 36 |  |  |
| honest | 83 |  |  |  |  |  |  |  |  |
| L1 |  |  |  | 48 |  |  |  |  |  |
| L2 |  |  |  | 48 |  |  |  |  |  |
| L3 |  |  |  | 59 |  |  |  |  |  |
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
| L16 | 30 |  | 5 | 96 |  |  |  |  |  |

### Confusion matrix: sigonly

| class | T:accept | T:accept-unproven | T:reject | F:accept | F:accept-unproven | F:reject | U:accept | U:accept-unproven | U:reject |
|---|---|---|---|---|---|---|---|---|---|
| AB-strip | 60 |  |  |  |  |  |  |  |  |
| AB-t1 |  |  |  |  |  |  | 36 |  |  |
| honest | 83 |  |  |  |  |  |  |  |  |
| L1 |  |  |  | 48 |  |  |  |  |  |
| L2 |  |  |  | 48 |  |  |  |  |  |
| L3 |  |  |  | 59 |  |  |  |  |  |
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
| L16 | 30 |  | 5 | 71 |  | 25 |  |  |  |

### Detection per class (FALSE messages)

| class | tracekit | standalone | a2a | sigonly |
|---|---|---|---|---|
| L1 | 38/48 rejected, 48 not accepted | 38/48 rejected, 48 not accepted | 0/48 rejected, 0 not accepted | 0/48 rejected, 0 not accepted |
| L2 | 45/48 rejected, 48 not accepted | 45/48 rejected, 48 not accepted | 0/48 rejected, 0 not accepted | 0/48 rejected, 0 not accepted |
| L3 | 48/59 rejected, 59 not accepted | 48/59 rejected, 59 not accepted | 0/59 rejected, 0 not accepted | 0/59 rejected, 0 not accepted |
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
| L16 | 80/96 rejected, 96 not accepted | 80/96 rejected, 96 not accepted | 0/96 rejected, 0 not accepted | 25/96 rejected, 25 not accepted |

### Real protocols as receivers (added after pre-registration)

| receiver | lies accepted | rate | Wilson 95% CI | honest accepted |
|---|---|---|---|---|
| a2a | 712/712 | 100.0% | [99.46%, 100.00%] | 83/83 |
| sigonly | 643/712 | 90.3% | [87.91%, 92.27%] | 83/83 |
| a2a-card | 712/712 | 100.0% | [99.46%, 100.00%] | 83/83 |
| uagents | 702/712 | 98.6% | [97.43%, 99.24%] | 83/83 |
| rfc9421 | 682/712 | 95.8% | [94.05%, 97.03%] | 83/83 |
| ap2 | 504/712 | 70.8% | [67.34%, 74.01%] | 67/83 |
| vi | 509/712 | 71.5% | [68.06%, 74.68%] | 67/83 |
| scitt | 550/712 | 77.2% | [74.03%, 80.18%] | 83/83 |
| ap2 ∩ scitt ∩ rfc9421 | 365/712 | 51.3% | [47.60%, 54.92%] | 67/83 |

Lies accepted per class:

| class | a2a | sigonly | a2a-card | uagents | rfc9421 | ap2 | vi | scitt | tracekit |
|---|---|---|---|---|---|---|---|---|---|
| L1 | 48/48 | 48/48 | 48/48 | 48/48 | 48/48 | 36/48 | 36/48 | 38/48 | 0/48 |
| L2 | 48/48 | 48/48 | 48/48 | 48/48 | 48/48 | 36/48 | 36/48 | 48/48 | 0/48 |
| L3 | 59/59 | 59/59 | 59/59 | 59/59 | 59/59 | 38/59 | 38/59 | 59/59 | 0/59 |
| L4 | 36/36 | 36/36 | 36/36 | 36/36 | 36/36 | 36/36 | 36/36 | 36/36 | 0/36 |
| L5 | 66/66 | 66/66 | 66/66 | 66/66 | 66/66 | 42/66 | 42/66 | 21/66 | 0/66 |
| L6 | 60/60 | 16/60 | 60/60 | 60/60 | 60/60 | 52/60 | 52/60 | 48/60 | 0/60 |
| L7 | 42/42 | 42/42 | 42/42 | 42/42 | 42/42 | 32/42 | 32/42 | 42/42 | 0/42 |
| L8 | 55/55 | 55/55 | 55/55 | 55/55 | 55/55 | 39/55 | 45/55 | 38/55 | 0/55 |
| L9 | 48/48 | 48/48 | 48/48 | 48/48 | 48/48 | 36/48 | 36/48 | 0/48 | 0/48 |
| L10 | 40/40 | 40/40 | 40/40 | 40/40 | 40/40 | 30/40 | 30/40 | 10/40 | 10/40 |
| L11 | 50/50 | 50/50 | 50/50 | 40/50 | 20/50 | 36/50 | 36/50 | 50/50 | 0/50 |
| L12 | 18/18 | 18/18 | 18/18 | 18/18 | 18/18 | 0/18 | 0/18 | 18/18 | 0/18 |
| L13 | 10/10 | 10/10 | 10/10 | 10/10 | 10/10 | 0/10 | 0/10 | 10/10 | 0/10 |
| L14 | 23/23 | 23/23 | 23/23 | 23/23 | 23/23 | 7/23 | 6/23 | 23/23 | 0/23 |
| L15 | 13/13 | 13/13 | 13/13 | 13/13 | 13/13 | 1/13 | 1/13 | 13/13 | 0/13 |
| L16 | 96/96 | 71/96 | 96/96 | 96/96 | 96/96 | 83/96 | 83/96 | 96/96 | 0/96 |

### approved_by with the receiver's SPEC 6.6 scope check

| verifier | messages | n | verdict | verdict after the scope check |
|---|---|---|---|---|
| tracekit | L3 message-scope lies | 9 | {"accept-unproven": 9} | {"accept-unproven": 9} |
| tracekit | honest approved_by | 22 | {"accept-unproven": 12, "accept": 10} | {"accept-unproven": 17, "accept": 5} |
| tracekit | all approved_by lies | 153 | {"reject": 140, "accept-unproven": 13} | {"reject": 140, "accept-unproven": 13} |
| standalone | L3 message-scope lies | 9 | {"accept-unproven": 9} | {"accept-unproven": 9} |
| standalone | honest approved_by | 22 | {"accept-unproven": 12, "accept": 10} | {"accept-unproven": 17, "accept": 5} |
| standalone | all approved_by lies | 153 | {"reject": 140, "accept-unproven": 13} | {"reject": 140, "accept-unproven": 13} |

### Cost

| claim type (honest) | n | plain A2A p50 B | PCM p50 B | PCM p99 B | overhead p50 B | overhead p99 B | PCM/plain p50 |
|---|---|---|---|---|---|---|---|
| A | 22 | 467 | 6131 | 8399 | 5664 | 7916 | 13.0x |
| F | 12 | 596 | 4404 | 4408 | 3808 | 3811 | 7.4x |
| G | 13 | 428 | 1907 | 2569 | 1480 | 2141 | 4.5x |
| H | 20 | 438 | 4163 | 4181 | 3730 | 3739 | 9.5x |
| T | 12 | 450 | 4161 | 4181 | 3711 | 3719 | 9.2x |
| X | 4 | 720 | 11659 | 11697 | 10939 | 10964 | 16.2x |

| verifier | messages timed | p50 ms | p99 ms | max ms |
|---|---|---|---|---|
| tracekit | 876 | 1.224 | 2.423 | 6.457 |
| standalone | 876 | 0.797 | 1.811 | 2.427 |

### Ablations

| ablation | verifier | verdicts |
|---|---|---|
| AB-strip | tracekit | {"accept-unproven": 60} |
| AB-strip | standalone | {"accept-unproven": 60} |
| AB-strip | a2a | {"accept": 60} |
| AB-strip | sigonly | {"accept": 60} |
| AB-strip | a2a-card | {"accept": 60} |
| AB-strip | uagents | {"accept": 60} |
| AB-strip | rfc9421 | {"accept": 60} |
| AB-strip | ap2 | {"accept": 48, "reject": 12} |
| AB-strip | vi | {"accept": 48, "reject": 12} |
| AB-strip | scitt | {"reject": 60} |
| AB-t1 | tracekit | {"accept-unproven": 36} |
| AB-t1 | standalone | {"accept-unproven": 36} |
| AB-t1 | a2a | {"accept": 36} |
| AB-t1 | sigonly | {"accept": 36} |
| AB-t1 | a2a-card | {"accept": 36} |
| AB-t1 | uagents | {"accept": 36} |
| AB-t1 | rfc9421 | {"accept": 36} |
| AB-t1 | ap2 | {"accept": 36} |
| AB-t1 | vi | {"accept": 36} |
| AB-t1 | scitt | {"accept": 36} |

### Every failure

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
- **honest not proven** (tracekit) `honest.H.15` t2-fetch-http-error-status -> reject: reached_host: failed (call WebFetch-177 reached 127.0.0.1, and failed) http://127.0.0.1:62610/missing reached 127.0.0.1 (error)
- **honest not proven** (tracekit) `honest.H.16` t2-fetch-http-error-status -> reject: reached_host: failed (call WebFetch-181 reached api.example.com, and failed) http://api.example.com/missing reached api.example.com (error)
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
- **honest not proven** (standalone) `honest.H.15` t2-fetch-http-error-status -> reject: reached_host: failed (call WebFetch-177 reached 127.0.0.1, and failed) http://127.0.0.1:62610/missing reached 127.0.0.1 (error)
- **honest not proven** (standalone) `honest.H.16` t2-fetch-http-error-status -> reject: reached_host: failed (call WebFetch-181 reached api.example.com, and failed) http://api.example.com/missing reached api.example.com (error)
<!-- auto:end -->
