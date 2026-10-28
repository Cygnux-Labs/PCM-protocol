# PCM-Lies pre-registration

This header was added when the file was committed. Everything after the line below is the design as it was written,
unchanged.

- **When it was written:** 2026-10-28 at 04:48 IST (UTC+05:30), by the file's modification time, as a local planning
  note. The first benchmark commit in this repository, `71cad5f`, is from 05:31 the same day.
- **No public timestamp.** The note was not committed or published anywhere before the results. It is committed here,
  as it was, after them. Its date rests on a local file time and on this repository's commit times, which the authors
  control, so read it as the design the run followed, not as proof that the design came first.
- **Where the run departed from it:**
  - **The improve loop stopped before H1 and H2 passed.** The design says every false accept blocks publication and
    the benchmark re-runs "until H1–H4 pass". Three findings were fixed in the spec and both verifiers, with vectors
    (F1, F3, F5), and the run was repeated. Two were not: the 10 false accepts of stale evidence (F2, H1) and the two
    honest fetches answered 404 (F4, H2). They are published as limits of PCM 0.1 (SPEC 14.13, 6.6), with designs
    for a later draft in Appendix B (questions 5 and 6).
  - **The dataset grew after the first run.** Dataset 2 adds 47 messages for the fixes, and four honest fetches with
    numeric host spellings moved to L16, so that the honest set uses canonical spellings (RESULTS.md, "Dataset 2").
    One message, `L15.G.13`, was relabelled before the final run of dataset 1 (RESULTS.md, "Harness fixes").
  - **L11 has two more replays** than the three listed: outside the time window and at or below the sender's floor.
  - **Baseline (b) checks the PCM signer's signature** (`sigonly`), a key the sender can't use, not a key the sender
    holds. So it catches forged and stripped signatures, and accepts 643 of 712 lies rather than all of them.
  - **H2 was first counted per message.** `report.py` counted honest messages whose claims are all proven. It now
    reports honest claims, as written here (76 of 78), and messages too (81 of 83); the pass bar is applied to claims.
  - **Six protocol receivers were added after the results** (A2A with a signed Agent Card, uAgents, RFC 9421 with
    replay checks, AP2, Verifiable Intent, SCITT). No hypothesis covers them, and RESULTS.md reports them apart.

---

# PCM-Lies: does a receiver catch an agent that lies to it? (pre-registered, 2026-10-28)

Purpose: the core result for the PCM paper and the public repo. Measure, on real signer evidence, how often a
receiving agent accepts a false claim from a sending agent under (a) plain A2A, (b) a sender-signed message without
evidence (JWS-style: proves who, not what), (c) PCM 0.1. Then fix whatever PCM gets wrong, and re-run.

## Threat model
The sender agent controls its own process, messages, T1 reports and any file it can write; it does not control the
signer, its keys, its log, or T2 results (Tracekit's model). The receiver has only the message and its trust.json.

## Hypotheses and pass criteria (fixed before running)
- H1 (safety): no false claim is accepted as proven by PCM. Pass: 0 false accepts over every lie class; any false
  accept is a blocker fixed (spec or code) before publication, then the whole benchmark re-runs.
- H2 (honest claims): honest claims backed by T2/signer evidence are proven. Pass: >= 99% proven; each miss explained.
- H3 (honest unknowns): claims whose only evidence is agent-written (T1) come out unproven, never proven. Pass: 100%.
- H4 (agreement): Tracekit's verifier and the standalone verifier in ~/pcm/verifier give the same verdict and reason
  class on every message. Pass: 100%; each disagreement is a bug in one of them.
- H5 (baselines): (a) and (b) accept 100% of lies (they have nothing to check) — reported as the comparison, not tested.
- Cost: message size overhead and verify time per message (p50/p99), reported.

## Lie taxonomy (each a mutation operator applied to honest messages; >= 10 instances per class per claim type)
Content lies (the sender says something false about the world):
L1 fabricated event (no such call: tests never ran, host never reached, file never written, no approval);
L2 wrong outcome (tests ran and failed, claims passed; fetch failed, claims reached);
L3 wrong object (reached host B, claims A; wrote file G, claims F; approval for $5 refund, claims $500 / other tool);
L4 T1-only evidence (the agent's own report is the only record).
Evidence lies (the sender forges or reuses proof):
L5 edited record bytes; L6 forged or stripped signature; L7 records spliced from another run of the same log;
L8 records from another log or tenant; L9 inclusion proof or checkpoint for a different tree; L10 stale checkpoint
(proof older than claim); L11 replayed message (same nonce, other recipient, after restart);
Authority lies (grants): L12 grant widened on delegation (bigger limit, more tools, longer expiry); L13 expired grant;
L14 grant from a non-person or wrong tenant; L15 delegation chain with a forged or missing link.
Encoding lies: L16 Unicode/IDNA host look-alikes, percent-escapes, trailing dots, IPv4/IPv6 alternate forms (the
round-4 class), duplicate JSON keys, non-JCS bytes.

Ground truth comes from the generator, never from a verifier: each message is labelled TRUE, FALSE or UNKNOWABLE
(T1-only) when it is built.

## Data (rawest material)
Honest messages come from real runs: a real Tracekit signer, real tool calls through the T2 executor (a real pytest
run that passes and one that fails; a real HTTP fetch to a local server; a real file write; a real approval answered by
a person identity), then `run.pcm_send` with `run.pcm_evidence`. Lies are mutations of those messages and their
evidence, plus lies the sender tells honestly-signed (a real message whose claim names evidence that doesn't support
it). Fixed seed; every message, label and verdict saved as JSONL so others can re-run any verifier on the same set.

## Method
Confusion matrix per class (truth x verdict accept/unproven/reject), false-accept rate with Wilson 95% CI, per-class
detection rate, reason-class agreement between the two verifiers, size and latency. Ablations: PCM with evidence
stripped (should be unproven, not reject); PCM with T1 records only.

## Outputs
~/pcm/bench/lies/: generator, runner, dataset (JSONL), results JSON, a short RESULTS.md (tables + what failed and
what was fixed). One entry in ~/tracekit-dogfood/reports/experiments-log.md. A reusable command:
`python -m bench.lies run --verifier tracekit|standalone`.

## Improve loop
Every false accept, verifier disagreement, or honest claim not proven goes to a fix (spec, Tracekit or the standalone
verifier), with a vector added to vectors/, and the benchmark re-runs until H1–H4 pass.
