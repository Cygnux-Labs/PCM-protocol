# PCM: Proof-Carrying Messages

Agents pass claims to each other that nobody can check.

Agent A asks agent B to refund $120 on order 81. A says alice approved refunds up to $200 for that order. B has only
A's word for it. If A was prompt-injected, or another process sends the message in A's name, B pays out anyway. If A
says "the tests passed", B can't tell whether a test ran, whether it passed, or whether A just wrote the words.

PCM is an open message format that lets B check before it acts. A PCM message carries:

- **who sent it**, signed by a signer service the agent can't control, which signs only as the sending run's own
  identity;
- **what it asks for**, a typed intent checked against a schema both sides agreed on by its hash;
- **what it claims**, each claim with records from the sender's signed log and their Merkle inclusion proofs;
- **who allowed it**, a chain of grants that starts with a person's approval and can only get narrower.

B checks all of it offline, with the keys it already pins. Each claim comes back `proven`, `unproven` or `failed`. A
claim that rests only on the agent's word is `unproven`, never `proven`.

## A worked example: the refund

This is what `tracekit pcm demo` does, with a real signer:

1. Agent A asks for a grant: "A may send `refund.request` with `amount <= 20000` (cents) and `order == 81`, for one
   hour". The signer won't sign that on A's say-so. It holds the request until alice, a person, approves it. Then it
   signs the grant.
2. A asks B for a $120.00 refund. It attaches alice's grant and a claim, `approved_by alice`, with records from A's
   signed log as evidence: alice's approval, the request it answers and the `pcm.grant` decision she approved. The
   signer signs the message as A, and only as A.
3. B checks the signature, the schema, the grant and the evidence: **accept**.
4. A sends the same request, adding "tests passed" with no evidence: **accept-unproven**. B sees that this part is
   only A's word.
5. Someone changes one digit in a record of the evidence: **reject** (`record 1: hash does not match the event`).
6. A asks for $500.00: **reject** (`grant 0: amount 50000 breaks amount <= 20000`). The grant, not A, sets the limit.
7. A asks the signer to sign a message as B: the signer refuses.

```text
$ tracekit pcm demo
  alice approves agent A's grant: refund.request, amount <= $200.00, order == 81, until 18:00Z, can be passed on: no
  A -> B  refund.request {amount $120.00, order 81} + approved_by(alice)
      B: ACCEPT           signature ok · replay ok · schema ok · grant ok (alice, 1 step) · approved_by proven (approval seq 4 by alice of "pcm.grant" call grant-1, which issued this message's root grant)
  A -> B  same request + tests_passed(pytest tests/test_refund.py), no evidence
      B: ACCEPT-UNPROVEN  tests_passed: unproven (no evidence)
  A -> B  approved_by with one record hash changed
      B: REJECT           approved_by: failed (record 1: hash does not match the event)
  A -> B  refund.request {amount $500.00, order 81} + approved_by(alice)
      B: REJECT           grant: grant 0: amount 50000 breaks amount <= 20000
  A asks the signer to sign as B
      signer: forbidden: the signer signs only as the calling run's own agent (uid:990101, run 682b33a74fb7e277f59f38d40404dcae, tenant default)
```

## Verify a message

With the standalone verifier in `verifier/python`:

```sh
pip install ./verifier/python
python -m pcm_verify MESSAGE --trust TRUST --schema SCHEMA --me uid:990102
```

`MESSAGE` is the message JSON, `TRUST` pins the signer's log key (`{"logs": ["<vkey>"]}`), `SCHEMA` is the schema
document of the message's intent, and `--me` is the receiver's own identity, so a message sent to someone else is
rejected. Tools are placed with PCM 0.1's frozen table, `registry/tools.json`, which the package ships. It prints the
verdict: `accept`, `accept-unproven` or `reject`, with the reasons and the checks it skipped (`not checked: replay`).

Hosts are compared in printable ASCII only (SPEC 6.7): a `reached_host` claim resting on a URL with a space, a tab,
a `%` in its host or any non-ASCII character is `unproven`. A sender fetches and claims a name in another script in
its `xn--` form (`xn--bcher-kva.example`, not `bücher.example`).

The CLI does not check replay: it has no memory of earlier messages. That is fine for an audit. A receiver that acts
on messages keeps one `pcm_verify.Replay` for its whole life and passes it to `pcm_verify.verify` (SPEC section 9).
A receiver takes each message once per identity, across all its replicas; `pcm_verify.Replay` lives in one process,
so replicas that answer for one identity must route each sender to one replica or share the state.

## What is here

| Path | What |
|---|---|
| [`SPEC.md`](SPEC.md) | the PCM 0.1 draft specification |
| [`schemas/`](schemas) | JSON Schemas of the message, grant, claim, evidence and schema document |
| [`vectors/`](vectors) | test vectors: inputs and the results a verifier must give |
| [`registry/tools.json`](registry/tools.json) | PCM 0.1's frozen tool placement table (SPEC 10.2) |
| [`registry/tracekit.event.v2.json`](registry/tracekit.event.v2.json) | the event schema of the evidence profile `tracekit.event.v2`, as Tracekit ships it |
| [`verifier/python`](verifier/python) | the standalone verifier, `pcm_verify`: Python, with no Tracekit code |
| [`docs/ts-verifier-plan.md`](docs/ts-verifier-plan.md) | the plan for a TypeScript verifier |

## Reference implementation

[Tracekit](https://github.com/Cygnux-Labs/Tracekit) is the reference implementation. Its signer signs PCM messages and
grants (`pcm_sign`, `pcm_grant`, `pcm_delegate`) and hands out evidence (`pcm_evidence`). Its `tracekit.pcm.verify`
produced every vector here. Where this repo and Tracekit disagree, that is a bug in one of them: open an issue.
Appendix C of `SPEC.md` says where each rule lives in Tracekit's code and where Tracekit does less than the spec asks.

## Status

Draft 0.1, experimental. The wire format (`"pcm": 0`) can change in any 0.x draft. Don't build anything you can't
change on it yet. What is implemented today and what is still draft is marked in `SPEC.md`; the questions
earlier drafts left open (base64, hosts, paths, test commands, senders, keys) are decided rules, marked
"(decided, 0.1)", and Appendix B lists what remains open.

## License

MIT, [`LICENSE`](LICENSE). It covers everything in this repository: the specification, the schemas, the test
vectors and the code.
