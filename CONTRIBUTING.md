# Contributing

This repository holds the PCM specification ([SPEC.md](SPEC.md)), its schemas and test vectors, and `pcm-verify`, a
standalone verifier. [Tracekit](https://github.com/Cygnux-Labs/Tracekit) is the reference implementation: each
vector's `expected` is what Tracekit returns.

## Run the tests

```sh
git clone https://github.com/Cygnux-Labs/PCM-protocol && cd PCM-protocol
python -m venv .venv && . .venv/bin/activate     # Python 3.11.4 or later
pip install ./verifier/python pytest
cd verifier/python && python -m pytest -q
```

The tests run the verifier on every vector in `vectors/` and compare the conformance fields (SPEC 13.2), check that
every example SPEC.md and README.md tie to a vector shows that vector's value, and cover hostile input and the CLI's
exit codes. They need no network and no Tracekit.

To check another verifier, run it on each vector's `input` and compare with its `expected`; the format is in
[vectors/README.md](vectors/README.md).

## Propose a spec change

1. Open an issue first (the **Spec change** template), before a pull request. Cite the SPEC sections it touches (for
   example 6.7 or 14.13), say what a verifier does now and what it should do, and give the message or vector that
   shows the difference.
2. Every rule change comes with a vector that pins it: one a verifier that follows the old rule gets wrong. A rule no
   vector can express, such as a trust or schema document refused as a configuration error (13.2), comes with a test
   in `verifier/python/tests/`.
3. The spec, `pcm-verify` and Tracekit change together. Where this repository and Tracekit disagree, one of them has
   a bug: open a **Verifier bug** issue with the vector or message.

0.x drafts may change anything, incompatibly too (SPEC 16). A change to what is signed, or how, needs a new wire
version.

## Regenerate the vectors and schemas

The vectors and schemas are written from Tracekit, never by hand, so the two can't drift. With a Tracekit checkout
at the version the README pins and its dependencies installed, from this repository's root:

```sh
PYTHONPATH=<tracekit checkout> python tools/gen_vectors.py   # vectors/<name>.json and vectors/index.json
PYTHONPATH=<tracekit checkout> python tools/gen_schemas.py   # schemas/, registry/tracekit.event.v2.json, the verifier's copies
```

A new vector is a new case in `tools/gen_vectors.py`; its name starts with its verdict (`accept-`,
`accept-unproven-`, `reject-`, `bad-input-`). Run ids, nonces, timestamps and signatures change on every run, so
commit the new vectors with the SPEC and README examples that quote them: the tests fail on an example that no
longer matches its vector.

## Security

Report vulnerabilities in the rules or the verifier privately (see [SECURITY.md](SECURITY.md)), never in a public
issue.

## Developer Certificate of Origin

Every commit in a pull request must be signed off under the [Developer Certificate of Origin 1.1](https://developercertificate.org/):
by adding the line below you certify that you wrote the change, or otherwise have the right to submit it under the
project's license.

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it, using your `user.name` and `user.email`. To fix older commits on your branch, run
`git rebase --signoff main` and push the branch again.
