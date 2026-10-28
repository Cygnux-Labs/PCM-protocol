---
name: Verifier bug
about: pcm-verify, Tracekit or another verifier gives a result the spec or a vector does not
labels: verifier
---

**Which verifier** (`pcm-verify` version or commit, `tracekit --version`, or another implementation)

**The vector, or the message with its trust and schema documents** (secrets and hostnames removed)

**The result it gave, and the result you expected** (the conformance fields of SPEC 13.2, and the SPEC sections that
decide it)

For a message a verifier accepts that it should reject, do not open an issue: see SECURITY.md.
