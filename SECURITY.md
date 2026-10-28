# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/Cygnux-Labs/PCM-protocol/security/advisories/new), or by
email to info@cygnuxlabs.com, rather than a public issue. Include the commit or `pcm-verify` version, the SPEC
sections involved, and the message, trust and schema documents that show the problem (or the vector it breaks).

## Disclosure timeline

- **3 business days**: we acknowledge the report.
- **10 business days**: we confirm or reject it and share an initial severity assessment.
- **90 days** from the report: the default limit for a fix and coordinated public disclosure. We will agree an
  earlier date for a fix that ships sooner, or a later one if a fix needs it and you agree.
- Once a fix is released we publish a GitHub security advisory and credit you, unless you ask us not to.

If a vulnerability is being actively exploited we may disclose sooner, and will tell you first.

## Supported versions

| Version | Supported |
|---|---|
| The latest draft on `main` (PCM 0.1) and `pcm-verify` 0.1.x | Yes: fixes land as a new draft, with a vector |
| Earlier drafts | No |

## Scope

In scope:

- A message, grant or evidence the spec's rules accept that they should not: a false claim `proven`, a grant
  widened, a replayed or misaddressed message accepted. Section 14 lists the attacks the rules already answer.
- A rule that can be read two ways, so that two conforming verifiers give different verdicts on one message.
- A bug in `pcm-verify` that makes it accept what the spec rejects, or crash or hang on hostile input (14.12).

Out of scope:

- What the spec says PCM does not prove: that the agent is honest, that the signer recorded the truth (14.25), that
  something did not happen, that a state is current (14.13), or what a T2 call ran beyond its tool name's class
  (14.26). A report that one of these holds is expected behaviour.
- Bugs in Tracekit, the reference implementation: report them under
  [Tracekit's security policy](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md).

## Safe harbour

We will not pursue or support legal action against you for security research done in good faith that:

- stays within the scope above and targets your own installations or test systems;
- avoids privacy violations, data destruction and service disruption;
- does not access, keep or share data that is not yours beyond what is needed to show the problem;
- gives us reasonable time to fix the issue before any public disclosure, following the timeline above.

If legal action is started by a third party against you for such research, we will make it known that your work was
authorised under this policy.
