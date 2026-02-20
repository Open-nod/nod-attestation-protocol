# Governance

The nod Attestation Protocol is maintained by the OpenNod project under the
Apache 2.0 license. This document describes how the protocol is maintained,
how changes are proposed, and how decisions are made.

---

## Maintainer

The protocol is currently maintained by a single lead maintainer. The maintainer
is responsible for reviewing proposals, accepting changes, publishing releases,
and ensuring the specification remains coherent and implementable.

As the community grows and additional implementers contribute, governance will
evolve to reflect that participation. Changes to this governance document will
follow the same proposal process as changes to the specification itself.

---

## Guiding Principles

**Implementability first.** Changes to the protocol must be implementable by
agent framework developers without requiring deep compliance expertise. If a
proposed change cannot be expressed as code, it belongs in guidance documentation,
not the specification.

**Backward compatibility.** Breaking changes are taken seriously. Before v1.0.0,
breaking changes are permitted with clear changelog documentation. After v1.0.0,
breaking changes require a major version increment and a migration path.

**Evidence over assertion.** The protocol exists to make compliance claims
verifiable rather than asserted. This principle applies to governance too —
decisions should be traceable to stated rationale, not opaque.

**Human review remains.** The protocol automates evidence production and
verification. It does not automate compliance judgment. Governance decisions
that would reduce the human review requirement in the audit package will not
be accepted.

---

## How to Propose a Change

**For bugs and clarifications:**
Open a GitHub issue describing the problem, the current behavior, and the
expected behavior. Label it `bug` or `clarification`. The maintainer will
respond within a reasonable timeframe.

**For new features or schema changes:**
Open a GitHub issue labeled `proposal` with the following information:
- What problem does this change solve
- Who is affected — emitters, validators, or both
- Whether it is a breaking change
- A sketch of the proposed schema or specification change

Allow time for community discussion before a decision is made. The maintainer
will close the issue with an accepted or declined decision and stated rationale.

**For editorial changes** (typos, formatting, wording that does not change meaning):
Open a pull request directly. These will be merged without a prior issue.

---

## Decision Making

The lead maintainer makes final decisions on all changes to the specification,
schema, and governance. Decisions are informed by community discussion in issues
and pull requests but are not determined by vote at this stage of the project.

Decisions will be documented in the relevant issue or pull request before closing,
so the rationale is part of the permanent record.

---

## Versioning and Releases

The protocol follows semantic versioning:

- **Patch** (0.1.x) — corrections, clarifications, and editorial changes that
  do not affect conformance
- **Minor** (0.x.0) — additive changes that do not break existing conformant
  implementations
- **Major** (x.0.0) — breaking changes that require existing implementations
  to update

Release notes are published in [CHANGELOG.md](CHANGELOG.md).

Pre-release versions (0.x.x) may include breaking changes between minor versions.
The changelog will clearly identify breaking changes.

---

## Implementations Registry

If you have implemented the nod Attestation Protocol in a tool or agent framework,
open an issue labeled `implementation` with:
- The name and repository of your implementation
- Whether it is an emitter, a validator, or both
- The protocol version it conforms to

Accepted implementations will be listed in the README.

---

## Code of Conduct

Contributors are expected to engage respectfully and in good faith. The maintainer
reserves the right to close issues or pull request
s that do not meet this standard.
