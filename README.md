# nod Attestation Protocol

**An open standard for compliance contracts and execution integrity in agentic systems.**

[![Protocol Version](https://img.shields.io/badge/protocol-v0.1.0-blue)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release-orange)](SPEC.md)

---

## What This Is

The nod Attestation Protocol defines how agentic systems prove they operated within
a compliance contract. It is a language-agnostic, pipeline-agnostic open standard
with three components:

**The Evidence Schema** — a machine-readable extension to compliance rule definitions
that specifies what proof of satisfaction looks like for each requirement: what artifact
type is expected, what fields it must contain, who produces it, and how frequently
it must be refreshed.

**The Attestation Block** — a structured, signed JSON document that an agent emits
upon task completion, mapping its execution results to the rule IDs it was governed
by and referencing the evidence artifacts it produced.

**The Verification Contract** — the validation logic that connects an attestation
block back to the compliance contract that governed the execution, confirming that
the agent operated within its defined constraints and that its evidence satisfies
the schemas defined for each rule.

Together these components close the loop between compliance intent and execution reality.

---

## Why This Matters

Agentic systems are increasingly performing consequential work — writing code, making
risk decisions, modifying configurations, generating compliance artifacts. The question
of whether an agent operated within its defined compliance boundaries is no longer
theoretical.

Current approaches to answering that question rely on human review after the fact,
audit trails that were not designed for agentic execution, and trust in the agent's
own assertions about its behavior. None of these are sufficient for regulated industries
or high-stakes agentic workflows.

The nod Attestation Protocol addresses this by making compliance evidence a byproduct
of agentic execution rather than a separate activity layered on top of it. An agent
that receives a compliance contract via the nod export format can emit a verifiable
record of its execution that any conformant validator can assess — without requiring
human assembly, interpretation, or trust in unverified claims.

---

## Who This Is For

**Agent framework developers** who want to make their systems auditable and compliant
by design. Implement the attestation emitter interface and your agents produce
verifiable compliance records automatically.

**Compliance practitioners and program managers** who need evidence of agentic
behavior that holds up to audit scrutiny. The attestation chain replaces manual
evidence assembly with a cryptographically verifiable package.

**Platform and toolchain builders** who want to integrate compliance contract
validation into CI/CD pipelines, approval workflows, or governance dashboards
without building the standard from scratch.

**AI governance researchers and practitioners** thinking about what compliance
looks like when agents write the code, make the decisions, and produce the artifacts.

---

## How It Works

```
1. Compliance rules are defined with evidence schemas
   (what proof of satisfaction looks like for each requirement)

2. A compliance contract is exported to an agent
   (the set of rules + evidence schemas that govern this execution)

3. The agent executes within the contract constraints

4. The agent emits a signed attestation block
   (per-rule results + evidence artifact references + execution metadata)

5. The attestation is validated against the contract
   (schema conformance, signature verification, evidence completeness)

6. An audit package is produced
   (spec scan + contract + attestation + validation + evidence artifacts + signature)
```

The audit package is self-contained and verifiable. An auditor does not need to
gather evidence — it is in the package, hashed, and signed.

---

## Repository Structure

```
nod-attestation-protocol/
├── README.md                        # This file
├── SPEC.md                          # Human-readable protocol specification
├── GOVERNANCE.md                    # How this standard is maintained and evolved
├── CHANGELOG.md                     # Version history and planned milestones
├── LICENSE                          # Apache 2.0
├── schema/
│   ├── attestation-block.json       # JSON Schema for attestation blocks
│   ├── evidence-schema.json         # JSON Schema for evidence schema extension
│   └── contract-export.json         # JSON Schema for contract export format
├── validator/
│   ├── validate.py                  # Reference validator (offline, no external deps)
│   └── README.md                    # How to use the reference validator
└── examples/
    ├── attestation-example.json     # Example conformant attestation block
    ├── evidence-example.yaml        # Example evidence schema on a rule
    └── contract-example.json        # Example contract export
```

---

## Current Status

This protocol is in **pre-release (v0.1.0)**. The schema definitions and specification
are published for community review and early implementation feedback. Breaking changes
may occur before v1.0.0. See [CHANGELOG.md](CHANGELOG.md) for the planned milestone path.

The reference implementation of the protocol in the [nod](https://github.com/opennod/nod)
tool is the primary validator. The reference validator in this repository is
language-agnostic and has no dependency on nod — it can be used independently
to validate attestation blocks against any conformant contract export.

---

## Implementing the Protocol

To implement the attestation emitter in your agent framework:

1. Read [SPEC.md](SPEC.md) — the full protocol specification
2. Review [examples/attestation-example.json](examples/attestation-example.json)
3. Implement the attestation block structure defined in [schema/attestation-block.json](schema/attestation-block.json)
4. Validate your implementation against the reference validator before publishing

To use evidence schemas in your compliance rule definitions:

1. Review [examples/evidence-example.yaml](examples/evidence-example.yaml)
2. Follow the schema defined in [schema/evidence-schema.json](schema/evidence-schema.json)
3. Use the [nod](https://github.com/opennod/nod) tool to validate evidence packages
   against your rule definitions

---

## Contributing

We welcome feedback, bug reports, and implementation reports from early adopters.
See [GOVERNANCE.md](GOVERNANCE.md) for how changes are proposed and accepted.

If you have implemented the protocol in a framework or tool, open an issue to be
listed in the implementations registry.

---

## Related Projects

- [opennod/nod](https://github.com/opennod/nod) — the compliance contract gatekeeper
  and primary reference implementation of this protocol
- [opennod/nod-rules](https://github.com/opennod/nod-rules) — community compliance
  contract library with evidence schemas for major AI governance frameworks

---

## License

Apache 2.0. See [LICENSE](LICENSE).
