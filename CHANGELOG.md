# Changelog

All notable changes to the nod Attestation Protocol are documented here.
This project follows [Semantic Versioning](https://semver.org/).

Format: `## [version] — YYYY-MM-DD`
Breaking changes are marked **BREAKING**.
Deprecations are marked **DEPRECATED**.

---

## [0.1.0] — 2026-02-19

### Initial Pre-Release

This is the first published version of the nod Attestation Protocol.
It is a pre-release — breaking changes may occur before v1.0.0 as the
specification is validated against real implementations and community feedback.

**What's included:**

- Evidence schema specification — machine-readable proof-of-satisfaction
  definitions for compliance rules, covering artifact type, required fields,
  producer, cadence, retention, and verification method
- Contract export format — serialized compliance contract structure including
  contract ID computation for attestation anchoring
- Attestation block specification — structured JSON format for agent execution
  records, including result values, evidence references, and HMAC signing
- Verification requirements — conformance checklist for validators covering
  schema conformance, contract binding, coverage, evidence schema conformance,
  temporal coherence, and signature validation
- Audit package structure — complete compliance record format combining spec
  scan, contract export, attestation, validation results, evidence artifacts,
  and package signature
- Security considerations — hash algorithm requirements, HMAC key management
  guidance, replay prevention, and agent identity notes
- Conformance definitions for emitters and validators
- Reference validator (Python, offline, no external dependencies)
- Example attestation block, evidence schema, and contract export

**Known limitations in this version:**

- The reference validator does not yet implement SARIF output. Plain text
  output only. SARIF support is planned for v0.2.0.
- The audit package assembler is not yet included. Manual assembly per the
  spec is required until v0.2.0.
- The implementations registry is empty. If you implement this protocol,
  see GOVERNANCE.md to be listed.

---

## Planned Milestones

### [0.2.0] — Target: Q2 2026

- SARIF output from reference validator
- Audit package assembler in reference validator
- Implementation report from nod v2.0 integration
- Schema refinements based on early implementer feedback
- Additional examples covering negotiation protocol use case

### [0.3.0] — Target: Q3 2026

- Attestation return protocol for agent-to-agent (A2A) trust negotiation
- Per-session attestation requirements for negotiated trust handshake
- Replay prevention reference implementation
- Agent identity guidance expanded based on community input

### [1.0.0] — Target: Q4 2026

- Stable release — breaking changes require major version increment after this point
- Full SARIF compatibility
- Complete nod v3.0 integration validated
- At least two independent conformant implementations documented
- Governance updated to reflect community participation

---

## How to Read This Changelog

Each version entry lists changes under one or more of the following categories:

- **Added** — new features or specification sections
- **Changed** — changes to existing behavior or specification language
- **Deprecated** — features that will be removed in a future version
- **Removed** — features removed in this version
- **Fixed** — corrections to specification errors or ambiguities
- **Security** — changes with 
security implications
