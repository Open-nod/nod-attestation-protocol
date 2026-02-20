# nod Attestation Protocol Specification
# Version: 0.1.0
# Status: Pre-Release
# License: Apache 2.0

---

## 1. Introduction

### 1.1 Purpose

The nod Attestation Protocol defines a standard for expressing compliance requirements
as machine-readable contracts, and for agents to prove they operated within those
contracts through verifiable execution records.

It addresses a fundamental gap in agentic compliance: the absence of a standard way
to connect compliance intent — what an agent was required to do — with execution
reality — what the agent actually did and what evidence it produced.

### 1.2 Scope

This specification covers:

- The evidence schema extension that adds proof-of-satisfaction definitions to compliance rules
- The attestation block structure that agents emit upon task completion
- The contract export format that communicates compliance requirements to agents
- The verification requirements that conformant validators must implement
- The audit package structure that assembles the complete compliance record

This specification does not cover:

- The content of specific compliance rules or frameworks
- How agents should implement their internal behavior to satisfy compliance requirements
- How audit findings should be adjudicated
- Legal or regulatory interpretation of compliance conformance

### 1.3 Relationship to nod

The nod tool is the primary reference implementation of this protocol. The protocol
is defined independently of nod so that other tools and agent frameworks can implement
against it without dependency on nod. Conformance is determined by this specification,
not by behavior of the nod tool.

### 1.4 Versioning

This protocol follows semantic versioning. Breaking changes to schema structure or
validation requirements increment the major version. Additive changes increment the
minor version. Clarifications and corrections increment the patch version.

A validator that conforms to v1.x must accept attestation blocks produced by any
v1.x emitter. Attestation blocks carry a version field. Validators must reject
attestation blocks from incompatible major versions.

---

## 2. Definitions

**Compliance Rule** — a requirement that a specification or system must satisfy,
defined with an identifier, severity, and remediation guidance.

**Evidence Schema** — a machine-readable definition attached to a compliance rule
that specifies what proof of satisfaction looks like for that rule.

**Compliance Contract** — the set of compliance rules and their evidence schemas
that govern a specific agent execution. Produced by exporting a rule set in
contract export format.

**Contract ID** — a SHA-256 hash of the serialized compliance contract that uniquely
identifies the contract version that governed a specific execution.

**Attestation Block** — a structured JSON document produced by an agent upon task
completion that maps execution results to rule IDs and references evidence artifacts.

**Attestation Signature** — an HMAC-SHA256 signature of the attestation block
produced using a shared secret key, providing tamper evidence.

**Audit Package** — the complete compliance record for an execution, combining the
spec scan results, contract export, attestation block, attestation validation results,
evidence artifacts, and package signature.

**Conformant Emitter** — an agent or system that produces attestation blocks
conforming to this specification.

**Conformant Validator** — a tool or system that validates attestation blocks
against compliance contracts per the requirements in Section 5.

---

## 3. Evidence Schema

### 3.1 Overview

An evidence schema is an optional extension to a compliance rule definition.
It specifies what proof of satisfaction must look like for that rule — what artifact
type is expected, what structured fields it must contain, who is responsible for
producing it, how frequently it must be refreshed, and how a validator or auditor
can verify it.

Evidence schemas are mandatory on rules with severity HIGH or CRITICAL in any rule
set that claims contract completeness. They are optional on rules with severity
MEDIUM or LOW.

### 3.2 Evidence Schema Fields

```yaml
evidence:
  required: boolean
  # Whether this evidence schema is required for contract completeness.
  # Must be true for HIGH and CRITICAL severity rules in complete contracts.

  artifact_type: string
  # The category of evidence artifact expected.
  # Valid values:
  #   document          — a written policy, procedure, or assessment document
  #   log               — an audit log, access log, or activity record
  #   attestation       — a signed attestation from a human or system
  #   test_result       — output from an automated test or evaluation
  #   review_record     — record of a human review, approval, or sign-off
  #   configuration     — a system configuration file or setting record
  #   scan_result       — output from a security or compliance scan
  #   approval_record   — a formal approval decision with named approver
  #   execution_trace   — a structured record of agent execution steps

  description: string
  # Plain language statement of what the evidence must demonstrate.
  # This is the human-readable contract statement for this rule.

  fields: array
  # Structured fields the evidence artifact must contain.
  # Each field has the following properties:
  #   name: string          — field identifier
  #   required: boolean     — whether the field must be present
  #   description: string   — what this field must contain
  #   format: string        — optional format constraint (e.g., ISO8601)
  #   valid_values: array   — optional enumeration of acceptable values

  producer: string
  # Who or what is responsible for producing this evidence.
  # Valid values: human | agent | system | pipeline | hybrid

  producer_role: string
  # Optional. Narrows the producer to a specific role when producer is human.

  cadence: string
  # How frequently this evidence must be refreshed.
  # Valid values: once | per_release | per_session | quarterly | annually |
  #               continuous | on_change

  retention: string
  # How long evidence must be retained for audit purposes.
  # Express as a duration string: "3 years", "90 days", etc.

  verification:
    method: string
    # How a validator confirms the evidence is valid.
    # Valid values: presence | schema_match | signature | cross_reference | human_review

    cross_reference:
      rule_id: string
      # The rule ID of a related evidence requirement.
      relationship: string
      # The relationship between this evidence and the referenced rule's evidence.
      # Valid values: corroborates | satisfies | supersedes | depends_on
```

### 3.3 Contract Completeness

A rule set is considered contract-complete when all rules with severity HIGH or
CRITICAL carry a conformant evidence schema. Rule sets must declare their
completeness status:

```yaml
profiles:
  example_profile:
    contract_complete: boolean
    contract_version: string  # The protocol version this contract conforms to
```

Validators must warn when processing a contract that declares `contract_complete: false`
or omits the field, as attestation coverage cannot be verified against incomplete contracts.

---

## 4. Contract Export Format

### 4.1 Overview

A contract export is the serialized representation of a compliance contract
communicated to an agent before execution. It contains the rule definitions,
evidence schemas, and a contract ID that anchors any attestation produced
against this specific contract version.

### 4.2 Contract Export Structure

```json
{
  "nod_contract": {
    "version": "string — protocol version this contract conforms to",
    "contract_id": "string — SHA-256 hash of this contract's canonical serialization",
    "exported_at": "string — ISO8601 timestamp of export",
    "contract_complete": "boolean",
    "profiles": [
      {
        "profile_id": "string",
        "badge_label": "string",
        "rules": [
          {
            "rule_id": "string",
            "label": "string",
            "control_id": "string",
            "severity": "string",
            "remediation": "string",
            "evidence": {}
          }
        ],
        "red_flags": [],
        "reality_checks": []
      }
    ]
  }
}
```

### 4.3 Contract ID Computation

The contract ID is computed as the SHA-256 hash of the canonical JSON serialization
of the contract content — excluding the `contract_id` and `exported_at` fields.
Canonical serialization uses UTF-8 encoding with keys sorted alphabetically and
no insignificant whitespace.

This ensures that two exports of the same rule set at different times produce
the same contract ID, enabling validators to confirm that an attestation was
produced against the same contract regardless of when the export occurred.

---

## 5. Attestation Block

### 5.1 Overview

An attestation block is a structured JSON document produced by a conformant emitter
upon completion of a task governed by a compliance contract. It maps execution
results to rule IDs, references evidence artifacts produced during execution, and
carries a signature that enables tamper detection.

### 5.2 Attestation Block Structure

```json
{
  "nod_attestation": {
    "version": "string — protocol version this attestation conforms to",
    "contract_id": "string — must match the contract_id of the governing contract",
    "agent_id": "string — identifier of the agent or pipeline that executed",
    "execution_id": "string — unique identifier for this execution instance",
    "timestamp_start": "string — ISO8601 timestamp when execution began",
    "timestamp_end": "string — ISO8601 timestamp when execution completed",
    "model_id": "string — optional, the model or system version that executed",

    "rule_attestations": [
      {
        "rule_id": "string — must match a rule_id in the governing contract",
        "label": "string",
        "result": "string — satisfied | not_satisfied | not_applicable | unable_to_verify",
        "evidence": {
          "artifact_type": "string — must match the artifact_type in the evidence schema",
          "artifact_id": "string — unique reference to the evidence artifact",
          "artifact_hash": "string — SHA-256 hash of the evidence artifact",
          "artifact_location": "string — path, URL, or GRC reference",
          "fields": {},
          "producer": "string",
          "producer_identity": "string — role or system that produced the evidence"
        },
        "notes": "string — required when result is not_satisfied or unable_to_verify"
      }
    ],

    "unsatisfied_rules": [
      {
        "rule_id": "string",
        "label": "string",
        "reason": "string",
        "severity": "string"
      }
    ],

    "attestation_signature": "string — HMAC-SHA256 of attestation content, omit if unsigned"
  }
}
```

### 5.3 Result Values

**satisfied** — the rule was evaluated and the evidence produced satisfies the
evidence schema. An artifact_hash must be present.

**not_satisfied** — the rule was evaluated and could not be satisfied. A notes
field explaining the reason is required. The rule must appear in unsatisfied_rules.

**not_applicable** — the rule does not apply to this execution context. A notes
field explaining the inapplicability determination is required.

**unable_to_verify** — the agent could not determine whether the rule was satisfied.
A notes field is required. This result must not be used as a substitute for
not_satisfied when the agent knows the rule was not met.

### 5.4 Coverage Requirements

A conformant attestation block must include a rule_attestation entry for every
rule with severity HIGH or CRITICAL in the governing contract. Rules with severity
MEDIUM or LOW may be included at the emitter's discretion.

Validators must flag attestation blocks that are missing entries for HIGH or
CRITICAL rules as coverage failures, not schema failures.

### 5.5 Signature

The attestation signature is computed as HMAC-SHA256 of the canonical JSON
serialization of the attestation block excluding the `attestation_signature` field,
using a shared secret key. Signing is optional but strongly recommended for
production use. Unsigned attestation blocks must omit the attestation_signature
field entirely rather than include a null or empty value.

---

## 6. Verification Requirements

### 6.1 Conformant Validator Requirements

A conformant validator must perform the following checks when validating an
attestation block against a contract:

**Schema conformance**
- The attestation block conforms to the attestation block JSON schema
- All required fields are present and correctly typed
- All result values are from the defined enumeration

**Contract binding**
- The contract_id in the attestation matches the contract_id of the provided contract
- The attestation version is compatible with the contract version

**Coverage**
- A rule_attestation entry exists for every HIGH and CRITICAL rule in the contract
- Rules appearing in unsatisfied_rules have a corresponding not_satisfied result
  in rule_attestations

**Evidence schema conformance**
- For each satisfied rule with an evidence schema, the evidence block contains
  all required fields defined in the schema
- artifact_type matches the type defined in the evidence schema
- artifact_hash is present for all satisfied rules

**Temporal coherence**
- timestamp_end is after timestamp_start
- timestamp_start is after the exported_at timestamp of the governing contract

**Signature**
- If attestation_signature is present, validate against the shared secret key
- If attestation_signature is absent, emit a warning that the attestation is unsigned

### 6.2 Validation Output

Validators must produce output that distinguishes between:

- **Schema failures** — the attestation block does not conform to the specification
- **Coverage failures** — required rules are not attested
- **Evidence failures** — evidence does not satisfy the schema for a rule
- **Binding failures** — the attestation cannot be bound to the provided contract
- **Signature failures** — the signature does not validate
- **Warnings** — conditions that do not constitute failures but require attention

Validators should produce output compatible with the SARIF format to enable
integration with CI/CD security tooling.

---

## 7. Audit Package

### 7.1 Structure

An audit package is the complete compliance record for an execution. It is
self-contained and verifiable without external dependencies.

```
audit-package/
├── spec-scan.sarif              # Results of nod scan against the governing specification
├── contract-export.json         # The compliance contract exported to the agent
├── attestation.json             # The agent's signed attestation block
├── attestation-validation.sarif # Validation results for the attestation
├── evidence/                    # Evidence artifacts referenced in the attestation
│   └── [artifact files]
└── audit-package.sig            # HMAC-SHA256 signature of the complete package
```

### 7.2 Package Signature

The package signature is computed as HMAC-SHA256 of the concatenated SHA-256
hashes of all files in the package, with files sorted alphabetically by path.
This enables verification that the package contents have not been modified after
assembly.

### 7.3 Human Review Requirement

An audit package is an input to human review, not a substitute for it.
Every audit package must include the following statement in its manifest or
accompanying documentation:

> "This package requires validation by a qualified compliance SME before audit submission."

---

## 8. Security Considerations

### 8.1 Hash Algorithm

All content hashes in this protocol use SHA-256 minimum. Implementations must
not use MD5 or SHA-1.

### 8.2 HMAC Key Management

Shared secret keys used for HMAC signing must be managed as sensitive credentials.
They must not be embedded in code, committed to version control, or logged.
Environment variable injection at runtime is the recommended pattern.

### 8.3 Replay Prevention

Attestation blocks carry execution_id and timestamp fields. Validators should
maintain a record of processed execution_ids and reject duplicates to prevent
replay attacks in automated pipelines.

### 8.4 Agent Identity

The agent_id field in the attestation block is a self-reported identifier.
Implementations that require strong agent identity assurance should combine
agent_id with the attestation signature and external identity verification
mechanisms appropriate to their environment.

---

## 9. Conformance

An implementation is considered a conformant emitter if it produces attestation
blocks that satisfy all MUST requirements in Section 5 and pass validation by
a conformant validator.

An implementation is considered a conformant validator if it performs all checks
defined in Section 6.1 and produces output that distinguishes the failure categories
defined in Section 6.2.

Conformance claims should reference the protocol version against which conformance
is claimed: "Conforms to nod Attestation Protocol v0.1.0."
