#!/usr/bin/env python3
"""
nod Attestation Protocol — Reference Validator
Version: 0.1.0
License: Apache 2.0

Validates attestation blocks against compliance contracts per the
nod Attestation Protocol specification (SPEC.md).

This validator is intentionally offline and has no dependency on the nod tool.
It can be used independently to validate any conformant attestation block
against any conformant contract export.

Usage:
    python validate.py --attestation attestation.json --contract contract-export.json
    python validate.py --attestation attestation.json --contract contract-export.json --key-env NOD_SECRET_KEY
    python validate.py --help

Exit codes:
    0 — validation passed (warnings may be present)
    1 — validation failed (one or more failures detected)
    2 — invocation error (missing arguments, unreadable files)
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


# ─── Result Types ─────────────────────────────────────────────────────────────

class ResultCategory(Enum):
    SCHEMA_FAILURE    = "SCHEMA_FAILURE"
    COVERAGE_FAILURE  = "COVERAGE_FAILURE"
    EVIDENCE_FAILURE  = "EVIDENCE_FAILURE"
    BINDING_FAILURE   = "BINDING_FAILURE"
    SIGNATURE_FAILURE = "SIGNATURE_FAILURE"
    WARNING           = "WARNING"
    PASS              = "PASS"


@dataclass
class ValidationResult:
    category: ResultCategory
    rule_id: Optional[str]
    message: str
    detail: Optional[str] = None


@dataclass
class ValidationReport:
    attestation_path: str
    contract_path: str
    results: list[ValidationResult] = field(default_factory=list)

    def add(self, category: ResultCategory, message: str,
            rule_id: Optional[str] = None, detail: Optional[str] = None):
        self.results.append(ValidationResult(category, rule_id, message, detail))

    @property
    def failures(self):
        return [r for r in self.results if r.category != ResultCategory.WARNING
                and r.category != ResultCategory.PASS]

    @property
    def warnings(self):
        return [r for r in self.results if r.category == ResultCategory.WARNING]

    @property
    def passed(self):
        return len(self.failures) == 0


# ─── File Loading ──────────────────────────────────────────────────────────────

def load_json(path: str, label: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: {label} file not found: {path}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"ERROR: {label} file is not valid JSON: {e}", file=sys.stderr)
        sys.exit(2)


# ─── Contract Helpers ──────────────────────────────────────────────────────────

def extract_all_rules(contract: dict) -> dict[str, dict]:
    """Return a flat map of rule_id -> rule from all profiles in the contract."""
    rules = {}
    profiles = contract.get("nod_contract", {}).get("profiles", [])
    for profile in profiles:
        for rule in profile.get("rules", []):
            rules[rule["rule_id"]] = rule
    return rules


def extract_high_critical_rule_ids(contract: dict) -> set[str]:
    """Return the set of rule IDs with severity HIGH or CRITICAL."""
    return {
        rule_id for rule_id, rule in extract_all_rules(contract).items()
        if rule.get("severity") in ("HIGH", "CRITICAL")
    }


def compute_contract_id(contract: dict) -> str:
    """
    Compute the canonical contract ID as SHA-256 of the contract content
    excluding contract_id and exported_at fields.
    Per SPEC.md Section 4.3.
    """
    content = contract.get("nod_contract", {})
    canonical = {k: v for k, v in content.items()
                 if k not in ("contract_id", "exported_at")}
    serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# ─── Signature Verification ────────────────────────────────────────────────────

def verify_signature(attestation_block: dict, secret_key: str) -> bool:
    """
    Verify HMAC-SHA256 signature of the attestation block.
    Canonical serialization excludes the attestation_signature field.
    """
    content = {k: v for k, v in attestation_block.items()
               if k != "attestation_signature"}
    serialized = json.dumps(content, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True)
    expected = hmac.new(
        secret_key.encode("utf-8"),
        serialized.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    provided = attestation_block.get("attestation_signature", "")
    return hmac.compare_digest(expected, provided)


# ─── Validation Checks ─────────────────────────────────────────────────────────

def check_schema_conformance(block: dict, report: ValidationReport):
    """Check that required top-level fields are present and correctly typed."""
    required_fields = {
        "version": str,
        "contract_id": str,
        "agent_id": str,
        "execution_id": str,
        "timestamp_start": str,
        "rule_attestations": list,
        "unsatisfied_rules": list,
    }
    for field_name, expected_type in required_fields.items():
        if field_name not in block:
            report.add(
                ResultCategory.SCHEMA_FAILURE,
                f"Required field '{field_name}' is missing from attestation block.",
            )
        elif not isinstance(block[field_name], expected_type):
            report.add(
                ResultCategory.SCHEMA_FAILURE,
                f"Field '{field_name}' must be {expected_type.__name__}, "
                f"got {type(block[field_name]).__name__}.",
            )

    # Validate contract_id format
    contract_id = block.get("contract_id", "")
    if contract_id and not re.match(r"^[a-f0-9]{64}$", contract_id):
        report.add(
            ResultCategory.SCHEMA_FAILURE,
            "Field 'contract_id' is not a valid SHA-256 hex string (64 lowercase hex chars).",
        )

    # Validate result values in rule_attestations
    valid_results = {"satisfied", "not_satisfied", "not_applicable", "unable_to_verify"}
    for idx, attestation in enumerate(block.get("rule_attestations", [])):
        result = attestation.get("result")
        if result not in valid_results:
            report.add(
                ResultCategory.SCHEMA_FAILURE,
                f"rule_attestations[{idx}] has invalid result value: '{result}'.",
                rule_id=attestation.get("rule_id"),
            )

        # Satisfied results must have evidence
        if result == "satisfied" and "evidence" not in attestation:
            report.add(
                ResultCategory.SCHEMA_FAILURE,
                f"rule_attestations[{idx}] has result 'satisfied' but no evidence block.",
                rule_id=attestation.get("rule_id"),
            )

        # Non-satisfied results should have notes
        if result in ("not_satisfied", "not_applicable", "unable_to_verify"):
            if not attestation.get("notes"):
                report.add(
                    ResultCategory.WARNING,
                    f"rule_attestations[{idx}] has result '{result}' but no notes field. "
                    "Notes are required for non-satisfied results.",
                    rule_id=attestation.get("rule_id"),
                )

        # Satisfied results must have artifact_hash in evidence
        if result == "satisfied":
            evidence = attestation.get("evidence", {})
            artifact_hash = evidence.get("artifact_hash", "")
            if not artifact_hash:
                report.add(
                    ResultCategory.EVIDENCE_FAILURE,
                    "Satisfied rule attestation is missing artifact_hash in evidence block.",
                    rule_id=attestation.get("rule_id"),
                )
            elif not re.match(r"^[a-f0-9]{64}$", artifact_hash):
                report.add(
                    ResultCategory.EVIDENCE_FAILURE,
                    "artifact_hash is not a valid SHA-256 hex string.",
                    rule_id=attestation.get("rule_id"),
                )


def check_contract_binding(block: dict, contract: dict, report: ValidationReport):
    """Confirm the attestation is bound to the provided contract."""
    contract_content = contract.get("nod_contract", {})

    # Version compatibility check
    attestation_version = block.get("version", "")
    contract_version = contract_content.get("version", "")
    if attestation_version.split(".")[0] != contract_version.split(".")[0]:
        report.add(
            ResultCategory.BINDING_FAILURE,
            f"Attestation protocol version '{attestation_version}' is not compatible "
            f"with contract version '{contract_version}'. Major versions must match.",
        )

    # Contract ID binding
    provided_id = block.get("contract_id", "")
    computed_id = compute_contract_id(contract)
    declared_id = contract_content.get("contract_id", "")

    if provided_id != computed_id:
        report.add(
            ResultCategory.BINDING_FAILURE,
            "Attestation contract_id does not match the computed ID of the provided contract. "
            "This attestation may have been produced against a different contract version.",
            detail=f"Attestation contract_id: {provided_id}\n"
                   f"Computed from contract:   {computed_id}\n"
                   f"Declared in contract:     {declared_id}",
        )

    # Temporal coherence
    exported_at_str = contract_content.get("exported_at", "")
    timestamp_start_str = block.get("timestamp_start", "")
    timestamp_end_str = block.get("timestamp_end", "")

    try:
        exported_at = datetime.fromisoformat(exported_at_str.replace("Z", "+00:00"))
        timestamp_start = datetime.fromisoformat(timestamp_start_str.replace("Z", "+00:00"))

        if timestamp_start < exported_at:
            report.add(
                ResultCategory.BINDING_FAILURE,
                "Attestation timestamp_start is before the contract exported_at timestamp. "
                "An attestation cannot have been produced before its governing contract was exported.",
                detail=f"timestamp_start: {timestamp_start_str}\nexported_at:     {exported_at_str}",
            )

        if timestamp_end_str:
            timestamp_end = datetime.fromisoformat(timestamp_end_str.replace("Z", "+00:00"))
            if timestamp_end < timestamp_start:
                report.add(
                    ResultCategory.SCHEMA_FAILURE,
                    "Attestation timestamp_end is before timestamp_start.",
                    detail=f"timestamp_start: {timestamp_start_str}\ntimestamp_end:   {timestamp_end_str}",
                )
    except (ValueError, AttributeError):
        report.add(
            ResultCategory.WARNING,
            "Could not parse timestamps for temporal coherence check. "
            "Ensure timestamps are valid ISO 8601 format.",
        )

    # Check for unknown rule references
    known_rule_ids = set(extract_all_rules(contract).keys())
    for attestation in block.get("rule_attestations", []):
        rule_id = attestation.get("rule_id", "")
        if rule_id and rule_id not in known_rule_ids:
            report.add(
                ResultCategory.BINDING_FAILURE,
                f"rule_attestation references rule_id '{rule_id}' which is not present "
                "in the governing contract.",
                rule_id=rule_id,
            )


def check_coverage(block: dict, contract: dict, report: ValidationReport):
    """Confirm all HIGH and CRITICAL rules in the contract are attested."""
    required_ids = extract_high_critical_rule_ids(contract)
    attested_ids = {a.get("rule_id") for a in block.get("rule_attestations", [])}

    missing = required_ids - attested_ids
    for rule_id in sorted(missing):
        all_rules = extract_all_rules(contract)
        rule = all_rules.get(rule_id, {})
        report.add(
            ResultCategory.COVERAGE_FAILURE,
            f"No attestation found for {rule.get('severity', 'HIGH/CRITICAL')} rule '{rule_id}'. "
            "All HIGH and CRITICAL rules in the contract must be attested.",
            rule_id=rule_id,
        )

    # Check unsatisfied_rules consistency
    not_satisfied_ids = {
        a.get("rule_id") for a in block.get("rule_attestations", [])
        if a.get("result") == "not_satisfied"
    }
    unsatisfied_summary_ids = {
        u.get("rule_id") for u in block.get("unsatisfied_rules", [])
    }

    missing_from_summary = not_satisfied_ids - unsatisfied_summary_ids
    for rule_id in sorted(missing_from_summary):
        report.add(
            ResultCategory.SCHEMA_FAILURE,
            f"Rule '{rule_id}' has result 'not_satisfied' in rule_attestations "
            "but is not listed in unsatisfied_rules.",
            rule_id=rule_id,
        )

    extra_in_summary = unsatisfied_summary_ids - not_satisfied_ids
    for rule_id in sorted(extra_in_summary):
        report.add(
            ResultCategory.SCHEMA_FAILURE,
            f"Rule '{rule_id}' appears in unsatisfied_rules but does not have "
            "a corresponding 'not_satisfied' result in rule_attestations.",
            rule_id=rule_id,
        )


def check_evidence_schemas(block: dict, contract: dict, report: ValidationReport):
    """For each satisfied rule with an evidence schema, validate the evidence reference."""
    all_rules = extract_all_rules(contract)

    for attestation in block.get("rule_attestations", []):
        rule_id = attestation.get("rule_id", "")
        result = attestation.get("result")

        if result != "satisfied":
            continue

        rule = all_rules.get(rule_id)
        if not rule:
            continue

        schema = rule.get("evidence")
        if not schema:
            continue

        evidence = attestation.get("evidence", {})

        # artifact_type must match schema
        expected_type = schema.get("artifact_type")
        actual_type = evidence.get("artifact_type")
        if expected_type and actual_type != expected_type:
            report.add(
                ResultCategory.EVIDENCE_FAILURE,
                f"Evidence artifact_type '{actual_type}' does not match "
                f"required type '{expected_type}' from evidence schema.",
                rule_id=rule_id,
            )

        # producer must match schema
        expected_producer = schema.get("producer")
        actual_producer = evidence.get("producer")
        if expected_producer and actual_producer != expected_producer:
            report.add(
                ResultCategory.EVIDENCE_FAILURE,
                f"Evidence producer '{actual_producer}' does not match "
                f"required producer '{expected_producer}' from evidence schema.",
                rule_id=rule_id,
            )

        # Required fields must be present
        evidence_fields = evidence.get("fields", {})
        for field_def in schema.get("fields", []):
            field_name = field_def.get("name")
            is_required = field_def.get("required", False)
            valid_values = field_def.get("valid_values")
            fmt = field_def.get("format")

            if is_required and (not evidence_fields.get(field_name)):
                report.add(
                    ResultCategory.EVIDENCE_FAILURE,
                    f"Required evidence field '{field_name}' is missing or empty.",
                    rule_id=rule_id,
                )
                continue

            field_value = evidence_fields.get(field_name, "")
            if not field_value:
                continue

            # Check valid_values enumeration
            if valid_values and field_value not in valid_values:
                report.add(
                    ResultCategory.EVIDENCE_FAILURE,
                    f"Evidence field '{field_name}' value '{field_value}' is not in "
                    f"the allowed values: {valid_values}.",
                    rule_id=rule_id,
                )

            # Check format constraints
            if fmt == "ISO8601":
                try:
                    datetime.fromisoformat(field_value.replace("Z", "+00:00"))
                except ValueError:
                    report.add(
                        ResultCategory.EVIDENCE_FAILURE,
                        f"Evidence field '{field_name}' value '{field_value}' "
                        "is not a valid ISO 8601 datetime.",
                        rule_id=rule_id,
                    )


def check_signature(block: dict, secret_key: Optional[str], report: ValidationReport):
    """Verify HMAC signature if present. Warn if absent."""
    has_signature = bool(block.get("attestation_signature"))

    if not has_signature:
        report.add(
            ResultCategory.WARNING,
            "Attestation block is unsigned. The attestation_signature field is absent. "
            "Unsigned attestations cannot provide tamper evidence.",
        )
        return

    if not secret_key:
        report.add(
            ResultCategory.WARNING,
            "Attestation block carries a signature but no secret key was provided for verification. "
            "Pass --key-env ENV_VAR_NAME to enable signature verification.",
        )
        return

    if not verify_signature(block, secret_key):
        report.add(
            ResultCategory.SIGNATURE_FAILURE,
            "Attestation signature verification failed. "
            "The attestation block may have been tampered with, or the wrong key was used.",
        )
    else:
        report.add(
            ResultCategory.PASS,
            "Attestation signature verified successfully.",
        )


def check_contract_completeness(contract: dict, report: ValidationReport):
    """Warn if the contract is not complete for attestation purposes."""
    contract_content = contract.get("nod_contract", {})
    if not contract_content.get("contract_complete", False):
        report.add(
            ResultCategory.WARNING,
            "The governing contract declares contract_complete: false or omits the field. "
            "Evidence schema coverage cannot be fully verified. "
            "HIGH and CRITICAL rules without evidence schemas will not be checked.",
        )


# ─── Report Output ─────────────────────────────────────────────────────────────

def print_report(report: ValidationReport):
    separator = "─" * 72

    print(f"\n{separator}")
    print("  nod Attestation Protocol — Validation Report")
    print(f"{separator}")
    print(f"  Attestation : {report.attestation_path}")
    print(f"  Contract    : {report.contract_path}")
    print(f"  Timestamp   : {datetime.now(timezone.utc).isoformat()}")
    print(separator)

    if not report.results:
        print("\n  No results recorded.\n")
        return

    categories = [
        ResultCategory.BINDING_FAILURE,
        ResultCategory.SCHEMA_FAILURE,
        ResultCategory.COVERAGE_FAILURE,
        ResultCategory.EVIDENCE_FAILURE,
        ResultCategory.SIGNATURE_FAILURE,
        ResultCategory.WARNING,
        ResultCategory.PASS,
    ]

    for category in categories:
        items = [r for r in report.results if r.category == category]
        if not items:
            continue

        label = category.value.replace("_", " ")
        print(f"\n  [{label}]")

        for item in items:
            prefix = "  ✗" if category not in (ResultCategory.WARNING, ResultCategory.PASS) else \
                     "  ⚠" if category == ResultCategory.WARNING else "  ✓"
            rule_tag = f" [{item.rule_id}]" if item.rule_id else ""
            print(f"{prefix}{rule_tag} {item.message}")
            if item.detail:
                for line in item.detail.splitlines():
                    print(f"      {line}")

    print(f"\n{separator}")
    failure_count = len(report.failures)
    warning_count = len(report.warnings)

    if report.passed:
        print(f"  RESULT: PASSED  ({warning_count} warning(s))")
    else:
        print(f"  RESULT: FAILED  ({failure_count} failure(s), {warning_count} warning(s))")

    print(separator)
    print()
    print("  All findings require validation by a qualified compliance SME")
    print("  before action is taken or this attestation is submitted for audit.")
    print(f"{separator}\n")


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="nod Attestation Protocol — Reference Validator v0.1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python validate.py --attestation attestation.json --contract contract-export.json
  python validate.py --attestation attestation.json --contract contract-export.json --key-env NOD_SECRET_KEY

Exit codes:
  0  Validation passed (warnings may be present)
  1  Validation failed (one or more failures detected)
  2  Invocation error (missing arguments, unreadable files)
        """
    )
    parser.add_argument(
        "--attestation", required=True,
        help="Path to the attestation block JSON file to validate."
    )
    parser.add_argument(
        "--contract", required=True,
        help="Path to the contract export JSON file the attestation was produced against."
    )
    parser.add_argument(
        "--key-env", metavar="ENV_VAR",
        help="Name of the environment variable containing the HMAC secret key "
             "for signature verification. The key value is read from the environment "
             "at runtime and never logged."
    )

    args = parser.parse_args()

    # Load inputs
    attestation = load_json(args.attestation, "Attestation")
    contract = load_json(args.contract, "Contract")

    # Unwrap root keys
    block = attestation.get("nod_attestation")
    if not block:
        print("ERROR: Attestation file does not contain a 'nod_attestation' root key.", file=sys.stderr)
        sys.exit(2)

    if not contract.get("nod_contract"):
        print("ERROR: Contract file does not contain a 'nod_contract' root key.", file=sys.stderr)
        sys.exit(2)

    # Resolve secret key
    secret_key = None
    if args.key_env:
        secret_key = os.environ.get(args.key_env)
        if not secret_key:
            print(f"WARNING: Environment variable '{args.key_env}' is not set or is empty. "
                  "Signature verification skipped.", file=sys.stderr)

    # Run validation
    report = ValidationReport(
        attestation_path=args.attestation,
        contract_path=args.contract,
    )

    check_contract_completeness(contract, report)
    check_schema_conformance(block, report)
    check_contract_binding(block, contract, report)
    check_coverage(block, contract, report)
    check_evidence_schemas(block, contract, report)
    check_signature(block, secret_key, report)

    # Output
    print_report(report)

    sys.exit(0 if report.passed else 1)


if __name__ == "__main__":
    main()
