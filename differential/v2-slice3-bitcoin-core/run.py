#!/usr/bin/env python3
"""Separately invoked QuietKey v2 slice-3 / Bitcoin Core v28.0 differential runner.

This runner consumes only committed public fixture bytes. It contains no
signer, private-key operation, wallet RPC, transaction submission, or product
dependency on Bitcoin Core.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import platform
import re
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any


CORE_RELEASE = "28.0"
CORE_ARCHIVE = "bitcoin-28.0-x86_64-apple-darwin.tar.gz"
CORE_ARCHIVE_BYTES = 37_680_963
CORE_ARCHIVE_SHA256 = "77e931bbaaf47771a10c376230bf53223f5380864bad3568efc7f4d02e40a0f7"
SUMS_BYTES = 2_620
SUMS_LINES = 25
SUMS_SHA256 = "d1384c7cbb9027bc5642943d675d25f2edd88e34207e0aaa307babf097d6d023"
SUMS_LINE = f"{CORE_ARCHIVE_SHA256}  {CORE_ARCHIVE}"
BITCOIND_SHA256 = "55afd04193715ef76bb445a8aec7c18f1af780b9df8b8e5028c1b78baa15b4ee"
BITCOIN_CLI_SHA256 = "2b53751345cdc0f326fa82e721c1f33b29db75d39f9125cb212d2e38524e4c1c"
BITCOIND_VERSION = "Bitcoin Core version v28.0.0"
BITCOIN_CLI_VERSION = "Bitcoin Core RPC client version v28.0.0"
REGTEST_GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
REVIEW_SCHEMA = 3
REVIEW_DOMAIN = b"QuietKey/D-09/review/v3"
FEE_POLICY = b"QK-FEE-POLICY-V2"
GOLDEN_WALLET_ID = bytes.fromhex(
    "d5b7e52f569ae51e7c66af14240d8e4459c6246785ce5c441773995614f60e9e"
)
GOLDEN_FINGERPRINTS = bytes.fromhex("2fae971172a14ab8")
HARNESS_REL = Path("differential/v2-slice3-bitcoin-core/run.py")
FIXTURE_REL = Path("differential/v2-slice3-bitcoin-core/fixtures/v2_core_vectors.txt")
PROCEDURE_REL = Path("differential/v2-slice3-bitcoin-core/README.md")
SIGNING_FIXTURE_REL = Path("host/qk-psbt/tests/fixtures/signing_finalization_v2.txt")
EVIDENCE_REL = Path("differential/v2-slice3-bitcoin-core/evidence")
TRANSCRIPT_NAME = re.compile(
    r"run-(?P<utc>[0-9]{8}T[0-9]{6}Z)-(?P<commit>[0-9a-f]{7,40})\.txt"
)
HEX_32 = re.compile(r"[0-9a-f]{64}")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}")
UTC_SECOND = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

PROVENANCE_FIELDS = {
    "fixture_profile",
    "permanent_label",
    "generation_procedure",
    "generated_outside_git",
    "implementation_count",
    "implementation_a_name",
    "implementation_a_runtime",
    "implementation_a_runtime_sha256",
    "implementation_a_source_bytes",
    "implementation_a_source_lines",
    "implementation_a_source_sha256",
    "implementation_b_name",
    "implementation_b_runtime",
    "implementation_b_runtime_sha256",
    "implementation_b_source_bytes",
    "implementation_b_source_lines",
    "implementation_b_source_sha256",
    "implementation_independence",
    "agreement_scope",
    "agreement_result",
    "normalized_agreement_bytes",
    "normalized_agreement_lines",
    "normalized_agreement_sha256",
    "public_scalar_count",
    "signature_count",
    "rfc6979_nonce_count",
    "unique_rfc6979_nonces",
    "screening_policy",
    "screening_representations",
    "screening_named_sets",
    "screening_source_sha256",
    "screening_source_bytes",
    "screening_source_lines",
    "screening_report_sha256",
    "screening_report_bytes",
    "screening_report_lines",
    "screening_repository_head",
    "screening_tracked_file_count",
    "screening_tracked_byte_count",
    "screened_public_key_count",
    "screened_signature_r_count",
    "screening_small_multiple_limit",
    "screening_unexpected_hits",
    "screening_small_multiple_hits",
    "screening_expected_same_lineage_hits",
    "same_lineage_matches",
    "initial_destruction_result",
    "initial_deletion_completed_utc",
    "initial_destroyed_regular_file_count",
    "initial_destroyed_directory_count",
    "initial_destroyed_symlink_count",
    "initial_destroyed_regular_file_byte_count",
    "initial_destroyed_root_absent",
    "source_recovery",
    "recovered_source_hashes_match",
    "reproduced_normalized_agreement_sha256",
    "recovery_search_artifact",
    "recovery_search_artifact_bytes",
    "recovery_search_artifact_deletion_utc",
    "recovery_search_artifact_absent",
    "destruction_result",
    "generation_workspace",
    "deletion_completed_utc",
    "destroyed_regular_file_count",
    "destroyed_directory_count",
    "destroyed_symlink_count",
    "destroyed_regular_file_byte_count",
    "destroyed_root_absent",
    "fixture_lineage",
    "mainnet_funding_status",
    "regtest_coin_status",
    "source_signing_fixture",
    "source_signing_fixture_bytes",
    "source_signing_fixture_lines",
    "source_signing_fixture_sha256",
    "role_a_transcript_ascii",
    "role_b_transcript_ascii",
    "role_a_transcript_sha256",
    "role_b_transcript_sha256",
    "role_a_route_private_scalar_hex",
    "role_b_route_private_scalar_hex",
}

HEADER_FIELDS = PROVENANCE_FIELDS | {
    "corpus_state",
    "core_release",
    "core_archive",
    "core_archive_sha256",
    "regtest_genesis_hash",
    "seed_block_len",
    "seed_block_sha256",
    "seed_block_hash",
    "seed_block_hex",
    "seed_coinbase_len",
    "seed_coinbase_sha256",
    "seed_coinbase_txid",
    "seed_coinbase_hex",
    "seed_vout",
    "seed_amount_sats",
    "seed_script_pubkey_hex",
}

POSITIVE_BASE_FIELDS = {
    "case",
    "class",
    "unknown_profile",
    "receive_descriptor",
    "change_descriptor",
    "wallet_id",
    "signed_psbt_len",
    "signed_psbt_sha256",
    "signed_psbt_hex",
    "finalized_psbt_len",
    "finalized_psbt_sha256",
    "finalized_psbt_hex",
    "raw_tx_len",
    "raw_tx_sha256",
    "raw_tx_hex",
    "stripped_tx_len",
    "stripped_tx_sha256",
    "stripped_tx_hex",
    "txid",
    "wtxid",
    "fee_sats",
    "tx_version",
    "tx_locktime",
    "input_count",
    "input_0_prev_txid",
    "input_0_prev_vout",
    "input_0_sequence",
    "input_0_script_sig_hex",
    "output_count",
    "witness_item_count",
    "witness_0_hex",
    "witness_1_hex",
    "witness_1_pubkey",
    "witness_2_hex",
    "witness_2_pubkey",
    "witness_3_hex",
    "core_finalized_psbt_rule",
    "review_schema",
    "review_domain",
    "fee_policy",
    "review_s0_len",
    "review_s0_sha256",
    "review_s0_hex",
    "canonical_review_v3_len",
    "canonical_review_v3_sha256",
    "canonical_review_v3_hex",
    "review_hash",
    "origin_fingerprint_a",
    "origin_fingerprint_b",
    "estimated_weight",
    "estimated_vsize",
    "fee_rate_msat_vb",
    "warning_tags",
}

UNKNOWN_ORDER_FIELDS = {
    "quietkey_unknown_type_order",
    "core_unknown_type_order",
    "quietkey_unknown_full_keys",
    "core_unknown_full_keys",
}

NEGATIVE_BASE_FIELDS = {
    "case",
    "class",
    "parent_case",
    "mutation",
    "raw_tx_len",
    "raw_tx_sha256",
    "raw_tx_hex",
    "txid",
    "wtxid",
    "core_rule",
}

EXPECTED_CASES = [
    ("V2-S3-CORE-UNKNOWN-FREE", "differential-accept"),
    ("V2-S3-CORE-UNKNOWN-ORDER", "differential-accept"),
    ("V2-S3-CORE-SWAPPED-SIGNATURES", "differential-reject"),
    ("V2-S3-CORE-MUTATED-SIGNATURE", "differential-reject"),
    ("V2-S3-CORE-MUTATED-BASE", "differential-reject"),
]

EXPECTED_SIGNED_MAP_TYPES = {
    "V2-S3-CORE-UNKNOWN-FREE": ((0,), (0, 1, 2, 2, 3, 5, 6, 6), ()),
    "V2-S3-CORE-UNKNOWN-ORDER": (
        (0, 255, 256),
        (0, 1, 2, 2, 3, 5, 6, 6, 255, 256),
        (255, 256),
    ),
}

EXPECTED_FINALIZED_MAP_TYPES = {
    "V2-S3-CORE-UNKNOWN-FREE": ((0,), (0, 1, 8), ()),
    "V2-S3-CORE-UNKNOWN-ORDER": (
        (0, 255, 256),
        (0, 1, 8, 255, 256),
        (255, 256),
    ),
}

AGREEMENT_SCOPE = (
    "public-keys,descriptors,derivations,scripts,digests,signatures,psbts,"
    "witnesses,raw-transactions,txids,wtxids,mutations,semantic-transcript"
)
SCREENING_POLICY = "QK-DEC-047/QK-DEC-058/QK-DEC-121/QK-DEC-123"
SCREENING_REPRESENTATIONS = (
    "raw_lowercase_hex_uppercase_hex_contiguous_hex_Rust_byte_arrays_"
    "hex_escapes_decimal_byte_arrays_base64_base58"
)
SCREENING_NAMED_SETS = "tracked_KAT_NUMS_fixture_and_all_other_tracked_material"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as src:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                return h.hexdigest()
            h.update(chunk)


def sha256d_display(data: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()[::-1].hex()


def compact_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("non-finite JSON decimal")
        rendered = format(value, "f")
        if "." in rendered:
            rendered = rendered.rstrip("0").rstrip(".")
        return rendered or "0"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(compact_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("JSON object keys must be strings")
        return "{" + ",".join(
            f"{compact_json(key)}:{compact_json(value[key])}" for key in sorted(value)
        ) + "}"
    raise TypeError(f"unsupported JSON value {type(value).__name__}")


def parse_hex(value: str, label: str) -> bytes:
    if len(value) % 2:
        raise ValueError(f"{label}: odd hex length")
    if re.fullmatch(r"[0-9a-f]*", value) is None:
        raise ValueError(f"{label}: expected canonical lowercase hex")
    return bytes.fromhex(value)


def parse_uint(value: str, label: str, maximum: int | None = None) -> int:
    if re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise ValueError(f"{label}: expected canonical unsigned decimal")
    parsed = int(value)
    if maximum is not None and parsed > maximum:
        raise ValueError(f"{label}: exceeds {maximum}")
    return parsed


def parse_i32(value: str, label: str) -> int:
    if re.fullmatch(r"0|-?[1-9][0-9]*", value) is None:
        raise ValueError(f"{label}: expected canonical signed decimal")
    parsed = int(value)
    if not -(1 << 31) <= parsed < (1 << 31):
        raise ValueError(f"{label}: outside signed 32-bit range")
    return parsed


def require_hash(fields: dict[str, str], name: str) -> str:
    value = required(fields, name)
    if HEX_32.fullmatch(value) is None:
        raise ValueError(f"{name}: expected 32-byte lowercase hash")
    return value


def require_literal(fields: dict[str, str], name: str, expected: str) -> None:
    actual = required(fields, name)
    if actual != expected:
        raise ValueError(f"{name}: actual={actual!r}, expected={expected!r}")


def require_exact_fields(fields: dict[str, str], expected: set[str], label: str) -> None:
    actual = set(fields)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{label}: closed schema mismatch; missing={missing}, extra={extra}")


def parse_fixture(path: Path) -> tuple[dict[str, str], list[dict[str, str]]]:
    header: dict[str, str] = {}
    cases: list[dict[str, str]] = []
    current = header
    for number, raw in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        if ": " not in raw and not raw.endswith(":"):
            raise ValueError(f"fixture line {number}: missing ': ' separator")
        key, value = raw.split(":", 1)
        if re.fullmatch(r"[a-z][a-z0-9_]*", key) is None:
            raise ValueError(f"fixture line {number}: noncanonical field name")
        if value.startswith(" "):
            value = value[1:]
        if value.endswith(" ") or "\t" in value:
            raise ValueError(f"fixture line {number}: noncanonical field whitespace")
        if key == "case":
            if not value:
                raise ValueError(f"fixture line {number}: empty case name")
            current = {"case": value}
            cases.append(current)
        elif key in current:
            raise ValueError(f"fixture line {number}: duplicate field {key}")
        else:
            current[key] = value
    return header, cases


def required(fields: dict[str, str], name: str) -> str:
    try:
        return fields[name]
    except KeyError as exc:
        raise ValueError(f"missing fixture field {name}") from exc


def positive_fields(case: dict[str, str]) -> set[str]:
    output_count = parse_uint(required(case, "output_count"), f"{case.get('case', 'case')} output_count", 100)
    if output_count == 0:
        raise ValueError(f"{case.get('case', 'case')}: output_count must be nonzero")
    fields = set(POSITIVE_BASE_FIELDS)
    for index in range(output_count):
        fields.add(f"output_{index}_amount_sats")
        fields.add(f"output_{index}_script_pubkey_hex")
    if case.get("case") == "V2-S3-CORE-UNKNOWN-ORDER":
        fields |= UNKNOWN_ORDER_FIELDS
    return fields


def negative_fields(case: dict[str, str]) -> set[str]:
    fields = set(NEGATIVE_BASE_FIELDS)
    if case.get("case") in {
        "V2-S3-CORE-MUTATED-SIGNATURE",
        "V2-S3-CORE-MUTATED-BASE",
    }:
        fields |= {"mutation_witness_index", "mutation_byte_offset", "mutation_xor_mask"}
    if case.get("case") == "V2-S3-CORE-MUTATED-BASE":
        fields.remove("mutation_witness_index")
    return fields


def validate_fixture_schema(header: dict[str, str], cases: list[dict[str, str]]) -> None:
    require_exact_fields(header, HEADER_FIELDS, "fixture header")
    actual_cases = [(required(case, "case"), required(case, "class")) for case in cases]
    if actual_cases != EXPECTED_CASES:
        raise ValueError(f"fixture cases: actual={actual_cases!r}, expected={EXPECTED_CASES!r}")
    if len({name for name, _ in actual_cases}) != len(actual_cases):
        raise ValueError("fixture cases: duplicate case name")
    for case in cases:
        name = required(case, "case")
        expected = positive_fields(case) if required(case, "class") == "differential-accept" else negative_fields(case)
        require_exact_fields(case, expected, name)


def validate_provenance(header: dict[str, str], checks: "Checks") -> None:
    literals = {
        "fixture_profile": "QuietKey/v2-slice3/Core/v1",
        "permanent_label": "PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL",
        "generation_procedure": "QK-DEC-047/QK-DEC-121/QK-DEC-123",
        "generated_outside_git": "true",
        "implementation_count": "2",
        "implementation_independence": "separately-written",
        "agreement_scope": AGREEMENT_SCOPE,
        "agreement_result": "byte-for-byte",
        "unique_rfc6979_nonces": "true",
        "screening_policy": SCREENING_POLICY,
        "screening_representations": SCREENING_REPRESENTATIONS,
        "screening_named_sets": SCREENING_NAMED_SETS,
        "screening_small_multiple_limit": "4096",
        "screening_unexpected_hits": "0",
        "screening_small_multiple_hits": "0",
        "same_lineage_matches": "role-a-and-role-b-route-public-keys-and-x-coordinates-in-bip67_sort_vectors.txt+descriptor_pairs.txt+review_v3.txt",
        "initial_destruction_result": "complete",
        "initial_destroyed_root_absent": "true",
        "source_recovery": "local-task-record",
        "recovered_source_hashes_match": "true",
        "recovery_search_artifact": "/tmp/qk-s3-rollout-hits.txt",
        "recovery_search_artifact_absent": "true",
        "destruction_result": "complete",
        "generation_workspace": "/tmp/qk-v2-s3-fixture.YpGNT8",
        "destroyed_root_absent": "true",
        "fixture_lineage": "QK-DEC-121-v2-GOLDEN",
        "mainnet_funding_status": "PERMANENTLY-NEVER-FUND",
        "regtest_coin_status": "valueless-by-construction",
        "source_signing_fixture": SIGNING_FIXTURE_REL.as_posix(),
        "role_a_transcript_ascii": "1234561234561234561234561234561234561234561234561234561234561234561234561234561234561234561234561234",
        "role_b_transcript_ascii": "2345612345612345612345612345612345612345612345612345612345612345612345612345612345612345612345612345",
        "role_a_route_private_scalar_hex": "f157e34f4db1854304bb10aeb045a653aa7c0dc50c9c578b0965ce4e48271134",
        "role_b_route_private_scalar_hex": "4e0f3dd5fefc3acd35eddeb3b66c65fc4e732b8f3f5339e45f6c79f3cc0950b9",
    }
    for name, expected in literals.items():
        checks.equal(required(header, name), expected, f"provenance {name}")
    checks.equal(required(header, "implementation_a_name"), "python-stdlib", "Python constructor name")
    checks.equal(required(header, "implementation_b_name"), "node-stdlib", "Node constructor name")
    checks.equal(
        required(header, "implementation_a_runtime"),
        "/usr/bin/python3:Python 3.9.6",
        "Python constructor runtime",
    )
    checks.equal(
        require_hash(header, "implementation_a_runtime_sha256"),
        "7f30f076d0e9c38f772a76449fca9da8cf97f6a3d43b94c90a00e4f9ce7ad39e",
        "Python runtime hash",
    )
    checks.equal(
        required(header, "implementation_b_runtime"),
        "/Users/admin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node:v24.19.0",
        "Node constructor runtime",
    )
    checks.equal(
        require_hash(header, "implementation_b_runtime_sha256"),
        "1052eb9c7d6c60a79b968e09f75af55a73462b0f6dff0964336d63b5e13eb63c",
        "Node runtime hash",
    )
    for prefix in ("implementation_a", "implementation_b"):
        runtime = required(header, f"{prefix}_runtime")
        checks.that(0 < len(runtime) <= 128 and runtime == runtime.strip(), f"provenance {prefix} runtime")
        checks.that("<" not in runtime and ">" not in runtime, f"provenance {prefix} runtime closed")
        require_hash(header, f"{prefix}_source_sha256")
        checks.that(parse_uint(required(header, f"{prefix}_source_bytes"), f"{prefix} bytes") > 0, f"{prefix} source nonempty")
        checks.that(parse_uint(required(header, f"{prefix}_source_lines"), f"{prefix} lines") > 0, f"{prefix} source has lines")
    checks.that(
        required(header, "implementation_a_source_sha256")
        != required(header, "implementation_b_source_sha256"),
        "constructor source hashes differ",
    )
    checks.equal(
        require_hash(header, "implementation_a_source_sha256"),
        "ff7b87b28378f5d8e50748c63d27dee64aee0b45a3dc795274d36baa4600f89e",
        "Python constructor source hash",
    )
    checks.equal(
        require_hash(header, "implementation_b_source_sha256"),
        "fae226d93910356ee885c815162727b8da823a999c6fc275c45fa1f5f7de45fc",
        "Node constructor source hash",
    )
    for name in ("normalized_agreement_sha256", "screening_source_sha256", "screening_report_sha256"):
        require_hash(header, name)
        checks.that(True, f"provenance {name}")
    checks.equal(
        require_hash(header, "normalized_agreement_sha256"),
        "784e34c3ac21b7c6d4f3717c4cf701356869b688ad62ee49774a84fe7f69faca",
        "normalized agreement hash",
    )
    checks.equal(
        require_hash(header, "reproduced_normalized_agreement_sha256"),
        "784e34c3ac21b7c6d4f3717c4cf701356869b688ad62ee49774a84fe7f69faca",
        "recovered constructor agreement hash",
    )
    checks.equal(
        require_hash(header, "screening_source_sha256"),
        "c9d57bf5070511025872ae1d47bf485a89421b9256d9ed3f5dd8a1aec3aa9a0c",
        "screening source hash",
    )
    checks.equal(
        require_hash(header, "screening_report_sha256"),
        "cf36278baa76f7adca90f35bf471c5f3c9c98cb9d9138247f53f46f46989c540",
        "screening report hash",
    )
    checks.equal(
        require_hash(header, "source_signing_fixture_sha256"),
        "0c1b55c4928cc05d3db3b4d9fa5310ec4011727ad3d2f133f151ec1f4d40ef25",
        "source signing fixture hash",
    )
    checks.equal(
        require_hash(header, "role_a_transcript_sha256"),
        sha256_bytes(required(header, "role_a_transcript_ascii").encode("ascii")),
        "role-A public transcript hash",
    )
    checks.equal(
        require_hash(header, "role_b_transcript_sha256"),
        sha256_bytes(required(header, "role_b_transcript_ascii").encode("ascii")),
        "role-B public transcript hash",
    )
    repository_head = required(header, "screening_repository_head")
    checks.that(
        re.fullmatch(r"[0-9a-f]{40}", repository_head) is not None,
        "provenance screening repository HEAD",
    )
    checks.equal(repository_head, "79553194780fde9d2d44c447c7e97885210d6f12", "screening repository HEAD pin")
    initial_completion = required(header, "initial_deletion_completed_utc")
    checks.that(
        UTC_SECOND.fullmatch(initial_completion) is not None,
        "initial provenance deletion completion UTC",
    )
    checks.equal(
        initial_completion,
        "2026-08-29T00:42:24Z",
        "initial fixture workspace destruction time",
    )
    completion = required(header, "deletion_completed_utc")
    checks.that(UTC_SECOND.fullmatch(completion) is not None, "provenance deletion completion UTC")
    checks.equal(completion, "2026-08-29T00:50:00Z", "final recovered workspace destruction time")
    search_completion = required(header, "recovery_search_artifact_deletion_utc")
    checks.that(
        UTC_SECOND.fullmatch(search_completion) is not None,
        "recovery-search artifact deletion completion UTC",
    )
    checks.equal(
        search_completion,
        "2026-08-29T00:51:36Z",
        "recovery-search artifact destruction time",
    )
    exact_counts = {
        "implementation_a_source_bytes": 28_587,
        "implementation_a_source_lines": 767,
        "implementation_b_source_bytes": 28_285,
        "implementation_b_source_lines": 584,
        "normalized_agreement_bytes": 29_159,
        "normalized_agreement_lines": 1,
        "public_scalar_count": 2,
        "signature_count": 4,
        "rfc6979_nonce_count": 4,
        "screening_tracked_file_count": 3_303,
        "screening_tracked_byte_count": 30_999_398,
        "screened_public_key_count": 2,
        "screened_signature_r_count": 4,
        "screening_source_bytes": 3_800,
        "screening_source_lines": 85,
        "screening_report_bytes": 1_987,
        "screening_report_lines": 1,
        "screening_expected_same_lineage_hits": 12,
        "recovery_search_artifact_bytes": 176_371,
        "source_signing_fixture_bytes": 16_075,
        "source_signing_fixture_lines": 74,
        "initial_destroyed_regular_file_count": 9,
        "initial_destroyed_directory_count": 1,
        "initial_destroyed_symlink_count": 0,
        "initial_destroyed_regular_file_byte_count": 184_766,
        "destroyed_regular_file_count": 6,
        "destroyed_directory_count": 1,
        "destroyed_symlink_count": 0,
        "destroyed_regular_file_byte_count": 173_566,
    }
    for name, expected in exact_counts.items():
        checks.equal(
            parse_uint(required(header, name), name),
            expected,
            f"provenance {name}",
        )


def read_cs(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise ValueError("truncated CompactSize")
    first = data[pos]
    pos += 1
    if first < 0xFD:
        return first, pos
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    end = pos + width
    if end > len(data):
        raise ValueError("truncated CompactSize payload")
    value = int.from_bytes(data[pos:end], "little")
    minimum = {2: 0xFD, 4: 0x10000, 8: 0x100000000}[width]
    if value < minimum:
        raise ValueError("nonminimal CompactSize")
    return value, end


def write_cs(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative CompactSize")
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFF_FFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= 0xFFFF_FFFF_FFFF_FFFF:
        return b"\xff" + value.to_bytes(8, "little")
    raise ValueError("CompactSize overflow")


@dataclass(frozen=True)
class TxInput:
    prev_hash: bytes
    prev_vout: int
    script_sig: bytes
    sequence: int
    witness: tuple[bytes, ...]


@dataclass(frozen=True)
class TxOutput:
    amount_sats: int
    script_pubkey: bytes


@dataclass(frozen=True)
class Transaction:
    version: int
    inputs: tuple[TxInput, ...]
    outputs: tuple[TxOutput, ...]
    locktime: int
    has_witness: bool


def read_bytes(data: bytes, pos: int, length: int, label: str) -> tuple[bytes, int]:
    end = pos + length
    if end > len(data):
        raise ValueError(f"truncated {label}")
    return data[pos:end], end


def parse_transaction(data: bytes) -> Transaction:
    version_bytes, pos = read_bytes(data, 0, 4, "transaction version")
    version = int.from_bytes(version_bytes, "little", signed=True)
    has_witness = data[pos : pos + 2] == b"\x00\x01"
    if has_witness:
        pos += 2
    input_count, pos = read_cs(data, pos)
    inputs: list[TxInput] = []
    for index in range(input_count):
        prev_hash, pos = read_bytes(data, pos, 32, f"input {index} prev hash")
        prev_vout_bytes, pos = read_bytes(data, pos, 4, f"input {index} prev vout")
        script_len, pos = read_cs(data, pos)
        script_sig, pos = read_bytes(data, pos, script_len, f"input {index} scriptSig")
        sequence_bytes, pos = read_bytes(data, pos, 4, f"input {index} sequence")
        inputs.append(
            TxInput(
                prev_hash=prev_hash,
                prev_vout=int.from_bytes(prev_vout_bytes, "little"),
                script_sig=script_sig,
                sequence=int.from_bytes(sequence_bytes, "little"),
                witness=(),
            )
        )
    output_count, pos = read_cs(data, pos)
    outputs: list[TxOutput] = []
    for index in range(output_count):
        amount_bytes, pos = read_bytes(data, pos, 8, f"output {index} amount")
        script_len, pos = read_cs(data, pos)
        script_pubkey, pos = read_bytes(data, pos, script_len, f"output {index} scriptPubKey")
        outputs.append(TxOutput(int.from_bytes(amount_bytes, "little"), script_pubkey))
    if has_witness:
        with_witness: list[TxInput] = []
        for index, txin in enumerate(inputs):
            item_count, pos = read_cs(data, pos)
            items: list[bytes] = []
            for item_index in range(item_count):
                item_len, pos = read_cs(data, pos)
                item, pos = read_bytes(data, pos, item_len, f"input {index} witness {item_index}")
                items.append(item)
            with_witness.append(
                TxInput(txin.prev_hash, txin.prev_vout, txin.script_sig, txin.sequence, tuple(items))
            )
        inputs = with_witness
    locktime_bytes, pos = read_bytes(data, pos, 4, "transaction locktime")
    if pos != len(data):
        raise ValueError("transaction trailing bytes")
    if input_count == 0:
        raise ValueError("transaction has no inputs")
    if output_count == 0:
        raise ValueError("transaction has no outputs")
    if has_witness and not any(txin.witness for txin in inputs):
        raise ValueError("superfluous witness marker/flag")
    return Transaction(
        version=version,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        locktime=int.from_bytes(locktime_bytes, "little"),
        has_witness=has_witness,
    )


def serialize_transaction(tx: Transaction, include_witness: bool) -> bytes:
    out = bytearray(tx.version.to_bytes(4, "little", signed=True))
    if include_witness:
        out.extend(b"\x00\x01")
    out.extend(write_cs(len(tx.inputs)))
    for txin in tx.inputs:
        out.extend(txin.prev_hash)
        out.extend(txin.prev_vout.to_bytes(4, "little"))
        out.extend(write_cs(len(txin.script_sig)))
        out.extend(txin.script_sig)
        out.extend(txin.sequence.to_bytes(4, "little"))
    out.extend(write_cs(len(tx.outputs)))
    for txout in tx.outputs:
        out.extend(txout.amount_sats.to_bytes(8, "little"))
        out.extend(write_cs(len(txout.script_pubkey)))
        out.extend(txout.script_pubkey)
    if include_witness:
        for txin in tx.inputs:
            out.extend(write_cs(len(txin.witness)))
            for item in txin.witness:
                out.extend(write_cs(len(item)))
                out.extend(item)
    out.extend(tx.locktime.to_bytes(4, "little"))
    return bytes(out)


def replace_witness(tx: Transaction, witness: tuple[bytes, ...]) -> Transaction:
    if len(tx.inputs) != 1:
        raise ValueError("mutation parent must have one input")
    txin = tx.inputs[0]
    replaced = TxInput(txin.prev_hash, txin.prev_vout, txin.script_sig, txin.sequence, witness)
    return Transaction(tx.version, (replaced,), tx.outputs, tx.locktime, True)


def strict_der_value_indices(stored_signature: bytes, label: str) -> set[int]:
    if not 9 <= len(stored_signature) <= 72 or stored_signature[-1] != 0x01:
        raise ValueError(f"{label}: expected strict DER plus SIGHASH_ALL")
    der = stored_signature[:-1]
    if der[0] != 0x30 or der[1] != len(der) - 2 or der[2] != 0x02:
        raise ValueError(f"{label}: invalid DER sequence")
    r_len = der[3]
    r_start = 4
    r_end = r_start + r_len
    if r_len == 0 or r_end + 2 > len(der) or der[r_end] != 0x02:
        raise ValueError(f"{label}: invalid DER R")
    s_len = der[r_end + 1]
    s_start = r_end + 2
    s_end = s_start + s_len
    if s_len == 0 or s_end != len(der):
        raise ValueError(f"{label}: invalid DER S")
    for name, start, end in (("R", r_start, r_end), ("S", s_start, s_end)):
        integer = der[start:end]
        if integer[0] & 0x80:
            raise ValueError(f"{label}: negative DER {name}")
        if len(integer) > 1 and integer[0] == 0 and not integer[1] & 0x80:
            raise ValueError(f"{label}: nonminimal DER {name}")
    return set(range(r_start, r_end)) | set(range(s_start, s_end))


def strict_der_r(stored_signature: bytes, label: str) -> bytes:
    strict_der_value_indices(stored_signature, label)
    r_len = stored_signature[3]
    return stored_signature[4 : 4 + r_len]


def btc_to_sats(value: Decimal, label: str) -> int:
    sats = value * Decimal(100_000_000)
    integral = sats.to_integral_value()
    if sats != integral or integral < 0 or integral > 21_000_000 * 100_000_000:
        raise ValueError(f"{label}: noncanonical Bitcoin amount")
    return int(integral)


def tx_counts(unsigned: bytes) -> tuple[int, int]:
    pos = 4
    vin, pos = read_cs(unsigned, pos)
    for _ in range(vin):
        pos += 36
        script_len, pos = read_cs(unsigned, pos)
        pos += script_len + 4
        if pos > len(unsigned):
            raise ValueError("truncated unsigned transaction input")
    vout, pos = read_cs(unsigned, pos)
    for _ in range(vout):
        pos += 8
        script_len, pos = read_cs(unsigned, pos)
        pos += script_len
        if pos > len(unsigned):
            raise ValueError("truncated unsigned transaction output")
    if pos + 4 != len(unsigned):
        raise ValueError("unsigned transaction trailing or truncated locktime")
    return vin, vout


Record = tuple[int, bytes, bytes]


def parse_psbt(data: bytes) -> list[list[Record]]:
    if not data.startswith(b"psbt\xff"):
        raise ValueError("bad PSBT magic")
    pos = 5

    def one_map() -> list[Record]:
        nonlocal pos
        records: list[Record] = []
        keys: set[bytes] = set()
        while True:
            key_len, pos = read_cs(data, pos)
            if key_len == 0:
                return records
            key_end = pos + key_len
            if key_end > len(data):
                raise ValueError("truncated PSBT key")
            key = data[pos:key_end]
            pos = key_end
            value_len, pos = read_cs(data, pos)
            value_end = pos + value_len
            if value_end > len(data):
                raise ValueError("truncated PSBT value")
            value = data[pos:value_end]
            pos = value_end
            key_type, type_end = read_cs(key, 0)
            if type_end > len(key):
                raise ValueError("bad PSBT key type")
            if key in keys:
                raise ValueError("duplicate PSBT complete key")
            keys.add(key)
            records.append((key_type, key, value))

    maps = [one_map()]
    unsigned_values = [value for typ, key, value in maps[0] if typ == 0 and len(key) == 1]
    if len(unsigned_values) != 1:
        raise ValueError("PSBT must contain one unsigned transaction")
    vin, vout = tx_counts(unsigned_values[0])
    maps.extend(one_map() for _ in range(vin + vout))
    if pos != len(data):
        raise ValueError("PSBT trailing bytes")
    return maps


def serialize_psbt(maps: list[list[Record]]) -> bytes:
    out = bytearray(b"psbt\xff")
    for records in maps:
        for _, key, value in records:
            out.extend(write_cs(len(key)))
            out.extend(key)
            out.extend(write_cs(len(value)))
            out.extend(value)
        out.append(0)
    return bytes(out)


def psbt_unsigned(maps: list[list[Record]]) -> bytes:
    values = [value for typ, key, value in maps[0] if typ == 0 and key == b"\x00"]
    if len(values) != 1:
        raise ValueError("PSBT must have one unsigned transaction record")
    return values[0]


def key_data(record: Record) -> bytes:
    _, key, _ = record
    _, pos = read_cs(key, 0)
    return key[pos:]


def map_multisets(maps: list[list[Record]]) -> list[list[Record]]:
    return [sorted(records, key=lambda item: (item[0], item[1], item[2])) for records in maps]


def swap_only_255_256(maps: list[list[Record]]) -> list[list[Record]]:
    copied = [list(records) for records in maps]
    selected: list[tuple[int, int, int]] = []
    for map_index, records in enumerate(copied):
        positions = [index for index, record in enumerate(records) if record[0] in (255, 256)]
        if positions:
            types = [records[index][0] for index in positions]
            if types != [255, 256]:
                raise ValueError("QuietKey unknown records are not exactly [255,256]")
            selected.append((map_index, positions[0], positions[1]))
    if [map_index for map_index, _, _ in selected] != list(range(len(copied))):
        raise ValueError("expected exactly one 255/256 pair in every PSBT map")
    for map_index, first, second in selected:
        copied[map_index][first], copied[map_index][second] = (
            copied[map_index][second],
            copied[map_index][first],
        )
    return copied


def locate_255_256_order(
    maps: list[list[Record]],
) -> list[tuple[int, list[int], list[str]]]:
    found: list[tuple[int, list[int], list[str]]] = []
    for index, records in enumerate(maps):
        selected = [(typ, key.hex()) for typ, key, _ in records if typ in (255, 256)]
        if selected:
            found.append((index, [typ for typ, _ in selected], [key for _, key in selected]))
    if [map_index for map_index, _, _ in found] != list(range(len(maps))):
        raise ValueError("expected exactly one unknown type-255/type-256 pair in every PSBT map")
    return found


def render_unknown_full_keys(
    orders: list[tuple[int, list[int], list[str]]],
) -> str:
    return "|".join(",".join(keys) for _, _, keys in orders)


class Checks:
    def __init__(self) -> None:
        self.total = 0

    def that(self, condition: bool, message: str) -> None:
        self.total += 1
        if not condition:
            raise AssertionError(message)

    def equal(self, actual: Any, expected: Any, message: str) -> None:
        self.that(actual == expected, f"{message}: actual={actual!r}, expected={expected!r}")


def decode_cli_result(method: str, raw: str) -> Any:
    if raw in ("", "null"):
        return None
    if method in {"getblockhash", "stop"}:
        return raw
    if method == "submitblock" and not raw.startswith(("{", "[")):
        return raw
    return json.loads(raw, parse_float=Decimal)


class Core:
    def __init__(self, bitcoind: Path, cli: Path, root: Path, port: int, transcript: list[str]):
        self.bitcoind = bitcoind
        self.cli = cli
        self.root = root
        self.port = port
        self.transcript = transcript
        self.process: subprocess.Popen[bytes] | None = None
        self.log_handle: Any = None
        self.rpc_index = 0

    def start(self) -> None:
        log_path = self.root / "bitcoind.log"
        self.log_handle = log_path.open("wb")
        args = [
            str(self.bitcoind),
            f"-datadir={self.root}",
            "-regtest=1",
            "-server=1",
            "-disablewallet=1",
            "-listen=0",
            "-connect=0",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-discover=0",
            "-upnp=0",
            "-natpmp=0",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            f"-rpcport={self.port}",
            "-printtoconsole=1",
        ]
        self.process = subprocess.Popen(args, stdout=self.log_handle, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        last_error = ""
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"bitcoind exited during startup with {self.process.returncode}")
            try:
                self.rpc("getblockchaininfo")
                return
            except RuntimeError as exc:
                last_error = str(exc)
                time.sleep(0.1)
        raise RuntimeError(f"bitcoind RPC startup timeout: {last_error}")

    def rpc(self, method: str, *params: Any) -> Any:
        cli_params = [param if isinstance(param, str) else compact_json(param) for param in params]
        args = [
            str(self.cli),
            "-regtest",
            f"-datadir={self.root}",
            f"-rpcport={self.port}",
            "-rpcclienttimeout=30",
            method,
            *cli_params,
        ]
        prefix = f"rpc_{self.rpc_index:03d}"
        self.transcript.append(f"{prefix}_method={method}")
        self.transcript.append(f"{prefix}_params={compact_json(list(params))}")
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            self.transcript.append(
                f'{prefix}_error={{"cli_exit":{proc.returncode},"kind":"rpc-command-failed"}}'
            )
            self.rpc_index += 1
            raise RuntimeError(f"RPC {method} failed with exit {proc.returncode}")
        raw = proc.stdout.strip()
        try:
            result = decode_cli_result(method, raw)
        except Exception as exc:
            self.transcript.append(
                f"{prefix}_error={compact_json({'kind': 'result-decode-failed', 'type': type(exc).__name__})}"
            )
            self.rpc_index += 1
            raise RuntimeError(f"RPC {method} returned an invalid result") from exc
        self.transcript.append(f"{prefix}_result={compact_json(result)}")
        self.rpc_index += 1
        return result

    def stop(self) -> int:
        try:
            if self.process is None:
                return 0
            if self.process.poll() is None:
                try:
                    self.rpc("stop")
                except Exception as exc:  # preserve failure in transcript; still terminate below
                    self.transcript.append(
                        f"daemon_stop_rpc_error_type={type(exc).__name__}"
                    )
                try:
                    self.process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=10)
            return int(self.process.returncode or 0)
        finally:
            if self.log_handle is not None:
                self.log_handle.close()
                self.log_handle = None


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def first_line(path: Path, argument: str) -> str:
    proc = subprocess.run([str(path), argument], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{path.name} {argument} failed")
    return proc.stdout.splitlines()[0]


def choose_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def safe_extract(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            target = (destination / member.name).resolve()
            if root not in target.parents and target != root:
                raise ValueError("archive path escapes extraction root")
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError("archive contains unsupported link/device entry")
        tar.extractall(destination, members=members)


def fixture_bytes(case: dict[str, str], stem: str, checks: Checks) -> bytes:
    label = case.get("case", "header")
    data = parse_hex(required(case, f"{stem}_hex"), f"{label} {stem}")
    expected_len = parse_uint(required(case, f"{stem}_len"), f"{label} {stem} length")
    checks.equal(len(data), expected_len, f"{label} {stem} length")
    checks.equal(sha256_bytes(data), require_hash(case, f"{stem}_sha256"), f"{label} {stem} SHA256")
    return data


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def assert_head_file(repo: Path, path: Path, relative: Path, label: str, checks: Checks) -> str:
    checks.equal(path, (repo / relative).resolve(), f"{label} canonical repository path")
    relative_text = relative.as_posix()
    tracked = git(repo, "ls-files", "--error-unmatch", "--", relative_text)
    checks.equal(tracked, relative_text, f"{label} tracked path")
    head_blob = git(repo, "rev-parse", f"HEAD:{relative_text}")
    worktree_blob = git(repo, "hash-object", "--", relative_text)
    checks.equal(worktree_blob, head_blob, f"{label} bytes equal HEAD blob")
    return head_blob


def witness_script_keys(script: bytes) -> tuple[bytes, bytes]:
    if len(script) != 71 or script[0:2] != b"\x52\x21" or script[35] != 0x21:
        raise ValueError("witnessScript: wrong sortedmulti frame")
    if script[69:] != b"\x52\xae":
        raise ValueError("witnessScript: wrong sortedmulti trailer")
    keys = (script[2:35], script[36:69])
    if any(len(key) != 33 or key[0] not in (2, 3) for key in keys):
        raise ValueError("witnessScript: invalid compressed pubkey")
    if not keys[0] < keys[1]:
        raise ValueError("witnessScript: pubkeys are not distinct strict BIP67 order")
    return keys


def serialize_witness(items: tuple[bytes, ...]) -> bytes:
    out = bytearray(write_cs(len(items)))
    for item in items:
        out.extend(write_cs(len(item)))
        out.extend(item)
    return bytes(out)


@dataclass(frozen=True)
class PositivePayload:
    tx: Transaction
    raw_tx: bytes
    stripped_tx: bytes
    signed_maps: list[list[Record]]
    finalized_maps: list[list[Record]]
    selected_positions: tuple[int, int]


def validate_positive_payload(
    case: dict[str, str],
    header: dict[str, str],
    signed: bytes,
    finalized: bytes,
    raw_tx: bytes,
    stripped: bytes,
    checks: Checks,
) -> PositivePayload:
    name = required(case, "case")
    tx = parse_transaction(raw_tx)
    stripped_tx = parse_transaction(stripped)
    checks.that(tx.has_witness, f"{name} raw transaction has BIP141 witness")
    checks.that(not stripped_tx.has_witness, f"{name} stripped transaction has no witness marker")
    checks.equal(serialize_transaction(tx, True), raw_tx, f"{name} raw transaction canonical reserialization")
    checks.equal(serialize_transaction(stripped_tx, False), stripped, f"{name} stripped transaction canonical reserialization")
    checks.equal(serialize_transaction(tx, False), stripped, f"{name} witness stripping")
    checks.equal(tx.version, stripped_tx.version, f"{name} stripped version")
    raw_base_inputs = tuple(TxInput(i.prev_hash, i.prev_vout, i.script_sig, i.sequence, ()) for i in tx.inputs)
    checks.equal(raw_base_inputs, stripped_tx.inputs, f"{name} stripped inputs")
    checks.equal(tx.outputs, stripped_tx.outputs, f"{name} stripped outputs")
    checks.equal(tx.locktime, stripped_tx.locktime, f"{name} stripped locktime")
    checks.equal(sha256d_display(stripped), require_hash(case, "txid"), f"{name} local txid")
    checks.equal(sha256d_display(raw_tx), require_hash(case, "wtxid"), f"{name} local wtxid")

    receive = required(case, "receive_descriptor")
    change = required(case, "change_descriptor")
    checks.equal(len(receive.encode("ascii")), 306, f"{name} receive descriptor length")
    checks.equal(len(change.encode("ascii")), 306, f"{name} change descriptor length")
    checks.equal(
        sha256_bytes(receive.encode("ascii") + b"\x00" + change.encode("ascii")),
        require_hash(case, "wallet_id"),
        f"{name} wallet_id",
    )
    checks.equal(bytes.fromhex(require_hash(case, "wallet_id")), GOLDEN_WALLET_ID, f"{name} GOLDEN wallet_id")

    checks.equal(parse_uint(required(case, "input_count"), f"{name} input_count"), 1, f"{name} one fixture input")
    checks.equal(len(tx.inputs), 1, f"{name} one parsed input")
    txin = tx.inputs[0]
    prev_txid = txin.prev_hash[::-1].hex()
    checks.equal(prev_txid, require_hash(case, "input_0_prev_txid"), f"{name} input prev txid")
    checks.equal(prev_txid, require_hash(header, "seed_coinbase_txid"), f"{name} spends seed coinbase")
    expected_vout = parse_uint(required(case, "input_0_prev_vout"), f"{name} input vout", 0xFFFF_FFFF)
    checks.equal(txin.prev_vout, expected_vout, f"{name} input vout")
    checks.equal(expected_vout, parse_uint(required(header, "seed_vout"), "seed_vout", 0xFFFF_FFFF), f"{name} seed vout")
    checks.equal(txin.sequence, parse_uint(required(case, "input_0_sequence"), f"{name} sequence", 0xFFFF_FFFF), f"{name} sequence")
    checks.equal(txin.script_sig, parse_hex(required(case, "input_0_script_sig_hex"), f"{name} scriptSig"), f"{name} empty fixture scriptSig")
    checks.equal(txin.script_sig, b"", f"{name} native witness empty scriptSig")
    checks.equal(tx.version, parse_i32(required(case, "tx_version"), f"{name} version"), f"{name} version")
    checks.equal(tx.locktime, parse_uint(required(case, "tx_locktime"), f"{name} locktime", 0xFFFF_FFFF), f"{name} locktime")

    output_count = parse_uint(required(case, "output_count"), f"{name} output_count", 100)
    checks.equal(len(tx.outputs), output_count, f"{name} output count")
    output_total = 0
    for index, txout in enumerate(tx.outputs):
        expected_amount = parse_uint(required(case, f"output_{index}_amount_sats"), f"{name} output {index} amount", 21_000_000 * 100_000_000)
        expected_script = parse_hex(required(case, f"output_{index}_script_pubkey_hex"), f"{name} output {index} script")
        checks.equal(txout.amount_sats, expected_amount, f"{name} output {index} amount")
        checks.equal(txout.script_pubkey, expected_script, f"{name} output {index} script")
        output_total += txout.amount_sats
    seed_amount = parse_uint(required(header, "seed_amount_sats"), "seed_amount_sats", 21_000_000 * 100_000_000)
    checks.that(output_total <= seed_amount, f"{name} output total does not exceed seed")
    checks.equal(seed_amount - output_total, parse_uint(required(case, "fee_sats"), f"{name} fee_sats"), f"{name} exact fee")

    checks.equal(parse_uint(required(case, "witness_item_count"), f"{name} witness count"), 4, f"{name} fixture witness count")
    witness = tuple(parse_hex(required(case, f"witness_{index}_hex"), f"{name} witness {index}") for index in range(4))
    checks.equal(txin.witness, witness, f"{name} exact witness bytes")
    checks.equal(witness[0], b"", f"{name} zero-length CHECKMULTISIG dummy")
    strict_der_value_indices(witness[1], f"{name} witness signature 1")
    strict_der_value_indices(witness[2], f"{name} witness signature 2")
    keys = witness_script_keys(witness[3])
    seed_script = parse_hex(required(header, "seed_script_pubkey_hex"), "seed_script_pubkey_hex")
    checks.equal(seed_script, b"\x00\x20" + hashlib.sha256(witness[3]).digest(), f"{name} seed P2WSH commitment")
    witness_pubkeys = (
        parse_hex(required(case, "witness_1_pubkey"), f"{name} witness pubkey 1"),
        parse_hex(required(case, "witness_2_pubkey"), f"{name} witness pubkey 2"),
    )
    positions = tuple(keys.index(pubkey) if pubkey in keys else -1 for pubkey in witness_pubkeys)
    checks.that(positions[0] >= 0 and positions[1] >= 0, f"{name} witness pubkeys are script members")
    checks.that(positions[0] < positions[1], f"{name} witness signatures follow script positions")

    signed_maps = parse_psbt(signed)
    finalized_maps = parse_psbt(finalized)
    checks.equal(
        tuple(tuple(record[0] for record in records) for records in signed_maps),
        EXPECTED_SIGNED_MAP_TYPES[name],
        f"{name} exact signed per-map type shape",
    )
    checks.equal(
        tuple(tuple(record[0] for record in records) for records in finalized_maps),
        EXPECTED_FINALIZED_MAP_TYPES[name],
        f"{name} exact finalized per-map type shape",
    )
    checks.equal(serialize_psbt(signed_maps), signed, f"{name} signed PSBT exact parse round trip")
    checks.equal(serialize_psbt(finalized_maps), finalized, f"{name} finalized PSBT exact parse round trip")
    checks.equal(psbt_unsigned(signed_maps), stripped, f"{name} signed unsigned transaction")
    checks.equal(psbt_unsigned(finalized_maps), stripped, f"{name} finalized unsigned transaction")
    expected_map_count = 2 + len(tx.outputs)
    checks.equal(len(signed_maps), expected_map_count, f"{name} signed map count")
    checks.equal(len(finalized_maps), expected_map_count, f"{name} finalized map count")
    partial = [(key_data(record), record[2]) for record in signed_maps[1] if record[0] == 2]
    checks.equal(len(partial), 2, f"{name} exactly two signed partial signatures")
    checks.equal(len({pubkey for pubkey, _ in partial}), len(partial), f"{name} distinct partial-signature pubkeys")
    checks.that(all(pubkey in keys for pubkey, _ in partial), f"{name} partial signatures are script members")
    partial_positions = [keys.index(pubkey) for pubkey, _ in partial]
    checks.equal(partial_positions, sorted(partial_positions), f"{name} partial signatures already follow script positions")
    selected = sorted(partial, key=lambda item: keys.index(item[0]))
    checks.equal(tuple(pubkey for pubkey, _ in selected), witness_pubkeys, f"{name} selected signature pubkeys")
    checks.equal(tuple(signature for _, signature in selected), witness[1:3], f"{name} selected signature values")
    witness_scripts = [record[2] for record in signed_maps[1] if record[0] == 5]
    checks.that(len(witness_scripts) <= 1, f"{name} optional signed witnessScript count")
    if witness_scripts:
        checks.equal(witness_scripts[0], witness[3], f"{name} signed witnessScript")
    derivation_keys = [key_data(record) for record in signed_maps[1] if record[0] == 6]
    checks.equal(len(derivation_keys), 2, f"{name} two signed derivations")
    checks.equal(set(derivation_keys), set(keys), f"{name} derivation keys equal script keys")
    final_input = finalized_maps[1]
    final_witnesses = [record for record in final_input if record[0] == 8]
    checks.equal(len(final_witnesses), 1, f"{name} one final witness record")
    checks.equal(final_witnesses[0][1], b"\x08", f"{name} final witness empty key data")
    checks.equal(final_witnesses[0][2], serialize_witness(witness), f"{name} final witness serialization")
    checks.that(not any(2 <= record[0] <= 7 for record in final_input), f"{name} signing fields removed and final_scriptSig absent")
    checks.equal(finalized_maps[0], signed_maps[0], f"{name} global map byte-frozen")
    checks.equal(finalized_maps[2:], signed_maps[2:], f"{name} output maps byte-frozen")
    expected_input: list[Record] = []
    final_record: Record = (8, b"\x08", serialize_witness(witness))
    final_inserted = False
    for record in signed_maps[1]:
        if 2 <= record[0] <= 6:
            continue
        checks.that(record[0] not in (7, 8), f"{name} no preexisting final input fields")
        if not final_inserted and record[0] > 8:
            expected_input.append(final_record)
            final_inserted = True
        expected_input.append(record)
    if not final_inserted:
        expected_input.append(final_record)
    checks.equal(final_input, expected_input, f"{name} exact input-map preservation delta")

    review_s0 = fixture_bytes(case, "review_s0", checks)
    expected_review_maps = [list(records) for records in signed_maps]
    expected_review_maps[1] = [record for record in expected_review_maps[1] if record[0] != 2]
    checks.equal(
        serialize_psbt(expected_review_maps),
        review_s0,
        f"{name} pre-insertion S0 is signed PSBT without type-02 records",
    )
    canonical = fixture_bytes(case, "canonical_review_v3", checks)
    checks.that(len(canonical) >= 99, f"{name} canonical review fixed prefix present")
    checks.equal(canonical[0], REVIEW_SCHEMA, f"{name} schema byte 03")
    checks.equal(canonical[1:3], b"\x01\x01", f"{name} mainnet and MicroSd tags")
    checks.equal(canonical[3:35], hashlib.sha256(review_s0).digest(), f"{name} canonical S0 identity")
    checks.equal(canonical[35:67], GOLDEN_WALLET_ID, f"{name} canonical wallet_id")
    checks.equal(canonical[67:75], GOLDEN_FINGERPRINTS, f"{name} canonical A/B fingerprints")
    policy_len = int.from_bytes(canonical[75:79], "little")
    checks.equal(policy_len, len(FEE_POLICY), f"{name} policy identifier length")
    checks.equal(canonical[79 : 79 + policy_len], FEE_POLICY, f"{name} policy identifier bytes")
    checks.equal(required(case, "review_schema"), "03", f"{name} declared schema")
    checks.equal(required(case, "review_domain"), REVIEW_DOMAIN.decode("ascii"), f"{name} declared domain")
    checks.equal(required(case, "fee_policy"), FEE_POLICY.decode("ascii"), f"{name} declared policy")
    checks.equal(parse_uint(required(case, "review_s0_len"), f"{name} review S0 length"), len(review_s0), f"{name} declared review S0 length")
    checks.equal(
        require_hash(case, "review_s0_sha256"),
        sha256_bytes(review_s0),
        f"{name} declared review S0 SHA256",
    )
    review_hash = hashlib.sha256(REVIEW_DOMAIN + b"\x00" + canonical).hexdigest()
    checks.equal(review_hash, require_hash(case, "review_hash"), f"{name} domain-separated review hash")
    checks.equal(required(case, "origin_fingerprint_a"), "2fae9711", f"{name} fingerprint A")
    checks.equal(required(case, "origin_fingerprint_b"), "72a14ab8", f"{name} fingerprint B")
    estimated_weight = 4 * len(stripped) + 2 + 220 * len(tx.inputs)
    estimated_vsize = (estimated_weight + 3) // 4
    fee_sats = parse_uint(required(case, "fee_sats"), f"{name} fee")
    fee_rate = fee_sats * 1000 // estimated_vsize
    checks.equal(parse_uint(required(case, "estimated_weight"), f"{name} weight"), estimated_weight, f"{name} estimated weight")
    checks.equal(parse_uint(required(case, "estimated_vsize"), f"{name} vsize"), estimated_vsize, f"{name} estimated vsize")
    checks.equal(parse_uint(required(case, "fee_rate_msat_vb"), f"{name} rate"), fee_rate, f"{name} fee rate")
    checks.equal(required(case, "warning_tags"), "none", f"{name} no warning tags")
    return PositivePayload(tx, raw_tx, stripped, signed_maps, finalized_maps, (positions[0], positions[1]))


def validate_core_decoded(case: dict[str, str], payload: PositivePayload, decoded: dict[str, Any], checks: Checks) -> None:
    name = required(case, "case")
    tx = payload.tx
    checks.equal(decoded["version"], tx.version, f"{name} Core version")
    checks.equal(decoded["locktime"], tx.locktime, f"{name} Core locktime")
    checks.equal(decoded["size"], len(payload.raw_tx), f"{name} Core serialized size")
    checks.equal(len(decoded["vin"]), 1, f"{name} Core input count")
    vin = decoded["vin"][0]
    txin = tx.inputs[0]
    checks.equal(vin["txid"], txin.prev_hash[::-1].hex(), f"{name} Core input txid")
    checks.equal(vin["vout"], txin.prev_vout, f"{name} Core input vout")
    checks.equal(vin["sequence"], txin.sequence, f"{name} Core input sequence")
    checks.equal(vin["scriptSig"]["hex"], txin.script_sig.hex(), f"{name} Core scriptSig")
    checks.equal(vin["txinwitness"], [item.hex() for item in txin.witness], f"{name} Core witness")
    checks.equal(len(decoded["vout"]), len(tx.outputs), f"{name} Core output count")
    for index, (decoded_output, txout) in enumerate(zip(decoded["vout"], tx.outputs)):
        checks.equal(decoded_output["n"], index, f"{name} Core output {index} index")
        checks.equal(btc_to_sats(decoded_output["value"], f"{name} Core output {index}"), txout.amount_sats, f"{name} Core output {index} amount")
        checks.equal(decoded_output["scriptPubKey"]["hex"], txout.script_pubkey.hex(), f"{name} Core output {index} script")


def derive_negative(case: dict[str, str], parent: PositivePayload, checks: Checks) -> bytes:
    name = required(case, "case")
    parent_witness = parent.tx.inputs[0].witness
    mutation = required(case, "mutation")
    if name == "V2-S3-CORE-SWAPPED-SIGNATURES":
        checks.equal(mutation, "witness-items-1-and-2-swapped", f"{name} mutation label")
        witness = (parent_witness[0], parent_witness[2], parent_witness[1], parent_witness[3])
    elif name == "V2-S3-CORE-MUTATED-SIGNATURE":
        checks.equal(mutation, "strict-der-preserving-signature-value-bit-flip", f"{name} mutation label")
        witness_index = parse_uint(required(case, "mutation_witness_index"), f"{name} witness index", 3)
        checks.that(witness_index in (1, 2), f"{name} signature witness index")
        offset = parse_uint(required(case, "mutation_byte_offset"), f"{name} mutation byte offset")
        mask_bytes = parse_hex(required(case, "mutation_xor_mask"), f"{name} mutation XOR mask")
        checks.equal(len(mask_bytes), 1, f"{name} one-byte XOR mask")
        mask = mask_bytes[0]
        checks.that(mask != 0 and mask & (mask - 1) == 0, f"{name} single-bit XOR mask")
        allowed_indices = strict_der_value_indices(parent_witness[witness_index], f"{name} parent DER")
        checks.that(offset in allowed_indices, f"{name} mutation lies inside DER integer value")
        mutated = bytearray(parent_witness[witness_index])
        mutated[offset] ^= mask
        strict_der_value_indices(bytes(mutated), f"{name} mutated DER")
        items = list(parent_witness)
        items[witness_index] = bytes(mutated)
        witness = tuple(items)
    elif name == "V2-S3-CORE-MUTATED-BASE":
        checks.equal(mutation, "output-0-amount-byte-0-xor-01", f"{name} mutation label")
        offset = parse_uint(required(case, "mutation_byte_offset"), f"{name} mutation byte offset")
        mask_bytes = parse_hex(required(case, "mutation_xor_mask"), f"{name} mutation XOR mask")
        checks.equal(offset, 49, f"{name} first output amount byte offset")
        checks.equal(mask_bytes, b"\x01", f"{name} one-bit XOR mask")
        mutated_raw = bytearray(parent.raw_tx)
        mutated_raw[offset] ^= mask_bytes[0]
        return bytes(mutated_raw)
    else:
        raise ValueError(f"{name}: closed negative mutation")
    return serialize_transaction(replace_witness(parent.tx, witness), True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--procedure", required=True, type=Path)
    parser.add_argument("--sha256sums", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--transcript", required=True, type=Path)
    args = parser.parse_args()

    repo = args.repo_root.resolve()
    transcript_path = args.transcript.resolve()
    if transcript_path.exists():
        raise SystemExit("refusing to overwrite transcript")
    evidence_root = (repo / EVIDENCE_REL).resolve()
    transcript_name = TRANSCRIPT_NAME.fullmatch(transcript_path.name)
    if transcript_path.parent != evidence_root or transcript_name is None:
        raise SystemExit(
            "transcript must be a new differential/v2-slice3-bitcoin-core/evidence/"
            "run-YYYYMMDDTHHMMSSZ-<HEAD>.txt path"
        )
    transcript: list[str] = [
        "QUIETKEY_V2_S3_CORE_DIFFERENTIAL_TRANSCRIPT_V1",
        "commit_every_run=true",
    ]
    checks = Checks()
    core: Core | None = None
    error: str | None = None
    error_detail: str | None = None

    try:
        fixture = args.fixture.resolve()
        procedure = args.procedure.resolve()
        sums = args.sha256sums.resolve()
        archive = args.archive.resolve()
        runner = Path(__file__).resolve()
        signing_fixture = (repo / SIGNING_FIXTURE_REL).resolve()

        checks.equal(git(repo, "status", "--porcelain", "--untracked-files=all"), "", "repository clean at entry")
        repo_commit = git(repo, "rev-parse", "HEAD")
        checks.that(
            repo_commit.startswith(transcript_name.group("commit")),
            "transcript filename commit suffix matches HEAD",
        )
        runner_blob = assert_head_file(repo, runner, HARNESS_REL, "runner", checks)
        fixture_blob = assert_head_file(repo, fixture, FIXTURE_REL, "fixture", checks)
        procedure_blob = assert_head_file(repo, procedure, PROCEDURE_REL, "procedure", checks)
        signing_fixture_blob = assert_head_file(
            repo,
            signing_fixture,
            SIGNING_FIXTURE_REL,
            "source signing fixture",
            checks,
        )
        checks.equal(platform.system(), "Darwin", "Core archive host operating system")
        checks.equal(platform.machine(), "x86_64", "Core archive host architecture")
        checks.equal(platform.python_version(), "3.9.6", "differential runner Python version")
        transcript.extend(
            [
                f"run_utc={dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')}",
                f"repo_commit={repo_commit}",
                f"repo_tree={git(repo, 'rev-parse', 'HEAD^{tree}')}",
                "repo_clean=true",
                f"host_os={platform.system()}",
                f"host_release={platform.release()}",
                f"host_arch={platform.machine()}",
                f"python_version={platform.python_version()}",
                f"harness_sha256={sha256_file(runner)}",
                f"harness_head_blob={runner_blob}",
                f"procedure_sha256={sha256_file(procedure)}",
                f"procedure_head_blob={procedure_blob}",
                f"fixture_sha256={sha256_file(fixture)}",
                f"fixture_head_blob={fixture_blob}",
                f"source_signing_fixture_sha256={sha256_file(signing_fixture)}",
                f"source_signing_fixture_head_blob={signing_fixture_blob}",
                f"core_release={CORE_RELEASE}",
            ]
        )

        sums_data = sums.read_bytes()
        checks.equal(len(sums_data), SUMS_BYTES, "SHA256SUMS size")
        checks.equal(sums_data.count(b"\n"), SUMS_LINES, "SHA256SUMS LF count")
        checks.that(sums_data.endswith(b"\n"), "SHA256SUMS final LF")
        checks.equal(sha256_bytes(sums_data), SUMS_SHA256, "SHA256SUMS SHA256")
        lines = sums_data.decode("ascii").splitlines()
        checks.equal([line for line in lines if line.endswith(f"  {CORE_ARCHIVE}")], [SUMS_LINE], "selected checksum line")
        checks.equal(archive.name, CORE_ARCHIVE, "archive filename")
        checks.equal(archive.stat().st_size, CORE_ARCHIVE_BYTES, "archive size")
        checks.equal(sha256_file(archive), CORE_ARCHIVE_SHA256, "archive SHA256")
        transcript.extend(
            [
                f"sha256sums_bytes={SUMS_BYTES}",
                f"sha256sums_lines={SUMS_LINES}",
                f"sha256sums_sha256={SUMS_SHA256}",
                f"core_archive={CORE_ARCHIVE}",
                f"core_archive_bytes={CORE_ARCHIVE_BYTES}",
                f"core_archive_sha256={CORE_ARCHIVE_SHA256}",
            ]
        )

        fixture_data = fixture.read_bytes()
        checks.that(fixture_data.endswith(b"\n"), "fixture final LF")
        checks.that(b"\r" not in fixture_data, "fixture LF-only encoding")
        fixture_text = fixture_data.decode("ascii")
        header, cases = parse_fixture(fixture)
        checks.equal(
            required(header, "corpus_state"),
            "READY",
            "fixture corpus state (the committed placeholder must fail closed)",
        )
        checks.that("PLACEHOLDER" not in fixture_text, "READY fixture contains no placeholder marker")
        checks.that("<" not in fixture_text and ">" not in fixture_text, "READY fixture contains no bracket token")
        validate_fixture_schema(header, cases)
        validate_provenance(header, checks)
        signing_data = signing_fixture.read_bytes()
        checks.equal(
            len(signing_data),
            parse_uint(required(header, "source_signing_fixture_bytes"), "source signing fixture bytes"),
            "source signing fixture byte count",
        )
        checks.equal(
            signing_data.count(b"\n"),
            parse_uint(required(header, "source_signing_fixture_lines"), "source signing fixture lines"),
            "source signing fixture LF count",
        )
        checks.that(signing_data.endswith(b"\n"), "source signing fixture final LF")
        checks.that(b"\r" not in signing_data, "source signing fixture LF-only encoding")
        checks.equal(
            sha256_bytes(signing_data),
            require_hash(header, "source_signing_fixture_sha256"),
            "source signing fixture hash",
        )
        signing_fields, signing_cases = parse_fixture(signing_fixture)
        checks.equal(signing_cases, [], "source signing fixture has no case sections")
        for name in (
            "role_a_transcript_ascii",
            "role_b_transcript_ascii",
            "role_a_transcript_sha256",
            "role_b_transcript_sha256",
            "role_a_route_private_scalar_hex",
            "role_b_route_private_scalar_hex",
        ):
            checks.equal(
                required(header, name),
                required(signing_fields, name),
                f"source signing fixture byte-tied {name}",
            )
        checks.equal(required(header, "core_release"), CORE_RELEASE, "fixture Core release")
        checks.equal(required(header, "core_archive"), CORE_ARCHIVE, "fixture Core archive")
        checks.equal(require_hash(header, "core_archive_sha256"), CORE_ARCHIVE_SHA256, "fixture Core archive hash")
        checks.equal(require_hash(header, "regtest_genesis_hash"), REGTEST_GENESIS, "fixture genesis")
        positive = [case for case in cases if required(case, "class") == "differential-accept"]
        negative = [case for case in cases if required(case, "class") == "differential-reject"]
        checks.equal(len(positive), 2, "two positive differential cases")
        checks.equal(len(negative), 3, "three negative Core controls")
        transcript.extend(
            [
                f"fixture_lineage={required(header, 'fixture_lineage')}",
                f"permanent_label={required(header, 'permanent_label')}",
                f"generation_procedure={required(header, 'generation_procedure')}",
                f"external_generation_transcript_sha256={require_hash(header, 'normalized_agreement_sha256')}",
                f"external_generation_transcript_len={required(header, 'normalized_agreement_bytes')}",
                f"external_generation_transcript_line_count={required(header, 'normalized_agreement_lines')}",
                "implementation_count=2",
                "agreement_result=byte-for-byte",
                f"screening_report_sha256={require_hash(header, 'screening_report_sha256')}",
                f"screening_repository_head={required(header, 'screening_repository_head')}",
                f"screening_tracked_file_count={required(header, 'screening_tracked_file_count')}",
                f"screening_tracked_byte_count={required(header, 'screening_tracked_byte_count')}",
                f"screened_public_key_count={required(header, 'screened_public_key_count')}",
                f"screened_signature_r_count={required(header, 'screened_signature_r_count')}",
                f"screening_expected_same_lineage_hits={required(header, 'screening_expected_same_lineage_hits')}",
                f"screening_same_lineage_matches={required(header, 'same_lineage_matches')}",
                "screening_collisions=0",
                "initial_destruction_result=complete",
                f"initial_deletion_completed_utc={required(header, 'initial_deletion_completed_utc')}",
                f"initial_destroyed_regular_file_count={required(header, 'initial_destroyed_regular_file_count')}",
                f"initial_destroyed_directory_count={required(header, 'initial_destroyed_directory_count')}",
                f"initial_destroyed_symlink_count={required(header, 'initial_destroyed_symlink_count')}",
                f"initial_destroyed_regular_file_byte_count={required(header, 'initial_destroyed_regular_file_byte_count')}",
                "initial_destroyed_root_absent=true",
                f"source_recovery={required(header, 'source_recovery')}",
                "recovered_source_hashes_match=true",
                f"reproduced_normalized_agreement_sha256={require_hash(header, 'reproduced_normalized_agreement_sha256')}",
                f"recovery_search_artifact_bytes={required(header, 'recovery_search_artifact_bytes')}",
                f"recovery_search_artifact_deletion_utc={required(header, 'recovery_search_artifact_deletion_utc')}",
                "recovery_search_artifact_absent=true",
                "destruction_result=complete",
                f"deletion_completed_utc={required(header, 'deletion_completed_utc')}",
                f"destroyed_regular_file_count={required(header, 'destroyed_regular_file_count')}",
                f"destroyed_directory_count={required(header, 'destroyed_directory_count')}",
                f"destroyed_symlink_count={required(header, 'destroyed_symlink_count')}",
                f"destroyed_regular_file_byte_count={required(header, 'destroyed_regular_file_byte_count')}",
                "destroyed_root_absent=true",
                "mainnet_funding_status=PERMANENTLY-NEVER-FUND",
                "regtest_coin_status=valueless-by-construction",
                f"wallet_id={GOLDEN_WALLET_ID.hex()}",
                "origin_fingerprint_a=2fae9711",
                "origin_fingerprint_b=72a14ab8",
                "review_schema=03",
                f"review_domain={REVIEW_DOMAIN.decode('ascii')}",
                f"fee_policy={FEE_POLICY.decode('ascii')}",
                "max_input_witness=220",
                "max_type08_record=223",
                "max_raw_transaction=27537",
                "min_finalized_psbt_shrink_per_input=121",
            ]
        )

        seed_block = fixture_bytes(header, "seed_block", checks)
        seed_coinbase = fixture_bytes(header, "seed_coinbase", checks)
        checks.equal(seed_block[80], 1, "seed block transaction count")
        checks.equal(seed_block[81:], seed_coinbase, "seed block sole transaction bytes")
        checks.equal(sha256d_display(seed_block[:80]), require_hash(header, "seed_block_hash"), "seed block hash")
        seed_block_time = int.from_bytes(seed_block[68:72], "little")
        checks.equal(seed_block_time, 1_800_000_000, "seed block header time")
        seed_coinbase_tx = parse_transaction(seed_coinbase)
        checks.equal(
            sha256d_display(serialize_transaction(seed_coinbase_tx, False)),
            require_hash(header, "seed_coinbase_txid"),
            "seed coinbase txid",
        )

        with tempfile.TemporaryDirectory(prefix="qk-v2-s3-core-") as temp_name:
            temp = Path(temp_name)
            extracted = temp / "release"
            extracted.mkdir()
            safe_extract(archive, extracted)
            bitcoind = extracted / "bitcoin-28.0" / "bin" / "bitcoind"
            cli = extracted / "bitcoin-28.0" / "bin" / "bitcoin-cli"
            checks.equal(sha256_file(bitcoind), BITCOIND_SHA256, "bitcoind SHA256")
            checks.equal(sha256_file(cli), BITCOIN_CLI_SHA256, "bitcoin-cli SHA256")
            daemon_version = first_line(bitcoind, "-version")
            cli_version = first_line(cli, "-version")
            checks.equal(daemon_version, BITCOIND_VERSION, "bitcoind version")
            checks.equal(cli_version, BITCOIN_CLI_VERSION, "bitcoin-cli version")
            transcript.extend(
                [
                    f"bitcoind_sha256={BITCOIND_SHA256}",
                    f"bitcoin_cli_sha256={BITCOIN_CLI_SHA256}",
                    f"bitcoind_version={daemon_version}",
                    f"bitcoin_cli_version={cli_version}",
                ]
            )

            datadir = temp / "node"
            datadir.mkdir()
            core = Core(bitcoind, cli, datadir, choose_port(), transcript)
            core.start()
            chain = core.rpc("getblockchaininfo")
            checks.equal(chain["chain"], "regtest", "Core chain")
            checks.equal(chain["blocks"], 0, "initial Core height")
            genesis = core.rpc("getblockhash", 0)
            checks.equal(genesis, REGTEST_GENESIS, "Core regtest genesis")
            transcript.extend(["chain=regtest", f"genesis_hash={REGTEST_GENESIS}", "height_before_seed=0"])

            checks.equal(core.rpc("setmocktime", seed_block_time), None, "setmocktime result")
            submitted = core.rpc("submitblock", seed_block.hex())
            checks.equal(submitted, None, "submitblock result")
            checks.equal(core.rpc("getblockcount"), 1, "height after seed")
            checks.equal(core.rpc("getblockhash", 1), require_hash(header, "seed_block_hash"), "active seed block")
            transcript.extend(
                [
                    f"seed_block_time={seed_block_time}",
                    f"seed_block_hash={required(header, 'seed_block_hash')}",
                    f"seed_coinbase_txid={required(header, 'seed_coinbase_txid')}",
                    "height_after_seed=1",
                ]
            )

            generated = core.rpc("generatetodescriptor", 100, "raw(51)")
            checks.equal(len(generated), 100, "maturity block count")
            checks.equal(core.rpc("getblockcount"), 101, "height after maturity")
            utxo = core.rpc(
                "gettxout",
                required(header, "seed_coinbase_txid"),
                parse_uint(required(header, "seed_vout"), "seed_vout", 0xFFFF_FFFF),
                True,
            )
            checks.that(isinstance(utxo, dict), "seed UTXO exists")
            checks.equal(utxo["confirmations"], 101, "seed UTXO confirmations")
            checks.equal(utxo["coinbase"], True, "seed UTXO coinbase flag")
            checks.equal(utxo["scriptPubKey"]["hex"], required(header, "seed_script_pubkey_hex"), "seed UTXO script")
            checks.equal(
                btc_to_sats(utxo["value"], "seed UTXO value"),
                parse_uint(required(header, "seed_amount_sats"), "seed_amount_sats", 21_000_000 * 100_000_000),
                "seed UTXO amount",
            )
            transcript.extend(
                [
                    "maturity_blocks_generated=100",
                    "height_after_maturity=101",
                    "seed_utxo_unspent=true",
                    "seed_utxo_coinbase=true",
                    "seed_utxo_confirmations=101",
                ]
            )

            positive_payloads: dict[str, PositivePayload] = {}
            for case_index, case in enumerate(positive):
                before = checks.total
                name = required(case, "case")
                signed = fixture_bytes(case, "signed_psbt", checks)
                finalized = fixture_bytes(case, "finalized_psbt", checks)
                raw_tx = fixture_bytes(case, "raw_tx", checks)
                stripped = fixture_bytes(case, "stripped_tx", checks)
                payload = validate_positive_payload(case, header, signed, finalized, raw_tx, stripped, checks)
                positive_payloads[name] = payload

                core_final = core.rpc("finalizepsbt", b64(signed), False)
                checks.equal(core_final["complete"], True, f"{name} Core final complete")
                core_psbt = base64.b64decode(core_final["psbt"], validate=True)
                core_psbt_sha256 = sha256_bytes(core_psbt)
                rule = required(case, "core_finalized_psbt_rule")
                if rule == "byte-equal":
                    checks.equal(name, "V2-S3-CORE-UNKNOWN-FREE", f"{name} byte-equal case identity")
                    checks.equal(required(case, "unknown_profile"), "none", f"{name} unknown profile")
                    checks.equal(core_psbt, finalized, f"{name} finalized PSBT byte equality")
                elif rule == "decoded-equal-order-delta":
                    checks.equal(name, "V2-S3-CORE-UNKNOWN-ORDER", f"{name} order-delta case identity")
                    checks.equal(required(case, "unknown_profile"), "numeric-255-256-order-delta", f"{name} unknown profile")
                    checks.equal(required(case, "quietkey_unknown_type_order"), "255,256", f"{name} declared QuietKey type order")
                    checks.equal(required(case, "core_unknown_type_order"), "256,255", f"{name} declared Core type order")
                    checks.that(core_psbt != finalized, f"{name} expected PSBT byte order delta")
                    qk_decode = core.rpc("decodepsbt", b64(finalized))
                    core_decode = core.rpc("decodepsbt", b64(core_psbt))
                    checks.equal(qk_decode, core_decode, f"{name} decoded PSBT equivalence")
                    qk_maps = payload.finalized_maps
                    core_maps = parse_psbt(core_psbt)
                    checks.equal(serialize_psbt(core_maps), core_psbt, f"{name} Core PSBT exact parse round trip")
                    checks.equal(map_multisets(qk_maps), map_multisets(core_maps), f"{name} PSBT record multisets")
                    qk_orders = locate_255_256_order(qk_maps)
                    core_orders = locate_255_256_order(core_maps)
                    checks.equal(
                        [entry[0] for entry in qk_orders],
                        [entry[0] for entry in core_orders],
                        f"{name} unknown map indices",
                    )
                    checks.equal(
                        [entry[1] for entry in qk_orders],
                        [[255, 256]] * len(qk_maps),
                        f"{name} QuietKey unknown order in every map",
                    )
                    checks.equal(
                        [entry[1] for entry in core_orders],
                        [[256, 255]] * len(core_maps),
                        f"{name} Core unknown order in every map",
                    )
                    checks.that(
                        all(
                            keys[0].startswith("fdff00")
                            and keys[1].startswith("fd0001")
                            for _, _, keys in qk_orders
                        ),
                        f"{name} QuietKey full keys carry minimal type encodings",
                    )
                    checks.that(
                        all(
                            keys[0].startswith("fd0001")
                            and keys[1].startswith("fdff00")
                            for _, _, keys in core_orders
                        ),
                        f"{name} Core full keys carry minimal type encodings",
                    )
                    checks.equal(
                        render_unknown_full_keys(qk_orders),
                        required(case, "quietkey_unknown_full_keys"),
                        f"{name} declared QuietKey complete keys",
                    )
                    checks.equal(
                        render_unknown_full_keys(core_orders),
                        required(case, "core_unknown_full_keys"),
                        f"{name} declared Core complete keys",
                    )
                    checks.equal(
                        serialize_psbt(swap_only_255_256(qk_maps)),
                        core_psbt,
                        f"{name} sole 255/256 record-order byte delta",
                    )
                else:
                    raise ValueError(f"{name}: closed finalized PSBT rule")

                extracted_result = core.rpc("finalizepsbt", b64(signed), True)
                checks.equal(extracted_result["complete"], True, f"{name} Core extraction complete")
                checks.equal(extracted_result["hex"], raw_tx.hex(), f"{name} raw transaction bytes")
                decoded_tx = core.rpc("decoderawtransaction", raw_tx.hex())
                checks.equal(decoded_tx["txid"], require_hash(case, "txid"), f"{name} Core txid")
                checks.equal(decoded_tx["hash"], require_hash(case, "wtxid"), f"{name} Core wtxid")
                validate_core_decoded(case, payload, decoded_tx, checks)
                acceptance = core.rpc("testmempoolaccept", [raw_tx.hex()], 0)
                checks.equal(len(acceptance), 1, f"{name} one acceptance result")
                result = acceptance[0]
                checks.equal(result.get("allowed"), True, f"{name} allowed")
                checks.equal(result["txid"], require_hash(case, "txid"), f"{name} accepted txid")
                checks.equal(result["wtxid"], require_hash(case, "wtxid"), f"{name} accepted wtxid")
                core_actual_vsize = result.get("vsize", 0)
                checks.that(core_actual_vsize > 0, f"{name} positive vsize")
                checks.that(isinstance(result.get("fees"), dict), f"{name} Core fee object")
                expected_fee = parse_uint(required(case, "fee_sats"), f"{name} fee_sats")
                checks.equal(btc_to_sats(result["fees"]["base"], f"{name} Core base fee"), expected_fee, f"{name} Core base fee")
                checks.equal(result["fees"]["effective-includes"], [require_hash(case, "wtxid")], f"{name} effective fee member")
                checks.that("reject-reason" not in result, f"{name} no reject reason")
                checks.that("package-error" not in result, f"{name} no package error")
                prefix = f"case_{case_index:03d}"
                transcript.extend(
                    [
                        f"{prefix}_name={name}",
                        f"{prefix}_schema_v3_identity=true",
                        f"{prefix}_policy_v2_identity=true",
                        f"{prefix}_review_s0_sha256={require_hash(case, 'review_s0_sha256')}",
                        f"{prefix}_canonical_review_sha256={require_hash(case, 'canonical_review_v3_sha256')}",
                        f"{prefix}_review_hash={require_hash(case, 'review_hash')}",
                        f"{prefix}_signed_psbt_sha256={require_hash(case, 'signed_psbt_sha256')}",
                        f"{prefix}_finalized_psbt_sha256={require_hash(case, 'finalized_psbt_sha256')}",
                        f"{prefix}_raw_tx_sha256={require_hash(case, 'raw_tx_sha256')}",
                        f"{prefix}_core_complete=true",
                        f"{prefix}_core_psbt_rule={rule}",
                        f"{prefix}_core_psbt_sha256={core_psbt_sha256}",
                    ]
                )
                if rule == "byte-equal":
                    transcript.append(f"{prefix}_core_psbt_equal=true")
                else:
                    transcript.extend(
                        [
                            f"{prefix}_core_psbt_equal=false",
                            f"{prefix}_decoded_equal=true",
                            f"{prefix}_record_multisets_equal=true",
                            f"{prefix}_unknown_map_count={len(payload.finalized_maps)}",
                            f"{prefix}_quietkey_unknown_type_order=255,256",
                            f"{prefix}_core_unknown_type_order=256,255",
                            f"{prefix}_quietkey_unknown_full_keys={required(case, 'quietkey_unknown_full_keys')}",
                            f"{prefix}_core_unknown_full_keys={required(case, 'core_unknown_full_keys')}",
                            f"{prefix}_sole_255_256_swap_equal=true",
                        ]
                    )
                transcript.extend(
                    [
                        f"{prefix}_raw_tx_equal=true",
                        f"{prefix}_txid={require_hash(case, 'txid')}",
                        f"{prefix}_wtxid={require_hash(case, 'wtxid')}",
                        f"{prefix}_decoded_fields_equal=true",
                        f"{prefix}_fee_sats={expected_fee}",
                        f"{prefix}_estimated_vsize={required(case, 'estimated_vsize')}",
                        f"{prefix}_core_actual_vsize={core_actual_vsize}",
                        f"{prefix}_witness_pubkey_positions={payload.selected_positions[0]},{payload.selected_positions[1]}",
                        f"{prefix}_testmempoolaccept_allowed=true",
                        f"{prefix}_assertions={checks.total - before}",
                        f"{prefix}_failures=0",
                    ]
                )

            committed_signatures = {
                record[2]
                for payload in positive_payloads.values()
                for record in payload.signed_maps[1]
                if record[0] == 2
            }
            committed_pubkeys = {
                key_data(record)
                for payload in positive_payloads.values()
                for record in payload.signed_maps[1]
                if record[0] in (2, 6)
            }
            committed_r_values = {
                strict_der_r(signature, "committed fixture signature") for signature in committed_signatures
            }
            checks.equal(
                len(committed_signatures),
                2,
                "two unique Core fixture signatures",
            )
            checks.equal(len(committed_r_values), len(committed_signatures), "one distinct r value per fixture signature")
            checks.equal(parse_uint(required(header, "signature_count"), "signature_count"), 4, "host plus Core fixture signature count")
            checks.that(
                parse_uint(required(header, "screened_signature_r_count"), "screened_signature_r_count")
                >= len(committed_r_values),
                "screening covers every Core signature r value",
            )
            checks.that(
                parse_uint(required(header, "screened_public_key_count"), "screened_public_key_count") >= len(committed_pubkeys),
                "provenance public-key screening covers all PSBT keys",
            )

            negative_raws: list[bytes] = []
            for offset, case in enumerate(negative):
                before = checks.total
                name = required(case, "case")
                checks.equal(required(case, "parent_case"), "V2-S3-CORE-UNKNOWN-FREE", f"{name} parent case")
                checks.equal(required(case, "core_rule"), "testmempoolaccept-allowed-false", f"{name} Core rule")
                parent = positive_payloads[required(case, "parent_case")]
                raw_tx = fixture_bytes(case, "raw_tx", checks)
                negative_raws.append(raw_tx)
                mutated_tx = parse_transaction(raw_tx)
                checks.equal(serialize_transaction(mutated_tx, True), raw_tx, f"{name} canonical raw mutation")
                checks.equal(raw_tx, derive_negative(case, parent, checks), f"{name} exact one-change derivation")
                mutated_stripped = serialize_transaction(mutated_tx, False)
                if name == "V2-S3-CORE-MUTATED-BASE":
                    checks.that(mutated_stripped != parent.stripped_tx, f"{name} base transaction changed")
                    checks.equal(mutated_tx.version, parent.tx.version, f"{name} version frozen")
                    checks.equal(mutated_tx.inputs, parent.tx.inputs, f"{name} inputs and witness frozen")
                    checks.equal(mutated_tx.locktime, parent.tx.locktime, f"{name} locktime frozen")
                    checks.equal(len(mutated_tx.outputs), len(parent.tx.outputs), f"{name} output count frozen")
                    checks.equal(
                        mutated_tx.outputs[0].amount_sats,
                        parent.tx.outputs[0].amount_sats + 1,
                        f"{name} output amount exact one-satoshi change",
                    )
                    checks.equal(
                        mutated_tx.outputs[0].script_pubkey,
                        parent.tx.outputs[0].script_pubkey,
                        f"{name} output script frozen",
                    )
                    checks.that(
                        require_hash(case, "txid") != sha256d_display(parent.stripped_tx),
                        f"{name} txid changed",
                    )
                    base_equal = "false"
                else:
                    checks.equal(mutated_stripped, parent.stripped_tx, f"{name} base transaction frozen")
                    checks.equal(
                        require_hash(case, "txid"),
                        sha256d_display(parent.stripped_tx),
                        f"{name} parent txid retained",
                    )
                    base_equal = "true"
                checks.equal(sha256d_display(mutated_stripped), require_hash(case, "txid"), f"{name} local txid")
                checks.equal(sha256d_display(raw_tx), require_hash(case, "wtxid"), f"{name} local wtxid")
                rejection = core.rpc("testmempoolaccept", [raw_tx.hex()], 0)
                checks.equal(len(rejection), 1, f"{name} one rejection result")
                result = rejection[0]
                checks.equal(result.get("allowed"), False, f"{name} rejected")
                checks.equal(result["txid"], require_hash(case, "txid"), f"{name} rejected txid")
                checks.equal(result["wtxid"], require_hash(case, "wtxid"), f"{name} rejected wtxid")
                checks.that(bool(result.get("reject-reason")), f"{name} nonempty reject reason")
                checks.that("package-error" not in result, f"{name} no package error")
                prefix = f"case_{len(positive) + offset:03d}"
                transcript.extend(
                    [
                        f"{prefix}_name={name}",
                        f"{prefix}_parent=V2-S3-CORE-UNKNOWN-FREE",
                        f"{prefix}_mutation={required(case, 'mutation')}",
                        f"{prefix}_exact_mutation_derivation=true",
                        f"{prefix}_base_transaction_equal={base_equal}",
                        f"{prefix}_raw_tx_sha256={require_hash(case, 'raw_tx_sha256')}",
                        f"{prefix}_txid={require_hash(case, 'txid')}",
                        f"{prefix}_wtxid={require_hash(case, 'wtxid')}",
                        f"{prefix}_testmempoolaccept_allowed=false",
                        f"{prefix}_reject_reason={compact_json(result['reject-reason'])}",
                        f"{prefix}_assertions={checks.total - before}",
                        f"{prefix}_failures=0",
                    ]
                )
            checks.equal(len(set(negative_raws)), 3, "three distinct negative raw transactions")

            stop_code = core.stop()
            transcript.extend(["daemon_stop_requested=true", f"daemon_exit_code={stop_code}"])
            checks.equal(stop_code, 0, "bitcoind clean exit")
            transcript.extend(
                [
                    f"positive_cases={len(positive)}",
                    f"negative_core_controls={len(negative)}",
                    f"rpc_calls={core.rpc_index}",
                    f"assertions_total={checks.total}",
                    "assertions_failed=0",
                    "result=PASS",
                ]
            )
            core = None
    except Exception as exc:
        error = type(exc).__name__
        error_detail = f"{error}: {exc}"
        transcript.extend(
            [
                f"failure_type={error}",
                f"assertions_total={checks.total}",
                "assertions_failed=1",
                "result=FAIL",
            ]
        )
    finally:
        if core is not None:
            try:
                code = core.stop()
                transcript.extend(["daemon_stop_requested=true", f"daemon_exit_code={code}"])
            except Exception as stop_exc:
                transcript.append(f"daemon_stop_error_type={type(stop_exc).__name__}")
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        with transcript_path.open("x", encoding="ascii", newline="\n") as out:
            out.write("\n".join(transcript) + "\n")

    if error is not None:
        print(error_detail, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
