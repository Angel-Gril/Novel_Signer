"""Validate the fresh outer graph report and its padding-only residual."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SCHEMA = "vm9-outer-graph-fresh-differential-v1"
LIBRARY_SHA256 = "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c"
LIBC_SHA256 = "d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db"
EXPECTED_PROFILES = {"absent", "sdk_30"}
EXPECTED_BASES = {"0x122c0000", "0x775c205000"}
EXPECTED_MISMATCHES = {
    "0x22", "0x23", "0x29", "0x2a", "0x2b", "0x3a", "0x3b",
    "0x40", "0x41", "0x42", "0x43", "0x50", "0x54", "0x58",
    "0x59", "0x5a", "0x5b", "0x5c", "0x5d", "0x5e", "0x5f",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify(report: dict) -> dict:
    require(report.get("schema") == SCHEMA, "schema")
    require(report.get("sample_sha256") == LIBRARY_SHA256, "library hash")
    require(report.get("libc_sha256") == LIBC_SHA256, "libc hash")
    cases = report.get("cases")
    require(isinstance(cases, list) and len(cases) == 4, "case count")
    require({case.get("image_base") for case in cases} == EXPECTED_BASES, "image bases")
    require({case.get("property_profile") for case in cases} == EXPECTED_PROFILES, "profiles")
    for case in cases:
        require(case.get("returned_core_graph_equal") is True, "core graph")
        require(case.get("default_logger_record_semantics_equal") is True, "record semantics")
        require(case.get("complete_native_outer_state_equal") is False, "state claim")
        mismatches = case.get("live_allocation_mismatches")
        require(isinstance(mismatches, list) and len(mismatches) == 1, "mismatch count")
        row = mismatches[0]
        require(row.get("allocation_index") == 308 and row.get("size") == 96, "allocation")
        require(set(row.get("mismatch_offsets", [])) == EXPECTED_MISMATCHES, "offsets")
        require(row.get("unused_short_string_padding_only") is True, "padding attribution")
        require(case.get("live_mismatch_semantic_bytes_equal") is True, "semantic residual")
    return {
        "schema": SCHEMA,
        "controls": len(cases),
        "core_graph_equal": all(case["returned_core_graph_equal"] for case in cases),
        "allocation_308_padding_only": all(
            case["live_mismatch_semantic_bytes_equal"] for case in cases),
        "complete_native_outer_state_equal": False,
        "complete_standalone_signer_verified": False,
        "whole_request_native_python_differential_verified": False,
        "online_header_acceptance_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    print(json.dumps(verify(report), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
