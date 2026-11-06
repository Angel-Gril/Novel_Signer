"""Validate the fresh native dispatch-table provenance rerun."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA = "vm9-dispatch-table-encoding-fresh-20261026-v1"
LIBRARY_SHA256 = "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c"
LIBC_SHA256 = "d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db"
BASES = {"0x122c0000", "0x775c205000"}
TABLE_COUNTS = (64, 64, 37, 37, 32)
TABLE_OFFSETS = ("0x34cf68", "0x34d168", "0x34d368", "0x34d490", "0x34ce68")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify(report: dict[str, Any]) -> dict[str, Any]:
    require(report.get("schema") == SCHEMA, "schema")
    require(report.get("sample_sha256") == LIBRARY_SHA256, "library hash")
    require(report.get("matching_libc_sha256") == LIBC_SHA256, "libc hash")
    require(report.get("evidence_date") == "2026-10-26", "source evidence date")
    require(report.get("observation_only") is True, "observation boundary")
    require(report.get("native_snapshot_input") is False, "native snapshot input")
    require(report.get("dispatch_table_bytes_source") ==
            "pinned ELF PT_LOAD and R_AARCH64_RELATIVE relocations", "table source")
    require(report.get("encoded_dispatch_pointer_provenance_closed") is True,
            "pointer provenance")
    require(report.get("external_dispatch_mapping_required_for_this_continuation") is False,
            "external mapping")
    require(report.get("synthetic_dispatch_table_used") is False and
            report.get("synthetic_callback_vtable_used") is False, "synthetic dispatch")
    for key in ("whole_request_native_differential_verified",
                "fresh_standalone_signer_verified", "online_header_acceptance_verified"):
        require(report.get(key) is False, f"{key} overclaim")
    static = report.get("static")
    require(static.get("handler_bias") == "0x33dc5", "handler bias")
    require(static.get("decoded_entry_count") == 234, "entry count")
    tables = static.get("tables")
    require(isinstance(tables, list) and len(tables) == 5, "table count")
    require(tuple(row.get("decoded_table_offset") for row in tables) == TABLE_OFFSETS,
            "table offsets")
    require(tuple(row.get("entry_count") for row in tables) == TABLE_COUNTS,
            "table entry counts")
    cases = report.get("cases")
    require(isinstance(cases, list) and len(cases) == 4, "case count")
    require({row.get("image_base") for row in cases} == BASES, "image bases")
    for row in cases:
        require(row.get("dispatch_load_count") == 1191, "dispatch loads")
        require(row.get("all_loads_match_fresh_ELF_relocations") is True,
                "relocation match")
        require(row.get("all_decoded_branches_observed") is True, "branch observation")
        require(row.get("relocation_slot_writes") == [], "slot writes")
        require(row.get("external_canary_pages_mapped") in (True, False), "canary state")
        continuation = row.get("continuation", {})
        require(continuation.get("request_reached_oracle_stop") is True and
                continuation.get("unmapped_event_count") == 0, "continuation")
    controls = report.get("canary_absence_controls")
    require(isinstance(controls, list) and len(controls) == 2 and
            all(all(row.get(key) is True for key in
                    ("dispatch_events_equal", "continuation_results_equal",
                     "all_noncanary_physical_pages_equal")) for row in controls),
            "canary controls")
    selector_controls = report.get("selector_boundary_controls")
    require(isinstance(selector_controls, list) and len(selector_controls) == 2 and
            all(row.get("native_selector_controls") == 234 for row in selector_controls),
            "selector controls")
    require(report.get("native_selector_control_count") == 468, "selector total")
    return {
        "schema": SCHEMA,
        "fresh_cases": len(cases),
        "dispatch_loads_per_case": 1191,
        "native_selector_controls": 468,
        "encoded_dispatch_pointer_provenance_closed": True,
        "external_dispatch_mapping_required_for_this_continuation": False,
        "whole_request_native_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("report", type=Path,
                        nargs="?", default=root / "evidence" /
                        "vm9_dispatch_table_encoding_fresh_20261106.json")
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    print(json.dumps(verify(report), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
