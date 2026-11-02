"""Verify digest-only FrameSign preimage-to-signvalue observations."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from verify_vm9_framesign_result_buffer_provenance_20261103 import (
    EXPECTED_INPUT, HEX_256, LIBRARY_SHA256, check_elf, parse_log, require, sha256,
    trials, verify as verify_buffers,
)

NAME = "vm9_framesign_sha256_edge_20261103"
SOURCE = "result_sha256_components_probe"
BUFFER = "vm9_framesign_result_buffer_provenance_20261103.json"
DIGEST = "vm9_sha256_digest_reference_fresh_20261103.json"
STATIC = {
    "0x284ce8": ("mov", "w1, #1"),
    "0x284cec": ("ldur", "x0, [x29, #-0x48]"),
    "0x284cf4": ("bl", "#0x258a48"),
    "0x284d38": ("bl", "#0x2481fc"),
    "0x258a80": ("bl", "#0x245630"),
}
CLAIMS = {
    "independent_runs": 2, "calls": 8, "input_length": 252,
    "signvalue_sha256_hex_relation_verified": True,
    "baseline_abab_preserved": True, "preimage_equals_signinfo": False,
    "four_part_direct_concatenation_matches": False,
    "preimage_composition_identified": False,
    "signinfo_generation_identified": False, "alternation_cause_identified": False,
    "android_relation_verified": False, "complete_standalone_signer_verified": False,
    "online_header_acceptance_verified": False,
}


def parse_edges(path: Path) -> list[dict]:
    result = []
    prefix = "[HookMain] FRAME_BUFFER_SHA256_EDGE "
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line.startswith(prefix):
            continue
        row = {}
        for token in line[len(prefix):].split():
            key, value = token.split("=", 1)
            require(key not in row, "duplicate edge attribute")
            row[key] = value == "true" if value in ("true", "false") else int(value) if value.isdecimal() else value
        result.append(row)
    return result


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None) -> dict:
    require(set(data) == {"schema", "evidence_date", "input", "buffer_provenance_evidence",
            "digest_component_evidence", "probe", "runs", "static_analysis", "conclusions",
            "raw_values_retained", "preimage_digest_retained", "interpretation"}, "evidence keys")
    require(data["schema"] == "vm9-framesign-sha256-edge-20261103-v1", "schema")
    require(data["evidence_date"] == "2026-11-03" and data["input"] == EXPECTED_INPUT, "date/input")
    require(data["raw_values_retained"] is False and data["preimage_digest_retained"] is False, "private preimage/signature retained")
    require(data["conclusions"] == CLAIMS, "unsupported claim")
    require(data["buffer_provenance_evidence"] == "evidence/" + BUFFER and
            data["digest_component_evidence"] == "evidence/" + DIGEST, "parent links")
    parent = json.loads((evidence_dir / BUFFER).read_text())
    verify_buffers(parent, evidence_dir, elf=elf)
    baseline_rows = parent["runs"][0]["repeat_trials"]
    expected = trials([{"ordinal": r["ordinal"], "fields": r["fields"]} for r in baseline_rows], "parent")
    component = json.loads((evidence_dir / DIGEST).read_text())
    require(component["schema"] == "vm9-sha256-digest-reference-fresh-20261103-v1" and
            component["library_sha256"] == LIBRARY_SHA256 and component["sha256_entry_offset"] == "0x258a48" and
            component["sha256_differential_cases"] == 62 and component["differential_cases"] == 204 and
            component["complete_standalone_signer_verified"] is False, "digest component identity/scope")
    probe = data["probe"]
    require(set(probe) == {"source_relative_path", "source_sha256", "entry_class_sha256",
            "read_only_guest_observation", "synthetic_jni_provider_used", "fresh_rootfs_per_run",
            "setup_rounds_per_run", "restore_enabled", "preimage_source"}, "probe keys")
    require(probe["source_relative_path"] == SOURCE + "/HookMain.java", "source owner")
    for key in ("source_sha256", "entry_class_sha256"):
        require(isinstance(probe[key], str) and HEX_256.fullmatch(probe[key]), "build digest")
    for key in ("read_only_guest_observation", "synthetic_jni_provider_used", "fresh_rootfs_per_run"):
        require(probe[key] is True, key)
    require(probe["setup_rounds_per_run"] == 1 and probe["restore_enabled"] is False and
            probe["preimage_source"] == "caller_frame_minus_0x48_string_object_at_signvalue_constructor_store", "probe scope")
    require(len(data["runs"]) == 2, "independent run count")
    for index, run in enumerate(data["runs"], 1):
        require(set(run) == {"local_run_name", "source_sha256", "entry_class_sha256", "native_library_sha256",
                "process_exit_code", "sanitized_log_sha256", "repeat_trials", "sha256_edges"}, "run keys")
        require(run["local_run_name"] == SOURCE + f"/run{index}" and run["process_exit_code"] == 0, "run identity/terminal")
        require(run["native_library_sha256"] == LIBRARY_SHA256 and HEX_256.fullmatch(run["sanitized_log_sha256"]), "run digests")
        for key in ("source_sha256", "entry_class_sha256"):
            require(run[key] == probe[key], "probe build mismatch")
        require(trials(run["repeat_trials"], "edge control") == expected, "changed control fields")
        require(run["sha256_edges"] == [{"ordinal": ordinal, "field": "signvalue",
            "constructor_return": "metasec+0x284d3c", "component_order": "none", "input_length": 252,
            "sha256_hex_matches": True, "input_equals_signinfo": False, "signinfo_source_observed": True,
            "output_length": 64, "output_sha256": expected[ordinal]["signvalue"]["sha256"]}
            for ordinal in range(1, 5)], "preimage/hash relation or unsupported composition")
        if probe_dir:
            log = probe_dir / run["local_run_name"] / "sanitized.log"
            require(sha256(log) == run["sanitized_log_sha256"], "local log digest")
            require(parse_edges(log) == run["sha256_edges"], "local edge mismatch")
            require(parse_log(log) == baseline_rows, "local constructor/conversion control mismatch")
            meta = json.loads(log.with_name("metadata.json").read_text())
            require(meta["read_only_guest_probe"] is True and meta["raw_values_retained"] is False and
                    meta["process_exit_code"] == 0, "local run state")
            for key in ("source_sha256", "entry_class_sha256", "native_library_sha256"):
                require(meta[key] == run[key], "local metadata mismatch")
    if probe_dir:
        require(sha256(probe_dir / probe["source_relative_path"]) == probe["source_sha256"] and
                sha256(probe_dir / SOURCE / "classes/HookMain.class") == probe["entry_class_sha256"], "local probe identity")
    analysis = data["static_analysis"]
    require(set(analysis) == {"native_library_sha256", "instructions"} and analysis["native_library_sha256"] == LIBRARY_SHA256,
            "static identity")
    require([r["image_offset"] for r in analysis["instructions"]] == list(STATIC), "static sites")
    for row in analysis["instructions"]:
        require(set(row) == {"image_offset", "file_offset", "bytes_hex", "mnemonic", "operands"} and
                (row["mnemonic"], row["operands"]) == STATIC[row["image_offset"]], "static contract")
    if elf:
        check_elf(elf, analysis)
    return {"sha256_edges_verified": 8, "input_length": 252, "baseline_abab_preserved": True,
            "local_logs_verified": probe_dir is not None, "elf_bytes_verified": elf is not None,
            "preimage_composition_identified": False, "standalone_signer_verified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=Path(__file__).resolve().parents[1] / "evidence" / (NAME + ".json"))
    parser.add_argument("--probe-dir", type=Path)
    parser.add_argument("--elf", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.evidence.read_text()), args.evidence.parent, args.probe_dir, args.elf), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
