"""Verify redacted native FrameSign JSON-source and length-minus-ten observations."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from verify_vm9_framesign_sha256_edge_20261103 import (
    EXPECTED_INPUT, HEX_256, LIBRARY_SHA256, check_elf, parse_edges, parse_log,
    require, sha256, trials, verify as verify_edge,
)

NAME = "vm9_framesign_preimage_composition_20261103"
SOURCE = "preimage_composition_probe"
PARENT = "vm9_framesign_sha256_edge_20261103.json"
BUFFER = "vm9_framesign_result_buffer_provenance_20261103.json"
STATIC = {
    "0x284268": ("ldur", "x8, [x29, #-0x50]"),
    "0x28426c": ("ldr", "x8, [x8]"),
    "0x284270": ("ldr", "x1, [x8, #0x10]"),
    "0x28427c": ("ldr", "w8, [x8, #0xc]"),
    "0x284284": ("sub", "w2, w8, #0xa"),
    "0x284288": ("bl", "#0x2481fc"),
    "0x284cec": ("ldur", "x0, [x29, #-0x48]"),
    "0x284cf4": ("bl", "#0x258a48"),
    "0x258a74": ("ldr", "x8, [x0, #0x10]"),
    "0x258a78": ("ldr", "w1, [x0, #0xc]"),
    "0x258a80": ("bl", "#0x245630"),
}
CLAIMS = {
    "independent_runs": 2, "calls": 8, "source_length": 262,
    "hash_input_length": 252, "native_length_subtraction": 10,
    "full_source_template_verified_for_fixed_profile": True,
    "source_minus_ten_matches_hash_input": True,
    "sha256_hex_matches_signvalue": True,
    "full_json_hash_matches_signvalue": False,
    "hash_input_is_complete_json": False,
    "baseline_abab_preserved": True,
    "general_input_composition_verified": False,
    "signinfo_generation_identified": False,
    "alternation_cause_identified": False,
    "android_relation_verified": False,
    "complete_standalone_signer_verified": False,
    "online_header_acceptance_verified": False,
}
TEMPLATE = '{"frametype":"0","lid":"<lid>","signinfo":"<signinfo>","signversion":"1.0"}'
VARIANTS = ("field_order", "whitespace", "numeric_frametype", "numeric_lid",
            "short_version_key", "signinfo_byte", "ignored_version_tail")
EVENTS = ("PREIMAGE_COPY", "PREIMAGE_SOURCE_MEMBER", "PREIMAGE_STORAGE",
          "PREIMAGE_STORAGE_PARSE", "PREIMAGE_LINK", "PREIMAGE_VARIANT", "PREIMAGE_STORAGE_TEMPLATE")


def parse_observations(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        prefix = "[HookMain] FRAME_BUFFER_"
        if not line.startswith(prefix):
            continue
        event, _, attributes = line[len(prefix):].partition(" ")
        if event not in EVENTS:
            continue
        row = {"event": event}
        for token in attributes.split():
            key, value = token.split("=", 1)
            require(key not in row, "duplicate composition attribute")
            row[key] = (value == "true" if value in ("true", "false") else
                        int(value) if value.isdecimal() else value)
        rows.append(row)
    return rows


def expected_observations() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        rows.append({"event": "PREIMAGE_COPY", "ordinal": ordinal,
                     "constructor": "metasec+0x248238", "caller": "metasec+0x28428c",
                     "source_length": 262, "source_cstring_length": 262, "copy_length": 252,
                     "source_slot_pointer_equal": True, "destination_slot_object_equal": True})
        for key, length, equal in (("frametype", 1, "frametype"), ("lid", 10, "lid"),
                                   ("signinfo", 192, "signinfo"), ("signversion", 3, "version")):
            rows.append({"event": "PREIMAGE_SOURCE_MEMBER", "ordinal": ordinal,
                         "key": key, "type": "String", "scalar_length": length,
                         **{"equals_" + name: name == equal
                            for name in ("frametype", "lid", "signinfo", "version")}})
        rows.extend([
            {"event": "PREIMAGE_STORAGE", "ordinal": ordinal, "logical_length": 252,
             "cstring_length": 252, "logical_equals_cstring": True},
            {"event": "PREIMAGE_STORAGE_PARSE", "ordinal": ordinal, "type": "parse_rejected"},
            {"event": "PREIMAGE_LINK", "ordinal": ordinal, "source_observed": True,
             "source_length": 262, "source_equals_candidate": True, "minus_ten_equals_hash_input": True},
        ])
        for variant in VARIANTS:
            rows.append({"event": "PREIMAGE_VARIANT", "ordinal": ordinal, "change": variant,
                         "prefix_bytes_equal": variant == "ignored_version_tail",
                         "sha256_hex_equal": variant == "ignored_version_tail"})
        rows.append({"event": "PREIMAGE_STORAGE_TEMPLATE", "ordinal": ordinal,
                     "candidate_length": 262, "prefix_bytes_equal": True, "storage_bytes_equal": False,
                     "prefix_sha256_hex_equal": True, "full_sha256_hex_equal": False})
    return rows


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None) -> dict:
    require(set(data) == {"schema", "evidence_date", "input", "parent_evidence", "source_template",
                         "probe", "runs", "static_analysis", "conclusions", "raw_values_retained",
                         "preimage_digest_retained", "interpretation"}, "evidence keys")
    require(data["schema"] == "vm9-framesign-preimage-composition-20261103-v1", "schema")
    require(data["evidence_date"] == "2026-11-03" and data["input"] == EXPECTED_INPUT, "date/input")
    require(data["raw_values_retained"] is False and data["preimage_digest_retained"] is False,
            "raw input/signature retained")
    require(data["conclusions"] == CLAIMS and data["source_template"] == TEMPLATE, "unsupported composition claim")
    require(data["parent_evidence"] == "evidence/" + PARENT, "parent link")
    parent = json.loads((evidence_dir / PARENT).read_text())
    verify_edge(parent, evidence_dir, elf=elf)
    baseline_rows = json.loads((evidence_dir / BUFFER).read_text())["runs"][0]["repeat_trials"]
    baseline = trials([{"ordinal": r["ordinal"], "fields": r["fields"]} for r in baseline_rows], "baseline")
    probe = data["probe"]
    require(set(probe) == {"source_relative_path", "source_sha256", "entry_class_sha256", "runner_sha256",
                          "read_only_guest_observation", "synthetic_jni_provider_used", "fresh_rootfs_per_run",
                          "setup_rounds_per_run", "restore_enabled"}, "probe keys")
    require(probe["source_relative_path"] == SOURCE + "/HookMain.java", "probe path")
    for key in ("source_sha256", "entry_class_sha256", "runner_sha256"):
        require(isinstance(probe[key], str) and HEX_256.fullmatch(probe[key]), "probe digest")
    for key in ("read_only_guest_observation", "synthetic_jni_provider_used", "fresh_rootfs_per_run"):
        require(probe[key] is True, "probe scope")
    require(probe["setup_rounds_per_run"] == 1 and probe["restore_enabled"] is False, "setup/restore")
    require(isinstance(data["runs"], list) and len(data["runs"]) == 2, "independent run count")
    for index, run in enumerate(data["runs"], 1):
        require(set(run) == {"local_run_name", "source_sha256", "entry_class_sha256", "native_library_sha256",
                             "sanitized_log_sha256", "process_exit_code", "repeat_trials", "sha256_edges",
                             "composition_observations"}, "run keys")
        require(run["local_run_name"] == SOURCE + f"/run{index}" and run["process_exit_code"] == 0, "run terminal")
        require(run["native_library_sha256"] == LIBRARY_SHA256, "run ELF identity")
        require(isinstance(run["sanitized_log_sha256"], str) and HEX_256.fullmatch(run["sanitized_log_sha256"]), "log digest")
        for key in ("source_sha256", "entry_class_sha256"):
            require(run[key] == probe[key], "probe identity")
        require(trials(run["repeat_trials"], "composition") == baseline, "changed control output")
        require(run["sha256_edges"] == parent["runs"][index - 1]["sha256_edges"], "SHA-256 edge mismatch")
        require(run["composition_observations"] == expected_observations(), "composition/source/variant mismatch")
        if probe_dir:
            log = probe_dir / run["local_run_name"] / "sanitized.log"
            require(sha256(log) == run["sanitized_log_sha256"], "local log identity")
            require(parse_log(log) == baseline_rows, "native pipeline baseline mismatch")
            require(parse_edges(log) == run["sha256_edges"], "local SHA-256 edges")
            require(parse_observations(log) == run["composition_observations"], "local composition observations")
            meta = json.loads(log.with_name("metadata.json").read_text())
            require(meta["process_exit_code"] == 0 and meta["read_only_guest_probe"] is True
                    and meta["raw_values_retained"] is False, "local probe scope/terminal")
            for key in ("source_sha256", "entry_class_sha256", "native_library_sha256"):
                require(meta[key] == run[key], "local build mismatch")
    if probe_dir:
        for relative, key in (("HookMain.java", "source_sha256"), ("classes/HookMain.class", "entry_class_sha256"),
                              ("run_buffer_probe.py", "runner_sha256")):
            require(sha256(probe_dir / SOURCE / relative) == probe[key], "local probe identity")
    static = data["static_analysis"]
    require(set(static) == {"native_library_sha256", "instructions"}
            and static["native_library_sha256"] == LIBRARY_SHA256, "static identity")
    require([r["image_offset"] for r in static["instructions"]] == list(STATIC), "static sites")
    for row in static["instructions"]:
        require(set(row) == {"image_offset", "file_offset", "bytes_hex", "mnemonic", "operands"}
                and (row["mnemonic"], row["operands"]) == STATIC[row["image_offset"]], "static contract")
    if elf:
        check_elf(elf, static)
    return {"calls_verified": 8, "variant_comparisons_verified": 56, "source_length": 262,
            "hash_input_length": 252, "native_subtraction": 10, "baseline_abab_preserved": True,
            "local_logs_verified": probe_dir is not None, "elf_bytes_verified": elf is not None,
            "general_input_composition_verified": False, "standalone_signer_verified": False}


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
