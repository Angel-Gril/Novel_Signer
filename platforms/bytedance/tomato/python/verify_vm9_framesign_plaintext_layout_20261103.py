"""Verify redacted FrameSign plaintext layout and the pre-block difference boundary."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from verify_vm9_framesign_signinfo_aes_20261103 import (
    BUFFER, EXPECTED_INPUT, HEX_256, LIBRARY_SHA256, check_elf, expected_aes,
    parse_aes, parse_edges, parse_log, parse_observations, require, sha256,
    verify as verify_aes,
)

NAME = "vm9_framesign_plaintext_layout_20261103"
SOURCE = "plaintext_layout_probe"
PARENT = "vm9_framesign_signinfo_aes_20261103.json"
STATIC = {
    "0x171c18": ("strb", "w10, [x11, x9]"),
    "0x26852c": ("ldp", "x8, x0, [x0]"),
    "0x268530": ("ldp", "x1, x2, [x19, #0x10]"),
    "0x268534": ("blr", "x8"),
    "0x268538": ("str", "x0, [x19, #0x20]"),
    "0x268584": ("ldp", "x8, x1, [x0, #8]"),
    "0x268588": ("ldr", "w2, [x0, #0x18]"),
    "0x26858c": ("ldr", "x3, [x0]"),
    "0x268590": ("mov", "x0, x8"),
    "0x268594": ("br", "x3"),
}
WRITERS = (
    ("a0e7c", 7), ("a0e80", 3), ("a0e84", 6), ("a0e88", 5),
    ("a0e8c", 4), ("a0e94", 2), ("a0e9c", 1), ("a0ea4", 0),
)
CLAIMS = {
    "independent_runs": 2, "calls": 8, "plaintext_length": 93,
    "layout_lengths": [1, 88, 4], "overlapping_copy_source_offset": 0,
    "overlapping_copy_destination_offset": 1, "overlapping_copy_length": 88,
    "suffix_destination_offset": 89, "suffix_length": 4,
    "pre_block_difference_spans_within_run": "0:1",
    "final_plaintext_difference_spans_within_run": "0:89",
    "pre_block_and_final_plaintext_abab_within_run": True,
    "observed_buffer_vm_byte_writes_per_call": 176,
    "observed_vm_bytecode_store_sites": 9,
    "complete_baseline_and_aes_controls_preserved": True,
    "pre_block_first_byte_origin_identified": False,
    "block_transform_algorithm_identified": False,
    "suffix_generation_identified": False,
    "alternation_root_cause_identified": False,
    "general_input_equivalence_verified": False,
    "android_equivalence_verified": False,
    "complete_standalone_signer_verified": False,
    "online_header_acceptance_verified": False,
}
EVENTS = {
    "PLAIN_CONSTRUCTOR", "PLAIN_SOURCE_WRITER", "PLAIN_AES_LINK", "PLAIN_COPY",
    "PLAIN_COPY_LINK", "COPY_SOURCE", "COPY_SOURCE_LINK", "FIRST_BYTE_COMPARE",
    "TRANSFORM", "TRANSFORM_WRITER", "TRANSFORM_COMPARE", "LAYOUT_MIDDLE",
    "LAYOUT_ORDER", "LAYOUT_COMPARE",
}
INDEXED = {"PLAIN_COPY", "PLAIN_COPY_LINK", "COPY_SOURCE", "COPY_SOURCE_LINK"}


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def ordered(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=canonical)


def parse_layout(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        prefix = "[HookMain] FRAME_BUFFER_"
        if not line.startswith(prefix):
            continue
        event, _, attributes = line[len(prefix):].partition(" ")
        require(event not in ("ERROR", "CONSTRUCTOR_WRITE_ERROR"), "probe observation error")
        if event not in EVENTS:
            continue
        row = {"event": event}
        for token in attributes.split():
            key, value = token.split("=", 1)
            require(key not in row, "duplicate layout attribute")
            row[key] = (value == "true" if value in ("true", "false") else
                        int(value) if value.lstrip("-").isdecimal() else value)
        if event in INDEXED and row.get("index") not in (24, 25):
            continue
        rows.append(row)
    return ordered(rows)


def expected_layout() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        def add(event, **values):
            rows.append({"event": event, "ordinal": ordinal, **values})

        add("PLAIN_CONSTRUCTOR", wrapper="metasec+0x268584", target="metasec+0x2481fc", length=93)
        for writer, caller, count in (("171c18", "outside_modules", 1),
                                      ("276e18", "metasec+0x268538", 4),
                                      ("276e38", "metasec+0x268538", 88)):
            add("PLAIN_SOURCE_WRITER", writer="metasec+0x" + writer, caller=caller,
                writer_ordinal=ordinal, covered_bytes=count, dropped=0)
        add("PLAIN_AES_LINK", same_constructor_object=True, constructor_bytes_equal=True,
            constructor_length=93, copy_count=25, pending_copy=False)
        for index, length, offset, writer in ((24, 88, 1, "171c18"), (25, 4, 89, "171268")):
            add("COPY_SOURCE", index=index, length=length, source_equals_destination=False,
                source_writers=f"metasec+0x{writer}/outside_modules/{ordinal}:{length}", dropped=0)
            add("PLAIN_COPY", index=index, wrapper="metasec+0x268524", target="metasec+0x276e00",
                length=length, kind="copy", fill_zero=False, destination_matches_expected=True)
            add("COPY_SOURCE_LINK", index=index, source_inside_constructor_source=index == 24,
                source_relative=0 if index == 24 else "none", source_current_equals_snapshot=index == 25)
            add("PLAIN_COPY_LINK", index=index, destination_inside_constructor_source=True,
                destination_relative=offset, length=length, expected_equals_final_slice=True, returned=True)
        add("TRANSFORM", length=88, source_equals_buffer=True, before_length=88, changed_bytes=88,
            xor_period_1=False, xor_period_2=False, xor_period_4=False, xor_period_8=False)
        for index, (bcp, offset) in enumerate(WRITERS):
            site = f"metasec+0x171c18/metasec+0x{bcp}"
            add("TRANSFORM_WRITER", site=site, byte_writes=11, distinct_offsets=11,
                min_offset=offset, max_offset=offset + 80)
            add("LAYOUT_ORDER", site=site, first_sequence=9 + index, last_sequence=169 + index, byte_writes=11)
        site = "metasec+0x171c18/metasec+0xa0f08"
        add("TRANSFORM_WRITER", site=site, byte_writes=88, distinct_offsets=88, min_offset=0, max_offset=87)
        add("LAYOUT_ORDER", site=site, first_sequence=1, last_sequence=168, byte_writes=88)
        add("LAYOUT_MIDDLE", length=88, before_changed_spans="0:8", after_changed_spans="0:88",
            xor_period_1=False, tail_xor_period_1=False)
        for previous in range(1, ordinal):
            same = previous % 2 == ordinal % 2
            add("FIRST_BYTE_COMPARE", previous_ordinal=previous, equal=same)
            add("TRANSFORM_COMPARE", previous_ordinal=previous, before_equal=same, xor_mask_equal=same)
            add("LAYOUT_COMPARE", previous_ordinal=previous,
                before_changed_spans="none" if same else "0:1",
                middle_changed_spans="none" if same else "0:1")
    return ordered(rows)


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None, elf: Path | None = None) -> dict:
    require(set(data) == {"schema", "evidence_date", "input", "parent_evidence", "probe", "runs",
                         "static_analysis", "conclusions", "raw_values_retained", "operand_digests_retained",
                         "interpretation"}, "evidence keys")
    require(data["schema"] == "vm9-framesign-plaintext-layout-20261103-v1", "schema")
    require(data["evidence_date"] == "2026-11-03" and data["input"] == EXPECTED_INPUT, "date/input")
    require(data["parent_evidence"] == "evidence/" + PARENT, "parent")
    require(data["raw_values_retained"] is False and data["operand_digests_retained"] is False, "raw operands/digests")
    require(canonical(data["conclusions"]) == canonical(CLAIMS), "unsupported conclusion")
    parent = json.loads((evidence_dir / PARENT).read_text())
    verify_aes(parent, evidence_dir, elf=elf)
    baseline = json.loads((evidence_dir / BUFFER).read_text())["runs"][0]["repeat_trials"]
    expected_fields = [{"ordinal": r["ordinal"], "fields": r["fields"]} for r in baseline]
    probe = data["probe"]
    require(set(probe) == {"source_relative_path", "source_sha256", "entry_class_sha256", "runner_sha256",
                          "read_only_guest_observation", "synthetic_jni_provider_used", "fresh_rootfs_per_run",
                          "setup_rounds_per_run", "restore_enabled", "comparison_scope", "return_observation_scope",
                          "before_snapshot_boundary", "middle_snapshot_boundary"}, "probe keys")
    require(probe["source_relative_path"] == SOURCE + "/HookMain.java", "source path")
    for key in ("source_sha256", "entry_class_sha256", "runner_sha256"):
        require(isinstance(probe[key], str) and HEX_256.fullmatch(probe[key]), "probe digest")
    for key in ("read_only_guest_observation", "synthetic_jni_provider_used", "fresh_rootfs_per_run"):
        require(probe[key] is True, "probe scope")
    require(type(probe["setup_rounds_per_run"]) is int and probe["setup_rounds_per_run"] == 1
            and probe["restore_enabled"] is False, "setup/restore")
    require(probe["comparison_scope"] == "within_each_four_call_run"
            and probe["return_observation_scope"] == "same_dispatcher_stack_pointer_after_callback"
            and probe["before_snapshot_boundary"] == "before_copy_12_scratch_fill"
            and probe["middle_snapshot_boundary"] == "before_first_a0e7c_buffer_store", "observation boundary")
    require(isinstance(data["runs"], list) and len(data["runs"]) == 2, "independent run count")
    expected = expected_layout()
    for index, run in enumerate(data["runs"], 1):
        require(set(run) == {"local_run_name", "source_sha256", "entry_class_sha256", "native_library_sha256",
                             "sanitized_log_sha256", "process_exit_code", "repeat_trials", "layout_observations"}, "run keys")
        require(run["local_run_name"] == SOURCE + f"/run{index}" and type(run["process_exit_code"]) is int
                and run["process_exit_code"] == 0, "run terminal")
        require(run["native_library_sha256"] == LIBRARY_SHA256 and
                isinstance(run["sanitized_log_sha256"], str) and HEX_256.fullmatch(run["sanitized_log_sha256"]), "run identity")
        for key in ("source_sha256", "entry_class_sha256"):
            require(run[key] == probe[key], "paired build identity")
        require(canonical(run["repeat_trials"]) == canonical(expected_fields), "changed output")
        require(canonical(run["layout_observations"]) == canonical(expected), "layout/writer/snapshot mismatch")
        if probe_dir:
            log = probe_dir / run["local_run_name"] / "sanitized.log"
            require(sha256(log) == run["sanitized_log_sha256"], "local log identity")
            require(parse_layout(log) == expected, "local layout observations")
            require(parse_log(log) == baseline, "complete field/constructor/writer/JNI baseline mismatch")
            require(parse_aes(log) == expected_aes(), "AES regression")
            composition = json.loads((evidence_dir / "vm9_framesign_preimage_composition_20261103.json").read_text())
            require(parse_observations(log) == composition["runs"][index - 1]["composition_observations"]
                    and parse_edges(log) == composition["runs"][index - 1]["sha256_edges"], "preimage/SHA-256 regression")
            meta = json.loads(log.with_name("metadata.json").read_text())
            require(meta["process_exit_code"] == 0 and meta["read_only_guest_probe"] is True
                    and meta["raw_values_retained"] is False, "local terminal/scope")
            for key in ("source_sha256", "entry_class_sha256", "native_library_sha256"):
                require(meta[key] == run[key], "local build identity")
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
    return {"calls_verified": 8, "layout_lengths": [1, 88, 4], "overlapping_copy_verified": True,
            "pre_block_difference_spans": "0:1", "final_plaintext_difference_spans": "0:89",
            "layout_observations_verified": len(expected) * 2, "baseline_and_aes_preserved": True,
            "local_logs_verified": probe_dir is not None, "elf_bytes_verified": elf is not None,
            "alternation_root_cause_identified": False, "standalone_signer_verified": False}


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
