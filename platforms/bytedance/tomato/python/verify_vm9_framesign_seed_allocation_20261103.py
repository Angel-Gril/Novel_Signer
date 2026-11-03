"""Verify the fixed-profile seed byte's observed calloc-return dependency."""
from __future__ import annotations

import argparse
from io import BytesIO
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile

from verify_vm9_framesign_plaintext_layout_20261103 import (
    BUFFER, EXPECTED_INPUT, HEX_256, LIBRARY_SHA256, canonical, check_elf, expected_aes,
    expected_layout, ordered, parse_aes, parse_edges, parse_layout, parse_log,
    parse_observations, require, sha256, verify as verify_layout,
)

NAME = "vm9_framesign_seed_allocation_20261103"
SOURCE = "preblock_seed_calloc_relation_probe"
PARENT = "vm9_framesign_plaintext_layout_20261103.json"
LIBC = {
    "artifact": "unidbg-android-0.9.9.jar", "resource": "android/sdk23/lib64/libc.so",
    "jar_sha256": "ce52ddda7772ac79adb4606dbaf0a65c53c41af96e73299a98eadec608f270fc",
    "library_sha256": "d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db",
    "symbol": "calloc", "image_offset": "0x1baa0", "symbol_size": 32,
    "symbol_code_sha256": "c5751722fc5f760d134dbf636051fe3bdd94bc91ce5e20d4fa2668260079f9d6",
}
STATIC = {
    "0x268504": ("stp", "x30, x19, [sp, #-0x10]!"),
    "0x268508": ("mov", "x19, x0"),
    "0x26850c": ("ldp", "x8, x0, [x0]"),
    "0x268510": ("ldr", "x1, [x19, #0x10]"),
    "0x268514": ("blr", "x8"),
    "0x268518": ("str", "x0, [x19, #0x18]"),
    "0x16f96c": ("ldr", "x9, [x12, x13]"),
    "0x16f974": ("str", "x9, [x28, x14, lsl #3]"),
    "0x16e108": ("and", "w9, w11, w14"),
    "0x16e110": ("and", "x9, x9, #0xffff"),
    "0x16e118": ("str", "x9, [x28, x12, lsl #3]"),
    "0x16a5b8": ("ldr", "x10, [x28, w8, uxtw #3]"),
    "0x16a5c0": ("ldr", "x11, [x28, w9, uxtw #3]"),
    "0x16a5cc": ("orr", "x10, x11, x10"),
    "0x16a5d8": ("str", "x10, [x28, w12, uxtw #3]"),
    "0x171c04": ("ldr", "w10, [x28, x10]"),
    "0x171c18": ("strb", "w10, [x11, x9]"),
}
CLAIMS = {
    "independent_runs": 2, "calls": 8, "calloc_count_per_call": 1,
    "allocation_size": 95, "allocation_is_plaintext_buffer": True,
    "pre_block_first_byte_calloc_dependency_verified": True,
    "allocation_pointer_abab_within_each_run": True,
    "varying_OR_input_is_masked_allocation_pointer": True,
    "other_OR_input_stable_within_each_run": True,
    "libc_symbol_and_runtime_code_matched": True,
    "complete_baseline_layout_and_aes_preserved": True,
    "allocator_reuse_policy_identified": False, "block_transform_algorithm_identified": False,
    "suffix_generation_identified": False, "key_or_iv_generation_identified": False,
    "general_input_equivalence_verified": False, "android_equivalence_verified": False,
    "android_alternation_cause_identified": False, "complete_standalone_signer_verified": False,
    "online_header_acceptance_verified": False,
}
EVENTS = {"PREBLOCK_CALLOC_CODE", "PREBLOCK_CALLOC_CALL", "PREBLOCK_CALLOC_RETURN", "PREBLOCK_CALLOC_LINK",
          "PREBLOCK_CALLOC_COMPARE", "PREBLOCK_ORIGIN", "PREBLOCK_VREG", "PREBLOCK_OR", "PREBLOCK_OPERAND",
          "PREBLOCK_OPERAND_COMPARE", "PREBLOCK_LOAD_SOURCE", "PREBLOCK_LOAD_ADDRESS_COMPARE"}
OPERANDS = {"root.0", "root.1", "root.0.0"}
COMPARISONS = OPERANDS | {"root.0.1"}


def parse_seed(path: Path) -> list[dict]:
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
            require(key not in row, "duplicate seed attribute")
            row[key] = (value == "true" if value in ("true", "false") else
                        int(value) if value.lstrip("-").isdecimal() else value)
        if event == "PREBLOCK_OPERAND" and row.get("path") not in OPERANDS:
            continue
        if event == "PREBLOCK_OPERAND_COMPARE" and row.get("path") not in COMPARISONS:
            continue
        rows.append(row)
    return ordered(rows)


def expected_seed() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        def add(event, **values):
            rows.append({"event": "PREBLOCK_" + event, "ordinal": ordinal, **values})
        add("CALLOC_CODE", code_length=32, code_sha256=LIBC["symbol_code_sha256"])
        add("CALLOC_CALL", wrapper="metasec+0x268504", target="libc.so+0x1baa0", symbol="calloc",
            count=1, element_size=95, allocation_size=95)
        add("CALLOC_RETURN", return_register_equals_slot=True, allocation_zero_filled=True, allocation_size=95)
        add("CALLOC_LINK", calls=1, returns=1, buffer_equals_return_pointer=True, buffer_93_inside_allocation=True,
            load_source_equals_return_slot=True, loaded_value_equals_return_pointer=True, masked_return_equals_OR_left=True,
            callback_expression_equals_OR_result=True, callback_expression_low_byte_equals_buffer=True)
        add("ORIGIN", writer="metasec+0x171c18", writer_bcp="metasec+0xa0658", writer_ordinal=ordinal, strb_record_present=True)
        add("VREG", value_slot=2, register_equals_store_operand=True, stored_byte_equals_buffer=True,
            source_writer="metasec+0x16a5d8", source_writer_bcp="metasec+0xa0654",
            source_writer_ordinal=ordinal, source_register_still_equal=False)
        for path, op, bcp, destination in (("root", "OR64", "a0654", 2), ("root.0", "AND16", "a064c", 2),
                                           ("root.0.0", "LOAD64", "a0614", 3), ("root.1", "AND16", "a05d4", 20)):
            add("OR", path=path, operation=op, bcp="metasec+0x" + bcp, destination_slot=destination,
                architectural_result_matches=True, operand_values_equal=False, result_equals_left=op == "LOAD64",
                result_equals_right=path == "root" and ordinal % 2 == 0)
        for path, slot, writer, bcp in (("root.0", 2, "16e118", "a064c"), ("root.1", 20, "16e118", "a05d4"),
                                         ("root.0.0", 3, "16f974", "a0614")):
            add("OPERAND", path=path, source_slot=slot, writer="metasec+0x" + writer,
                writer_bcp="metasec+0x" + bcp, writer_ordinal=ordinal, definition_present=True, depth_limit=False)
        add("LOAD_SOURCE", path="root.0.0", source_location="outside_modules",
            source_writers=f"metasec+0x268518/metasec+0x268518/{ordinal}:8")
        for previous in range(1, ordinal):
            same = previous % 2 == ordinal % 2
            add("CALLOC_COMPARE", previous_ordinal=previous, return_pointer_equal=same)
            add("LOAD_ADDRESS_COMPARE", path="root.0.0", previous_ordinal=previous, address_equal=True)
            for path in sorted(COMPARISONS):
                add("OPERAND_COMPARE", path=path, previous_ordinal=previous,
                    value_equal=True if path in ("root.1", "root.0.1") else same)
    return ordered(rows)


def check_libc_jar(path: Path) -> None:
    from elftools.elf.elffile import ELFFile
    require(sha256(path) == LIBC["jar_sha256"], "libc provider identity")
    with ZipFile(path) as archive:
        raw = archive.read(LIBC["resource"])
    require(hashlib.sha256(raw).hexdigest() == LIBC["library_sha256"], "libc library identity")
    elf = ELFFile(BytesIO(raw))
    matches = [s for s in elf.get_section_by_name(".dynsym").iter_symbols() if s.name == "calloc"]
    require(len(matches) == 1 and matches[0]["st_value"] == int(LIBC["image_offset"], 16)
            and matches[0]["st_size"] == 32, "calloc symbol")
    address = matches[0]["st_value"]
    segment = next(s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"
                   and s["p_vaddr"] <= address and address + 32 <= s["p_vaddr"] + s["p_filesz"])
    offset = segment["p_offset"] + address - segment["p_vaddr"]
    require(hashlib.sha256(raw[offset:offset + 32]).hexdigest() == LIBC["symbol_code_sha256"], "calloc code")


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None, libc_jar: Path | None = None) -> dict:
    require(set(data) == {"schema", "evidence_date", "input", "parent_evidence", "probe", "runs", "static_analysis",
                         "libc_provider", "conclusions", "raw_values_retained", "operand_digests_retained", "interpretation"}, "evidence keys")
    require(data["schema"] == "vm9-framesign-seed-allocation-20261103-v1", "schema")
    require(data["evidence_date"] == "2026-11-03" and data["input"] == EXPECTED_INPUT, "date/input")
    require(data["parent_evidence"] == "evidence/" + PARENT, "parent")
    require(data["raw_values_retained"] is False and data["operand_digests_retained"] is False, "raw operands/digests")
    require(canonical(data["conclusions"]) == canonical(CLAIMS) and data["libc_provider"] == LIBC, "unsupported conclusion/provider")
    verify_layout(json.loads((evidence_dir / PARENT).read_text()), evidence_dir, elf=elf)
    baseline = json.loads((evidence_dir / BUFFER).read_text())["runs"][0]["repeat_trials"]
    fields = [{"ordinal": r["ordinal"], "fields": r["fields"]} for r in baseline]
    probe = data["probe"]
    require(set(probe) == {"source_relative_path", "source_sha256", "entry_class_sha256", "runner_sha256",
                          "read_only_guest_observation", "synthetic_jni_provider_used", "fresh_rootfs_per_run",
                          "setup_rounds_per_run", "restore_enabled", "comparison_scope", "return_observation_scope"}, "probe keys")
    require(probe["source_relative_path"] == SOURCE + "/HookMain.java", "source path")
    for key in ("source_sha256", "entry_class_sha256", "runner_sha256"):
        require(isinstance(probe[key], str) and HEX_256.fullmatch(probe[key]), "probe digest")
    for key in ("read_only_guest_observation", "synthetic_jni_provider_used", "fresh_rootfs_per_run"):
        require(probe[key] is True, "probe scope")
    require(type(probe["setup_rounds_per_run"]) is int and probe["setup_rounds_per_run"] == 1
            and probe["restore_enabled"] is False, "setup/restore")
    require(probe["comparison_scope"] == "within_each_four_call_run"
            and probe["return_observation_scope"] == "same_dispatcher_stack_pointer_after_callback", "observation scope")
    require(isinstance(data["runs"], list) and len(data["runs"]) == 2, "independent run count")
    expected = expected_seed()
    for index, run in enumerate(data["runs"], 1):
        require(set(run) == {"local_run_name", "source_sha256", "entry_class_sha256", "native_library_sha256",
                             "sanitized_log_sha256", "process_exit_code", "repeat_trials", "seed_observations"}, "run keys")
        require(run["local_run_name"] == SOURCE + f"/run{index}" and type(run["process_exit_code"]) is int
                and run["process_exit_code"] == 0, "run terminal")
        require(run["native_library_sha256"] == LIBRARY_SHA256 and
                isinstance(run["sanitized_log_sha256"], str) and HEX_256.fullmatch(run["sanitized_log_sha256"]), "run identity")
        for key in ("source_sha256", "entry_class_sha256"):
            require(run[key] == probe[key], "paired build identity")
        require(canonical(run["repeat_trials"]) == canonical(fields), "changed output")
        require(canonical(run["seed_observations"]) == canonical(expected), "seed/calloc/dataflow mismatch")
        if probe_dir:
            log = probe_dir / run["local_run_name"] / "sanitized.log"
            require(sha256(log) == run["sanitized_log_sha256"], "local log identity")
            require(parse_seed(log) == expected and parse_layout(log) == expected_layout(), "local seed/layout")
            require(parse_log(log) == baseline and parse_aes(log) == expected_aes(), "complete baseline/AES")
            parent = json.loads((evidence_dir / "vm9_framesign_preimage_composition_20261103.json").read_text())
            require(parse_observations(log) == parent["runs"][index - 1]["composition_observations"]
                    and parse_edges(log) == parent["runs"][index - 1]["sha256_edges"], "preimage/SHA-256")
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
    if libc_jar:
        check_libc_jar(libc_jar)
    return {"calls_verified": 8, "seed_observations_verified": len(expected) * 2, "allocation_size": 95,
            "pre_block_seed_calloc_dependency_verified": True, "baseline_layout_and_aes_preserved": True,
            "local_logs_verified": probe_dir is not None, "elf_bytes_verified": elf is not None,
            "libc_artifact_verified": libc_jar is not None, "android_equivalence_verified": False,
            "standalone_signer_verified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=Path(__file__).resolve().parents[1] / "evidence" / (NAME + ".json"))
    parser.add_argument("--probe-dir", type=Path)
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--libc-jar", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.evidence.read_text()), args.evidence.parent, args.probe_dir, args.elf, args.libc_jar), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
