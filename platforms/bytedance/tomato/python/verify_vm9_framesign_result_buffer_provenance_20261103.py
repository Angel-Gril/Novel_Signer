"""Verify digest-only native FrameSign constructor-to-JNI provenance."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from verify_vm9_framesign_same_input_four_call_cycle_20261103 import (
    EXPECTED_INPUT, EXPECTED_KEYS, HEX_256, require, trials,
)
from verify_vm9_framesign_state_boundary_restore_20261103 import LIBRARY_SHA256, check_elf


NAME = "vm9_framesign_result_buffer_provenance_20261103"
SOURCE = "result_constructor_write_probe"
STATIC = {
    "0x16470c": ("ldr", "x9, [x8, #0x50]"),
    "0x164714": ("blr", "x9"),
    "0x17b010": ("bl", "#0x164428"),
    "0x17b024": ("bl", "#0x16285c"),
    "0x17b030": ("bl", "#0x271384"),
    "0x283f38": ("ldr", "x1, [x8, #0x10]"),
    "0x283f44": ("ldr", "w2, [x8, #0xc]"),
    "0x283f48": ("bl", "#0x2481fc"),
    "0x284d28": ("ldr", "x1, [x8, #0x10]"),
    "0x284d34": ("ldr", "w2, [x8, #0xc]"),
    "0x284d38": ("bl", "#0x2481fc"),
    "0x248238": ("str", "x0, [x21, #0x10]"),
    "0x24824c": ("mov", "x0, x22"),
    "0x248250": ("mov", "x1, x20"),
    "0x248254": ("bl", "#0x347f60"),
    "0x2714f0": ("ldr", "x1, [x8, #0x10]"),
    "0x2714f4": ("bl", "#0x270204"),
    "0x271504": ("ldr", "x1, [x8, #0x10]"),
    "0x271508": ("bl", "#0x270204"),
    "0x270238": ("bl", "#0x165b78"),
    "0x270244": ("bl", "#0x270168"),
    "0x27017c": ("b", "#0x270184"),
    "0x2701c4": ("ldr", "x8, [x8, #0x538]"),
    "0x2701c8": ("blr", "x8"),
}
SOURCE_RETURNS = {"lid": "0x284bc0", "signinfo": "0x283f4c",
                  "signvalue": "0x284d3c", "signversion": "0x284b6c"}
POINTER_WRITERS = {"frametype": "0x2481dc", "lid": "0x248238",
                   "signinfo": "0x248238", "signvalue": "0x248238",
                   "signversion": "0x248388"}
EVENTS = {
    "DISPATCH": ("dispatch", "pc target result_slot_present"),
    "COLLECTION": ("collection", "pc result_present shares_dispatch_result"),
    "PAIR": ("pairs", "pc field length sha256"),
    "CONVERT": ("conversions", "pc caller field role source_pointer_equal source_bytes_equal length sha256"),
    "CONSTRUCTOR_SOURCE": ("constructor_sources", "field same_final_object source_bytes_equal write_site source_chain length sha256"),
    "LAST_WRITER": ("last_writers", "field region writer writer_ordinal writer_tag covered_bytes dropped"),
}
CONCLUSIONS = {
    "independent_runs": 2, "calls": 8, "fields_checked": 40,
    "constructor_sources_checked": 32, "dynamic_constructor_sources_checked": 16,
    "value_conversion_stages_checked": 120, "baseline_abab_preserved": True,
    "dispatch_result_shared_with_jni_converter": True,
    "dynamic_field_constructor_inputs_match_jni_results": True,
    "upstream_dynamic_source_identified": False, "cross_runtime_equality_verified": False,
    "fresh_standalone_signer_verified": False,
    "whole_request_native_python_differential_verified": False,
    "online_header_acceptance_verified": False,
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_log(path: Path) -> list[dict]:
    calls, row, keys = [], None, {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if m := re.search(r"FRAME_SIGN_TRIAL=(\d+)$", line):
            row = {"ordinal": int(m[1]) + 1, "result": None, "fields": [],
                   **{key: [] for key, _ in EVENTS.values()}}
            calls.append(row)
            keys = {}
        elif "FRAME_BUFFER_" in line and "ERROR" in line:
            raise AssertionError("probe reported an observation error")
        elif row is None:
            continue
        elif line.endswith("FRAME_SIGN_RESULT_LENGTH=10"):
            row["result"] = "array10"
        elif m := re.search(r"FRAME_SIGN_FIELD_KEY\[(\d+)\]=(\w+)$", line):
            keys[int(m[1])] = m[2]
        elif m := re.search(r"FRAME_SIGN_FIELD_VALUE\[(\d+)\] length=(\d+) sha256=([a-f0-9]{64})$", line):
            row["fields"].append({"key": keys[int(m[1])], "length": int(m[2]), "sha256": m[3]})
        elif m := re.fullmatch(r"\[HookMain\] FRAME_BUFFER_(\w+) (.+)", line):
            if m[1] not in EVENTS:
                continue
            event = {}
            for token in m[2].split():
                key, value = token.split("=", 1)
                require(key not in event, "duplicate local event attribute")
                event[key] = (value == "true" if value in ("true", "false") else
                              int(value) if re.fullmatch(r"-?\d+", value) else value)
            require(event["ordinal"] == row["ordinal"], "local event ordinal")
            target, names = EVENTS[m[1]]
            normalized = {key: event[key] for key in names.split()}
            if m[1] == "CONSTRUCTOR_SOURCE":
                # The private probe retained only digests at the constructor
                # store; reserve byte equality for the live conversion reads.
                normalized["source_digest_equal"] = normalized.pop("source_bytes_equal")
            row[target].append(normalized)
    return calls


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None) -> dict:
    require(set(data) == {"schema", "evidence_date", "input", "baseline_evidence", "probe",
                         "runs", "static_analysis", "conclusions", "raw_values_retained", "interpretation"}, "evidence keys")
    require(data["schema"] == "vm9-framesign-result-buffer-provenance-20261103-v1", "schema")
    require(data["evidence_date"] == "2026-11-03" and data["input"] == EXPECTED_INPUT, "input/date")
    require(data["raw_values_retained"] is False and data["conclusions"] == CONCLUSIONS, "scope/claims")
    require(data["baseline_evidence"] == "evidence/vm9_framesign_same_input_four_call_cycle_20261103.json", "baseline link")
    baseline = json.loads((evidence_dir / Path(data["baseline_evidence"]).name).read_text())
    expected = trials(baseline["unidbg"]["repeat_trials"], "baseline")
    probe = data["probe"]
    require(set(probe) == {"source_relative_path", "source_sha256", "entry_class_sha256",
            "read_only_guest_observation", "synthetic_jni_provider_used", "fresh_rootfs_per_run",
            "setup_rounds_per_run", "restore_enabled", "writer_tracking", "entry_hook_absence_is_execution_exclusion"}, "probe keys")
    require(probe["source_relative_path"] == SOURCE + "/HookMain.java", "source owner")
    for key in ("read_only_guest_observation", "synthetic_jni_provider_used", "fresh_rootfs_per_run"):
        require(probe[key] is True, key)
    require(probe["setup_rounds_per_run"] == 1 and probe["restore_enabled"] is False, "setup/restore")
    require(probe["writer_tracking"] == "last_observed_guest_writer_per_byte" and
            probe["entry_hook_absence_is_execution_exclusion"] is False, "observation limits")
    for key in ("source_sha256", "entry_class_sha256"):
        require(isinstance(probe[key], str) and HEX_256.fullmatch(probe[key]), key)
    require(isinstance(data["runs"], list) and len(data["runs"]) == 2, "run count")
    for run_index, run in enumerate(data["runs"], 1):
        require(set(run) == {"local_run_name", "source_sha256", "entry_class_sha256", "sanitized_log_sha256",
                "native_library_sha256", "process_exit_code", "repeat_trials"}, "run keys")
        require(run["local_run_name"] == SOURCE + f"/run{run_index}", "independent run identity")
        require(run["process_exit_code"] == 0 and run["native_library_sha256"] == LIBRARY_SHA256, "run/library identity")
        for key in ("source_sha256", "entry_class_sha256"):
            require(run[key] == probe[key], "paired probe build")
        require(HEX_256.fullmatch(run["sanitized_log_sha256"]), "log digest")
        rows = run["repeat_trials"]
        actual = trials([{"ordinal": r["ordinal"], "fields": r["fields"]} for r in rows], "result")
        require(actual == expected, "probe changed baseline output")
        for row in rows:
            ordinal = row["ordinal"]
            require(set(row) == {"ordinal", "result", "fields", *[x for x, _ in EVENTS.values()]}, "call keys")
            require(row["result"] == "array10", "result shape")
            require(row["dispatch"] == [
                {"pc": "metasec+0x164894", "target": "metasec+0x163e58", "result_slot_present": False},
                {"pc": "metasec+0x164714", "target": "metasec+0x283748", "result_slot_present": True}], "actual dispatch")
            require(row["collection"] == [{"pc": "metasec+" + pc, "result_present": True,
                    "shares_dispatch_result": pc == "0x271384"} for pc in ("0x164718", "0x17b014", "0x271384")], "result ownership")
            require(row["pairs"] == [{"pc": "metasec+0x2714e4", "field": k, **actual[ordinal][k]}
                                     for k in EXPECTED_KEYS], "native pairs")
            conversions = []
            for key in EXPECTED_KEYS:
                key_bytes = key.encode()
                for role in ("key", "value"):
                    digest = ({"length": len(key_bytes), "sha256": hashlib.sha256(key_bytes).hexdigest()}
                              if role == "key" else actual[ordinal][key])
                    for pc, caller in (("metasec+0x270204", "metasec+0x2714f8" if role == "key" else "metasec+0x27150c"),
                                       ("metasec+0x270184", "metasec+0x270248"),
                                       ("outside_modules", "metasec+0x2701cc")):
                        conversions.append({"pc": pc, "caller": caller, "field": key, "role": role,
                            "source_pointer_equal": role == "value" and pc == "metasec+0x270204",
                            "source_bytes_equal": role == "value", **digest})
            unrelated = {"pc": "outside_modules", "caller": "metasec+0x26ff40", "field": "none", "role": "value",
                "source_pointer_equal": False, "source_bytes_equal": False, "length": 5,
                "sha256": "5cf1fa8d836a5e82ead36fb0854a6a68a4b8f7542038a346357d2424ddb60f5e"}
            require(row["conversions"] == [unrelated, *conversions], "ordered key/value conversion pipeline")
            require(row["constructor_sources"] == [{"field": key, "same_final_object": True,
                "source_digest_equal": True, "write_site": "metasec+" + POINTER_WRITERS[key],
                "source_chain": ",".join(["metasec+" + ret, "metasec+0x164718", "metasec+0x17b014",
                                         "metasec+0x17713c", "outside_modules"]),
                **actual[ordinal][key]} for key, ret in SOURCE_RETURNS.items()], "constructor input provenance")
            writers = []
            for key in EXPECTED_KEYS:
                for region, site, size in (("value", "libc.so+0x1c148", actual[ordinal][key]["length"]),
                                            ("pointer_slot", "metasec+" + POINTER_WRITERS[key], 8)):
                    writers.append({"field": key, "region": region, "writer": site,
                        "writer_ordinal": ordinal, "writer_tag": "0x200000a", "covered_bytes": size, "dropped": 0})
            require(row["last_writers"] == writers, "current-call writer coverage")
        if probe_dir:
            log = probe_dir / run["local_run_name"] / "sanitized.log"
            require(sha256(log) == run["sanitized_log_sha256"], "local log identity")
            require(parse_log(log) == rows, "local observation mismatch")
            meta = json.loads(log.with_name("metadata.json").read_text())
            require(meta["process_exit_code"] == 0 and meta["read_only_guest_probe"] is True and
                    meta["raw_values_retained"] is False, "local run terminal/scope")
            for key in ("source_sha256", "entry_class_sha256", "native_library_sha256"):
                require(meta[key] == run[key], "local metadata mismatch")
    if probe_dir:
        require(sha256(probe_dir / probe["source_relative_path"]) == probe["source_sha256"], "source identity")
        require(sha256(probe_dir / SOURCE / "classes/HookMain.class") == probe["entry_class_sha256"], "entry identity")
    analysis = data["static_analysis"]
    require(set(analysis) == {"native_library_sha256", "instructions"} and
            analysis["native_library_sha256"] == LIBRARY_SHA256, "static identity")
    require([x["image_offset"] for x in analysis["instructions"]] == list(STATIC), "static sites")
    for instruction in analysis["instructions"]:
        require(set(instruction) == {"image_offset", "file_offset", "bytes_hex", "mnemonic", "operands"}, "instruction keys")
        require((instruction["mnemonic"], instruction["operands"]) == STATIC[instruction["image_offset"]], "static contract")
        require(re.fullmatch(r"[a-f0-9]{8}", instruction["bytes_hex"]), "instruction bytes")
    if elf:
        check_elf(elf, analysis)
    return {"calls_verified": 8, "field_pipelines_verified": 40, "constructor_sources_verified": 32,
            "dynamic_constructor_sources_verified": 16, "value_conversion_stages_verified": 120,
            "static_instructions_verified": len(STATIC), "baseline_abab_preserved": True,
            "local_logs_verified": probe_dir is not None, "elf_bytes_verified": elf is not None,
            "upstream_dynamic_source_identified": False, "standalone_signer_verified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=Path(__file__).resolve().parents[1] / "evidence" / (NAME + ".json"))
    parser.add_argument("--probe-dir", type=Path)
    parser.add_argument("--elf", type=Path)
    args = parser.parse_args()
    data = json.loads(args.evidence.read_text(encoding="utf-8"))
    print(json.dumps(verify(data, args.evidence.parent, args.probe_dir, args.elf), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
