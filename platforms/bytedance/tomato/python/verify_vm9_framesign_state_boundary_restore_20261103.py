"""Check the redacted FrameSign boundary-restore intervention and its limits."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from verify_vm9_framesign_same_input_four_call_cycle_20261103 import (
    EXPECTED_INPUT, EXPECTED_LENGTHS, HEX_256, require, verify as verify_baseline,
)
from verify_vm9_framesign_unidbg_repeat_call_dynamics_20261103 import validate_fields


LIBRARY_SHA256 = "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c"
RESULTS = ["array10", "null", "array10", "array10"]
LIMITS = ("direct_dynamic_source_identified", "manager_extent_verified",
          "fresh_standalone_signer_verified",
          "whole_request_native_python_differential_verified",
          "online_header_acceptance_verified")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def field_map(row: dict) -> dict:
    if row["result"] == "null":
        require(row["fields"] == [], "null call carries fields")
        return {}
    require(row["result"] == "array10", "unexpected result shape")
    parsed = validate_fields(row["fields"], "restore evidence")
    require({k: v["length"] for k, v in parsed.items()} == EXPECTED_LENGTHS, "field lengths")
    return parsed


def check_local_log(path: Path, run: dict) -> None:
    require(sha256(path) == run["sanitized_log_sha256"], "local sanitized log hash")
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    found, row, keys = [], None, {}
    for line in lines:
        if m := re.search(r"FRAME_SIGN_TRIAL=(\d+)$", line):
            row = {"ordinal": int(m[1]) + 1, "result": None, "fields": []}
            found.append(row)
            keys = {}
        elif m := re.search(r"FRAME_SIGN_RESULT_LENGTH=(\d+)$", line):
            require(int(m[1]) == 10, "local result length")
            row["result"] = "array10"
        elif line.endswith("FRAME_SIGN_RESULT_TYPE=null"):
            row["result"] = "null"
        elif m := re.search(r"FRAME_SIGN_FIELD_KEY\[(\d+)\]=(\w+)$", line):
            keys[int(m[1])] = m[2]
        elif m := re.search(r"FRAME_SIGN_FIELD_VALUE\[(\d+)\] length=(\d+) sha256=([0-9a-f]{64})$", line):
            row["fields"].append({"key": keys[int(m[1])], "length": int(m[2]), "sha256": m[3]})
    require(found == [{k: row[k] for k in ("ordinal", "result", "fields")}
                      for row in run["repeat_trials"]], "local log/result mismatch")


def check_elf(path: Path, analysis: dict) -> None:
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == LIBRARY_SHA256, "native ELF identity")
    require(raw[:6] == b"\x7fELF\x02\x01", "64-bit little-endian ELF required")
    require(struct.unpack_from("<H", raw, 18)[0] == 183, "AArch64 ELF required")
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    entsize, count = struct.unpack_from("<HH", raw, 54)
    segments = [struct.unpack_from("<IIQQQQQQ", raw, phoff + i * entsize)
                for i in range(count)]
    for item in analysis["instructions"]:
        va, offset = int(item["image_offset"], 16), int(item["file_offset"], 16)
        owners = [s for s in segments if s[0] == 1 and s[1] & 1 and s[3] <= va
                  and va + 4 <= s[3] + s[5]]
        require(len(owners) == 1, "instruction not in one executable PT_LOAD")
        seg = owners[0]
        require(offset == va - seg[3] + seg[2], "file/VA mapping mismatch")
        require(raw[offset:offset + 4].hex() == item["bytes_hex"], "static instruction mismatch")


def verify(path: Path, probe_dir: Path | None = None, elf: Path | None = None) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(set(data) == {"schema", "evidence_date", "package", "input",
                         "baseline_evidence", "unidbg", "intervention", "paired_runs",
                         "earlier_restore_reproductions", "static_analysis",
                         "comparison", "raw_signature_values_retained", "interpretation"},
            "unexpected evidence field")
    require(data["schema"] == "vm9-framesign-state-boundary-restore-20261103-v1", "schema")
    require(data["input"] == EXPECTED_INPUT, "input identity")
    require(data["package"] == "com.dragon.read", "package identity")
    require(data["raw_signature_values_retained"] is False, "raw signature retention")
    require(data["baseline_evidence"] ==
            "evidence/vm9_framesign_same_input_four_call_cycle_20261103.json", "baseline link")
    baseline_path = path.parent / Path(data["baseline_evidence"]).name
    verify_baseline(baseline_path)
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    require(data["unidbg"] == {
        "version": "0.9.9", "backend": "Unicorn2", "frame_sign_tag": "0x200000a",
        "handle_source_tag": "0x4000002", "preceding_business_sign_rounds": 1,
        "same_handle_within_run": True, "fresh_rootfs_per_run": True,
        "synthetic_jni_provider_used": True}, "runtime contract")
    intervention = data["intervention"]
    require(intervention == {
        "offset_from_manager": 112, "length": 16, "capture_after_ordinal": 1,
        "restore_before_ordinals": [2, 3, 4],
        "write_event_scope": "guest writes overlapping the selected 16 bytes",
        "restore_execution_scope": "next instruction hook in metasec +0x1000..+0x3c9000, or JNI call return",
        "libc_instruction_boundaries_hooked": False,
        "continuous_write_suppression_verified": False,
        "restored_bytes_object_ownership_verified": False}, "intervention or coverage overclaim")
    runs = data["paired_runs"]
    require(set(runs) == {"control", "restored"}, "paired run names")
    parsed = {}
    for label, run in runs.items():
        require(set(run) == {"local_run_name", "source_sha256", "entry_class_sha256",
                            "native_library_sha256", "sanitized_log_sha256",
                            "process_exit_code", "restore_enabled", "repeat_trials",
                            "saved_after_first_call", "pre_call_restore_count",
                            "allocator_coverage"}, "unexpected run data")
        for k in ("source_sha256", "entry_class_sha256", "native_library_sha256", "sanitized_log_sha256"):
            require(HEX_256.fullmatch(run[k]) is not None, f"invalid digest: {k}")
        require(run["native_library_sha256"] == LIBRARY_SHA256, "library hash")
        require(run["process_exit_code"] == 0, "run did not terminate successfully")
        enabled = label == "restored"
        require(run["restore_enabled"] is enabled, "restore switch")
        require(run["saved_after_first_call"] is enabled, "saved region")
        require(run["pre_call_restore_count"] == (3 if enabled else 0), "pre-call restores")
        require(run["allocator_coverage"] == {"allocation_entry_events": 87,
                "matched_allocation_returns": 78, "free_entry_events": 51,
                "manager_minus_hint": 0}, "bounded allocation coverage")
        rows = run["repeat_trials"]
        require([r["ordinal"] for r in rows] == [1, 2, 3, 4], "call order")
        require([r["result"] for r in rows] == (RESULTS if enabled else ["array10"] * 4),
                "paired result sequence")
        for row in rows:
            require(set(row) == {"ordinal", "result", "fields", "restore", "write_sites"},
                    "unexpected per-call data")
        parsed[label] = [field_map(row) for row in rows]
        if probe_dir:
            require(run["local_run_name"] in {"lifetime_control_4", "lifetime_frozen_1"}, "local run path")
            check_local_log(probe_dir / run["local_run_name"] / "sanitized.log", run)
    for key in ("source_sha256", "entry_class_sha256", "native_library_sha256"):
        require(runs["control"][key] == runs["restored"][key], "paired build identity")
    if probe_dir:
        require(sha256(probe_dir / "HookMain.java") == runs["control"]["source_sha256"],
                "current private harness identity")
        require(sha256(probe_dir / "classes/HookMain.class") == runs["control"]["entry_class_sha256"],
                "current private entry class identity")
    control, restored = parsed["control"], parsed["restored"]
    require([r["fields"] for r in runs["control"]["repeat_trials"]] ==
            [r["fields"] for r in baseline["unidbg"]["repeat_trials"]], "prior baseline differs")
    require(control[0] == restored[0], "paired first calls differ")
    for key in ("signinfo", "signvalue"):
        require(control[1][key] == restored[2][key], "delayed B digest")
        require(restored[3][key] not in [control[0][key], control[1][key]], "new C digest")
    for n in (0, 2, 3):
        for key in ("frametype", "lid", "signversion"):
            require(restored[n][key] == control[0][key], "stable field digest changed")
    for n, row in enumerate(runs["restored"]["repeat_trials"]):
        if n == 0:
            require(row["restore"] is None and row["write_sites"] == [], "first call mutated")
        else:
            require(row["restore"] == {"write_events": 4 if n == 1 else 0,
                    "boundary_restores": 2 if n == 1 else 0, "errors": 0,
                    "pending": False, "final_bytes_equal_saved": True}, "restore counts/state")
    sites = runs["restored"]["repeat_trials"][1]["write_sites"]
    require(sites == [
        {"pc": "libc.so+0x1c148", "lr": "metasec+0x2543f8", "relative_offset": 0, "size": 8, "count": 1},
        {"pc": "libc.so+0x1c148", "lr": "metasec+0x2543f8", "relative_offset": 8, "size": 8, "count": 2},
        {"pc": "metasec+0x255110", "lr": "metasec+0x2633e0", "relative_offset": 0, "size": 8, "count": 1}],
        "write origin observations")
    require(all(row["restore"] is None and row["write_sites"] == []
                for row in runs["control"]["repeat_trials"]), "control mutated")
    history = data["earlier_restore_reproductions"]
    require(len(history) == 4, "earlier reproduction count")
    for i, run in enumerate(history, 1):
        require(set(run) == {"local_run_name", "sanitized_log_sha256",
                "source_revision_identity_available", "result_sequence",
                "dynamic_digest_sequence", "second_call_write_events",
                "second_call_boundary_restores"}, "unexpected earlier-run data")
        require(run["local_run_name"] == f"freeze_during_call_{i}", "earlier run identity")
        require(run["source_revision_identity_available"] is False, "invented historical build identity")
        require(HEX_256.fullmatch(run["sanitized_log_sha256"]) is not None, "earlier log digest")
        require(run["result_sequence"] == RESULTS, "earlier result differs")
        require(run["second_call_write_events"] == 4 and run["second_call_boundary_restores"] == 2,
                "earlier restoration differs")
        require(run["dynamic_digest_sequence"] == {k: [r.get(k, {}).get("sha256") for r in restored]
                for k in ("signinfo", "signvalue")}, "earlier signature digests differ")
        if probe_dir:
            require(sha256(probe_dir / run["local_run_name"] / "sanitized.log") ==
                    run["sanitized_log_sha256"], "earlier local log identity")
    analysis = data["static_analysis"]
    require(analysis["native_library_sha256"] == LIBRARY_SHA256, "static source identity")
    require(analysis["runtime_object_identity_verified"] is False, "static/runtime identity overclaim")
    instructions = {r["image_offset"]: r for r in analysis["instructions"]}
    require(len(instructions) == 15, "static instruction inventory")
    require(all(set(r) == {"image_offset", "file_offset", "bytes_hex", "mnemonic", "operands"}
                and re.fullmatch(r"[0-9a-f]{8}", r["bytes_hex"])
                for r in analysis["instructions"]), "static instruction record")
    zero = instructions["0x255110"]
    require(zero["mnemonic"] == "str" and zero["operands"] == "xzr, [x24], #8", "zero store")
    require(instructions["0x2551ac"]["operands"] == "#0x2550cc", "recursive cleanup call")
    require(instructions["0x2633ec"]["operands"] == "#0x32a264", "delete wrapper tail")
    comparison = data["comparison"]
    require(set(comparison) == set(LIMITS) | {"control_matches_prior_unidbg_four_calls",
            "paired_first_call_matches", "second_call_null_only_with_restore",
            "subsequent_dynamic_digests_depart_from_control", "mutation_affects_isolated_call_flow"},
            "comparison fields")
    require(all(v is (False if k in LIMITS else True) for k, v in comparison.items()),
            "causality/completion overclaim")
    if elf:
        check_elf(elf, analysis)
    return {"paired_calls_verified": 8, "earlier_reproduction_runs_verified": 4,
            "intervention_changes_call_flow": True, "continuous_suppression_verified": False,
            "dynamic_source_identified": False, "local_logs_verified": probe_dir is not None,
            "static_elf_bytes_verified": elf is not None, "complete_signer_verified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=Path(__file__).resolve().parents[1] /
                        "evidence/vm9_framesign_state_boundary_restore_20261103.json")
    parser.add_argument("--probe-dir", type=Path, help="Private probe directory; reads sanitized logs only")
    parser.add_argument("--elf", type=Path, help="Pinned native ELF for independent file/VA byte checks")
    args = parser.parse_args()
    print(json.dumps(verify(args.evidence, args.probe_dir, args.elf), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
