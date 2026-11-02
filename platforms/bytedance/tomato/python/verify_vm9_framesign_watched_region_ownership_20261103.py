"""Verify that the previously watched FrameSign bytes overlap per-call objects."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from verify_vm9_framesign_same_input_four_call_cycle_20261103 import (
    EXPECTED_INPUT, HEX_256, require, trials,
)
from verify_vm9_framesign_state_boundary_restore_20261103 import (
    LIBRARY_SHA256, check_elf, check_local_log, sha256, verify as verify_restore,
)


def local_events(path: Path) -> list[list[dict]]:
    calls = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if "FRAME_SIGN_TRIAL=" in line:
            calls.append([])
        elif calls and (m := re.search(
            r"FRAME_SIGN_LIFETIME event=(callback_alloc|cleanup_object)(?: seq=\d+)? "
            r"tag=(0x[0-9a-f]+) relative_start=(\d+) requested_size=(\d+)(.*)$", line
        )):
            calls[-1].append({"kind": m[1], "tag": m[2], "relative_start": int(m[3]),
                "requested_size": int(m[4]), "overlaps_watch": "overlaps_watch=true" in m[5],
                "site": "metasec+0x25438c" if m[1] == "callback_alloc" else "metasec+0x2550cc"})
    return calls


def verify(path: Path, probe_dir: Path | None = None, elf: Path | None = None) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(set(data) == {"schema", "evidence_date", "input", "baseline_evidence",
            "restore_evidence", "probe", "runs", "static_analysis", "conclusions",
            "raw_values_retained", "interpretation"}, "unexpected top-level data")
    require(data["schema"] == "vm9-framesign-watched-region-ownership-20261103-v1", "schema")
    require(data["input"] == EXPECTED_INPUT, "input")
    require(data["raw_values_retained"] is False, "raw values retained")
    require(data["baseline_evidence"] == "evidence/vm9_framesign_same_input_four_call_cycle_20261103.json",
            "baseline link")
    require(data["restore_evidence"] == "evidence/vm9_framesign_state_boundary_restore_20261103.json",
            "restore link")
    verify_restore(path.parent / Path(data["restore_evidence"]).name)
    baseline = json.loads((path.parent / Path(data["baseline_evidence"]).name).read_text(encoding="utf-8"))
    baseline_calls = trials(baseline["unidbg"]["repeat_trials"], "prior unidbg")
    probe = data["probe"]
    require(set(probe) == {"read_only_guest_observation", "synthetic_jni_provider_used",
            "fresh_rootfs_per_run", "setup_rounds_per_run", "watch_relative_start",
            "watch_length", "callback_source_relative_path", "source_sha256",
            "entry_class_sha256"}, "unexpected probe data")
    for k in ("read_only_guest_observation", "synthetic_jni_provider_used", "fresh_rootfs_per_run"):
        require(probe[k] is True, k)
    require(probe["setup_rounds_per_run"] == 1, "setup count")
    require((probe["watch_relative_start"], probe["watch_length"]) == (112, 16), "watch bounds")
    require(probe["callback_source_relative_path"] == "callback_lifetime_probe/HookMain.java", "probe path")
    require(len(data["runs"]) == 2, "independent run count")
    for i, run in enumerate(data["runs"], 1):
        require(set(run) == {"local_run_name", "source_sha256", "entry_class_sha256",
            "sanitized_log_sha256", "native_library_sha256", "process_exit_code",
            "restore_enabled", "repeat_trials"}, "unexpected run data")
        require(run["local_run_name"] == f"callback_lifetime_control_{i}", "run identity")
        require(run["restore_enabled"] is False and run["process_exit_code"] == 0, "run state")
        require(run["native_library_sha256"] == LIBRARY_SHA256, "native library identity")
        for k in ("source_sha256", "entry_class_sha256"):
            require(HEX_256.fullmatch(run[k]) and run[k] == probe[k], "paired probe build")
        require(HEX_256.fullmatch(run["sanitized_log_sha256"]), "sanitized log digest")
        rows = run["repeat_trials"]
        fields = trials([{"ordinal": r["ordinal"], "fields": r["fields"]} for r in rows], "ownership")
        require(fields == baseline_calls, "read-only probe changed baseline outputs")
        for row in rows:
            require(set(row) == {"ordinal", "result", "fields", "lifetime_events"}, "unexpected call data")
            require(row["result"] == "array10", "call result")
            expected = [{"kind": kind, "tag": "0x200000a", "relative_start": 112,
                         "requested_size": 112, "overlaps_watch": True, "site": site}
                        for kind, site in [("callback_alloc", "metasec+0x25438c"),
                                           ("cleanup_object", "metasec+0x2550cc")]]
            require(row["lifetime_events"] == expected, "allocation/cleanup ownership sequence")
            obj = row["lifetime_events"][0]
            require(obj["relative_start"] <= probe["watch_relative_start"] and
                    probe["watch_relative_start"] + probe["watch_length"] <=
                    obj["relative_start"] + obj["requested_size"], "watch outside new object")
        if probe_dir:
            log = probe_dir / run["local_run_name"] / "sanitized.log"
            check_local_log(log, run)
            require(local_events(log) == [r["lifetime_events"] for r in rows], "local lifetime events differ")
    if probe_dir:
        require(sha256(probe_dir / probe["callback_source_relative_path"]) == probe["source_sha256"],
                "private callback source identity")
        require(sha256(probe_dir / "callback_lifetime_probe/classes/HookMain.class") ==
                probe["entry_class_sha256"], "private callback class identity")
    analysis = data["static_analysis"]
    require(set(analysis) == {"native_library_sha256", "instructions", "allocator_call_contract"},
            "unexpected static data")
    require(analysis["native_library_sha256"] == LIBRARY_SHA256, "static ELF identity")
    static = {r["image_offset"]: r for r in analysis["instructions"]}
    require(list(static) == ["0x254364", "0x254378", "0x25437c", "0x254380",
                             "0x254384", "0x254388", "0x25438c"], "static sites")
    for pc, mnemonic, operands in [("0x254364", "mov", "x22, x0"),
                                    ("0x25437c", "ldr", "x1, [x0, #0x28]"),
                                    ("0x254388", "blr", "x8"),
                                    ("0x25438c", "mov", "x21, x0")]:
        require((static[pc]["mnemonic"], static[pc]["operands"]) == (mnemonic, operands), "allocator ABI")
    require(data["conclusions"] == {
        "call_count": 8, "per_call_new_allocation_at_watch_start": True,
        "allocation_request_size": 112, "watch_inside_returned_object": True,
        "same_address_cleanup_entry_per_call": True, "deallocation_completion_verified": False,
        "read_only_probe_preserves_prior_abab": True, "persistent_manager_state_attribution_supported": False,
        "manager_extent_verified": False, "direct_dynamic_source_identified": False,
        "fresh_standalone_signer_verified": False,
        "whole_request_native_python_differential_verified": False,
        "online_header_acceptance_verified": False}, "unsupported ownership or completion claim")
    if elf:
        check_elf(elf, analysis)
    return {"read_only_calls_verified": 8, "independent_runs": 2,
            "watched_bytes_in_per_call_object": True, "baseline_abab_preserved": True,
            "local_logs_verified": probe_dir is not None, "elf_bytes_verified": elf is not None,
            "persistent_manager_state_verified": False, "dynamic_source_identified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=Path(__file__).resolve().parents[1] /
                        "evidence/vm9_framesign_watched_region_ownership_20261103.json")
    parser.add_argument("--probe-dir", type=Path)
    parser.add_argument("--elf", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.evidence, args.probe_dir, args.elf), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
