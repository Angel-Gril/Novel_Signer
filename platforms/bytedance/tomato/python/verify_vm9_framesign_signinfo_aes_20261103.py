"""Verify redacted native AES-to-signinfo linkage and within-run operand comparisons."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from verify_vm9_framesign_preimage_composition_20261103 import (
    EXPECTED_INPUT, HEX_256, LIBRARY_SHA256, check_elf, parse_edges, parse_log,
    parse_observations, require, sha256, trials, verify as verify_composition,
)

NAME = "vm9_framesign_signinfo_aes_20261103"
SOURCE = "signinfo_aes_inputs_probe"
PARENT = "vm9_framesign_preimage_composition_20261103.json"
BUFFER = "vm9_framesign_result_buffer_provenance_20261103.json"
STATIC = {
    "0x267350": ("stp", "x8, x0, [sp, #8]"),
    "0x267390": ("bl", "#0x168324"),
    "0x16aa40": ("ldr", "x8, [x8]"),
    "0x16aa44": ("ldr", "x0, [x9]"),
    "0x16aa48": ("blr", "x8"),
    "0x16aa4c": ("ldp", "x5, x1, [x29, #-0x90]"),
    "0x268600": ("ldp", "x9, x1, [x0, #0x10]"),
    "0x268604": ("ldp", "x10, x8, [x0]"),
    "0x268608": ("ldp", "x2, x3, [x0, #0x20]"),
    "0x26860c": ("mov", "x0, x9"),
    "0x268610": ("blr", "x10"),
    "0x268614": ("ldr", "x30, [sp], #0x10"),
    "0x283f34": ("ldr", "x8, [x8]"),
    "0x283f38": ("ldr", "x1, [x8, #0x10]"),
    "0x283f44": ("ldr", "w2, [x8, #0xc]"),
    "0x283f48": ("bl", "#0x2481fc"),
}
CLAIMS = {
    "independent_runs": 2, "calls": 8, "algorithm": "AES-128-CBC", "padding": "PKCS7",
    "plaintext_length": 93, "key_length": 16, "iv_length": 16, "ciphertext_length": 96,
    "signinfo_length": 192, "signinfo_is_lowercase_hex_ciphertext": True,
    "independent_cipher_comparisons": 32, "within_run_operand_comparisons": 12,
    "key_and_iv_stable_within_each_run": True, "plaintext_abab_within_each_run": True,
    "different_plaintext_prefix_length": 89, "common_plaintext_suffix_length": 4,
    "baseline_full_pipeline_preserved": True, "preimage_composition_control_preserved": True,
    "plaintext_composition_identified": False, "key_or_iv_generation_identified": False,
    "alternation_root_cause_identified": False, "general_input_equivalence_verified": False,
    "android_equivalence_verified": False, "complete_standalone_signer_verified": False,
    "online_header_acceptance_verified": False,
}
EVENTS = ("SIGNINFO_AES_SOURCE", "SIGNINFO_PLAINTEXT_COMPONENT", "SIGNINFO_PLAINTEXT_PARSE",
          "SIGNINFO_PLAINTEXT_SHAPE", "SIGNINFO_AES_CALL", "SIGNINFO_AES_COMPARE",
          "SIGNINFO_AES_RETURN", "SIGNINFO_AES_LINK")


def parse_aes(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        prefix = "[HookMain] FRAME_BUFFER_"
        if not line.startswith(prefix):
            continue
        event, _, attributes = line[len(prefix):].partition(" ")
        if event not in EVENTS:
            continue
        # Retain counts only; masked character classes are private discovery data.
        if event == "SIGNINFO_PLAINTEXT_SHAPE":
            attributes, separator, masked = attributes.partition(" masked=")
            require(bool(separator) and len(masked) == 93, "private shape bound")
        row = {"event": event}
        for token in attributes.split():
            key, value = token.split("=", 1)
            require(key not in row, "duplicate AES observation attribute")
            row[key] = (value == "true" if value in ("true", "false") else
                        int(value) if value.isdecimal() else value)
        rows.append(row)
    return rows


def expected_aes() -> list[dict]:
    rows = []
    chain = "metasec+0x16aa4c,metasec+0x267394,metasec+0x284c84,metasec+0x164718,metasec+0x17b014"
    for ordinal in range(1, 5):
        for role, site in (("data", "metasec+0x248238"), ("key", "metasec+0x248388"), ("iv", "unobserved")):
            rows.append({"event": "SIGNINFO_AES_SOURCE", "ordinal": ordinal, "role": role,
                         "constructor_observed": role != "iv", "write_site": site,
                         "source_chain": chain if role != "iv" else "unobserved"})
        for label, length in (("url", 49), ("url_path", 25), ("lid", 10),
                              ("md5_url_hex", 32), ("sha1_url_hex", 40), ("sha256_url_hex", 64)):
            rows.append({"event": "SIGNINFO_PLAINTEXT_COMPONENT", "ordinal": ordinal,
                         "label": label, "length": length, "offsets": "none"})
        rows.extend([
            {"event": "SIGNINFO_PLAINTEXT_PARSE", "ordinal": ordinal, "type": "parse_rejected"},
            {"event": "SIGNINFO_PLAINTEXT_SHAPE", "ordinal": ordinal, "length": 93,
             "printable_ascii": 34 if ordinal % 2 else 29, "zero_bytes": 0},
            {"event": "SIGNINFO_AES_CALL", "ordinal": ordinal, "wrapper": "metasec+0x2685fc",
             "target": "metasec+0x259324", "data_length": 93, "key_length": 16,
             "iv_length": 16, "mode_present": True, "mode_word": 1},
        ])
        for previous in range(1, ordinal):
            same = previous % 2 == ordinal % 2
            rows.append({"event": "SIGNINFO_AES_COMPARE", "ordinal": ordinal, "previous_ordinal": previous,
                         "plaintext_equal": same, "key_equal": True, "iv_equal": True,
                         "ciphertext_equal": same, "changed_plaintext_bytes": 0 if same else 89,
                         "changed_plaintext_spans": "none" if same else "0:89"})
        rows.extend([
            {"event": "SIGNINFO_AES_RETURN", "ordinal": ordinal, "output_length": 96,
             "cbc_pkcs5_matches": True, "ecb_pkcs5_matches": False,
             "cbc_no_padding_matches": False, "ecb_no_padding_matches": False},
            {"event": "SIGNINFO_AES_LINK", "ordinal": ordinal, "constructor_return": "metasec+0x283f4c",
             "aes_calls": 1, "aes_returns": 1, "ciphertext_length": 96, "signinfo_length": 192,
             "lowercase_hex_equal": True, "uppercase_hex_equal": False},
        ])
    return rows


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None) -> dict:
    require(set(data) == {"schema", "evidence_date", "input", "parent_evidence", "probe", "runs",
                         "static_analysis", "conclusions", "raw_values_retained", "operand_digests_retained",
                         "interpretation"}, "evidence keys")
    require(data["schema"] == "vm9-framesign-signinfo-aes-20261103-v1", "schema")
    require(data["evidence_date"] == "2026-11-03" and data["input"] == EXPECTED_INPUT, "date/input")
    require(data["raw_values_retained"] is False and data["operand_digests_retained"] is False, "raw operands/digests retained")
    require(data["conclusions"] == CLAIMS and data["parent_evidence"] == "evidence/" + PARENT, "unsupported claim/parent")
    parent = json.loads((evidence_dir / PARENT).read_text())
    verify_composition(parent, evidence_dir, elf=elf)
    baseline = json.loads((evidence_dir / BUFFER).read_text())["runs"][0]["repeat_trials"]
    expected_trials = trials([{"ordinal": r["ordinal"], "fields": r["fields"]} for r in baseline], "baseline")
    probe = data["probe"]
    require(set(probe) == {"source_relative_path", "source_sha256", "entry_class_sha256", "runner_sha256",
                          "read_only_guest_observation", "synthetic_jni_provider_used", "fresh_rootfs_per_run",
                          "setup_rounds_per_run", "restore_enabled", "independent_cipher_provider",
                          "return_observation_scope", "operand_comparison_scope"}, "probe keys")
    require(probe["source_relative_path"] == SOURCE + "/HookMain.java", "source path")
    for key in ("source_sha256", "entry_class_sha256", "runner_sha256"):
        require(isinstance(probe[key], str) and HEX_256.fullmatch(probe[key]), "probe digest")
    for key in ("read_only_guest_observation", "synthetic_jni_provider_used", "fresh_rootfs_per_run"):
        require(probe[key] is True, "probe scope")
    require(probe["setup_rounds_per_run"] == 1 and probe["restore_enabled"] is False, "setup/restore")
    require(probe["independent_cipher_provider"] == "javax.crypto.Cipher" and
            probe["return_observation_scope"] == "same_dispatcher_stack_pointer_after_callback" and
            probe["operand_comparison_scope"] == "within_each_four_call_run", "observation scope")
    require(isinstance(data["runs"], list) and len(data["runs"]) == 2, "independent run count")
    for index, run in enumerate(data["runs"], 1):
        require(set(run) == {"local_run_name", "source_sha256", "entry_class_sha256", "native_library_sha256",
                             "sanitized_log_sha256", "process_exit_code", "repeat_trials", "aes_observations"}, "run keys")
        require(run["local_run_name"] == SOURCE + f"/run{index}" and run["process_exit_code"] == 0, "run terminal")
        require(run["native_library_sha256"] == LIBRARY_SHA256 and
                isinstance(run["sanitized_log_sha256"], str) and HEX_256.fullmatch(run["sanitized_log_sha256"]), "run identity")
        for key in ("source_sha256", "entry_class_sha256"):
            require(run[key] == probe[key], "paired probe identity")
        require(trials(run["repeat_trials"], "AES control") == expected_trials, "changed output")
        require(run["aes_observations"] == expected_aes(), "AES operands/cipher/hex/input-comparison mismatch")
        if probe_dir:
            log = probe_dir / run["local_run_name"] / "sanitized.log"
            require(sha256(log) == run["sanitized_log_sha256"], "local log identity")
            require(parse_log(log) == baseline, "complete field/constructor/writer/JNI baseline mismatch")
            require(parse_aes(log) == run["aes_observations"], "local AES observations")
            require(parse_observations(log) == parent["runs"][index - 1]["composition_observations"] and
                    parse_edges(log) == parent["runs"][index - 1]["sha256_edges"], "composition/SHA-256 regression")
            meta = json.loads(log.with_name("metadata.json").read_text())
            require(meta["process_exit_code"] == 0 and meta["read_only_guest_probe"] is True and
                    meta["raw_values_retained"] is False, "local scope/terminal")
            for key in ("source_sha256", "entry_class_sha256", "native_library_sha256"):
                require(meta[key] == run[key], "local build identity")
    if probe_dir:
        for relative, key in (("HookMain.java", "source_sha256"), ("classes/HookMain.class", "entry_class_sha256"),
                              ("run_buffer_probe.py", "runner_sha256")):
            require(sha256(probe_dir / SOURCE / relative) == probe[key], "local probe identity")
    static = data["static_analysis"]
    require(set(static) == {"native_library_sha256", "instructions"} and
            static["native_library_sha256"] == LIBRARY_SHA256, "static identity")
    require([r["image_offset"] for r in static["instructions"]] == list(STATIC), "static sites")
    for row in static["instructions"]:
        require(set(row) == {"image_offset", "file_offset", "bytes_hex", "mnemonic", "operands"} and
                (row["mnemonic"], row["operands"]) == STATIC[row["image_offset"]], "static contract")
    if elf:
        check_elf(elf, static)
    return {"calls_verified": 8, "independent_cipher_comparisons": 32, "operand_pair_comparisons": 12,
            "algorithm": "AES-128-CBC", "padding": "PKCS7", "plaintext_length": 93,
            "changed_prefix_length": 89, "common_suffix_length": 4, "signinfo_lowercase_hex_verified": True,
            "baseline_preserved": True, "local_logs_verified": probe_dir is not None,
            "elf_bytes_verified": elf is not None, "alternation_root_cause_identified": False,
            "standalone_signer_verified": False}


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
