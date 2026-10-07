"""Compare fresh root VM caller spill after the native +0x168324 prelude.

The native and Python controls are run independently. Native backing words are
used only as expected observations; they are never copied into the Python
pages. The verifier records only 32-slot equality; subsequent constructor
completion and returned object state require the outer-graph differential.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

import verify_vm9_outer_constructor_boundary as boundary
import verify_vm9_outer_signer_native as native
import verify_vm9_signer_objects as oracle
import verify_vm9_worker_allocator as worker

LIBRARY = Path(r"C:\AI\6\libmetasec_ml_71332.so")
LIBC = Path(r"C:\AI\6\_vlibc.so")
PROFILES = {"absent": None, "sdk_30": b"30"}
BASES = (0x122C0000, 0x775C205000)


def _words_from_hex_bytes(raw: str) -> list[int]:
    data = bytes.fromhex(raw)
    if len(data) != 0x100:
        raise AssertionError(f"root backing span is {len(data):#x}, expected 0x100")
    return [int.from_bytes(data[i * 8:(i + 1) * 8], "little") for i in range(32)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, default=LIBRARY)
    ap.add_argument("--libc", type=Path, default=LIBC)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == worker.LIBC_SHA256
    os.environ["TOMATO_LIBMETASEC"] = str(args.library.resolve())
    import vm_full

    rows = []
    for image in BASES:
        for label, value in PROFILES.items():
            native_trace: list[dict] = []
            native_result = native.case(args.library, args.libc, image, value,
                                        trace=native_trace)
            native_prelude = [item for item in native_trace
                              if item.get("offset") == "0x1684f0"
                              and item.get("register_backing_words_after_prelude")]
            if len(native_prelude) != 1:
                raise AssertionError("native root prelude boundary count changed")
            vm_runs: list[dict] = []
            previous_vm = vm_full.VM
            class TraceVM(previous_vm):
                def run(self):
                    start = self.pc - vm_full.B
                    try:
                        return super().run()
                    finally:
                        vm_runs.append({
                            "start_offset": hex(start),
                            "stop_offset": hex(self.pc - vm_full.B),
                            "steps": self.steps,
                            "registers_0_8": [hex(value) for value in self.R[:9]],
                            "modeled_callbacks": list(getattr(self.native_hook, "modeled", [])),
                        })
            vm_full.VM = TraceVM
            try:
                python_result = boundary.case(
                    args.library, args.libc, image, label, value, vm_full,
                    apply_logger_model=False)
            finally:
                vm_full.VM = previous_vm
            python_entries = python_result.get("python_vm_entries", [])
            if len(python_entries) != 1:
                raise AssertionError("Python root VM entry count changed")
            native_words = [int(word, 16) for word in
                            native_prelude[0]["register_backing_words_after_prelude"]]
            python_words = _words_from_hex_bytes(
                python_entries[0]["register_backing_bytes_0x100"])
            mismatches = [index for index, (left, right) in
                          enumerate(zip(native_words, python_words)) if left != right]
            native_backing = bytes.fromhex(
                python_entries[0]["register_backing_bytes_0x100"])
            row = {
                "image_base": hex(image),
                "property_profile": label,
                "fresh_elf_inputs": True,
                "native_input_snapshot_used": False,
                "native_prelude_offset": "0x1684f0",
                "python_vm_entry_offset": "0x991c0",
                "native_word_count": len(native_words),
                "python_word_count": len(python_words),
                "mismatch_indices": mismatches,
                "all_32_backing_words_match": not mismatches,
                "backing_span_sha256": hashlib.sha256(native_backing).hexdigest(),
                "python_logger_callback_reached": bool(python_result.get("logger_calls")),
                "python_descriptor_trampoline_reached": bool(
                    python_result.get("descriptor_trampoline")),
                "python_vm_runs": vm_runs,
                "native_outer_getter_returned": native_result[
                    "native_outer_getter_returned"],
                "fresh_medusa_output_verified": False,
            }
            if mismatches:
                raise AssertionError(f"{hex(image)} {label}: backing mismatch {mismatches}")
            rows.append(row)
            print("root prelude", hex(image), label, "PASS", flush=True)

    report = {
        "schema": "vm9-root-prelude-backing-match-v1",
        "sample_sha256": oracle.LIBRARY_SHA256,
        "libc_sha256": worker.LIBC_SHA256,
        "controls": len(rows),
        "cases": rows,
        "native_prelude_path": ["0x257084", "0x257308", "0x168324", "0x1684f0"],
        "python_seed_path": ["construct_initialized_root", "construct_root_caller", "0x991c0"],
        "native_input_snapshot_used": False,
        "caller_spill_generated_from_current_objects": True,
        "all_controls_32_word_match": all(row["all_32_backing_words_match"] for row in rows),
        "python_logger_callback_semantics_complete": False,
        "descriptor_trampoline_recovered": False,
        "fresh_medusa_output_verified": False,
        "complete_python_medusa": False,
        "limitations": [
            "This proves only the 32-slot caller spill at the generic VM prelude boundary.",
            "Exact spill does not prove complete outer state or a signer output; see the fresh outer-graph verifier for the current return status.",
            "No native memory snapshot is copied into Python and no online signature or Rust result is implied.",
        ],
    }
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print("root prelude", len(rows), "fresh controls PASS; logger/callback remains open", flush=True)


if __name__ == "__main__":
    main()
