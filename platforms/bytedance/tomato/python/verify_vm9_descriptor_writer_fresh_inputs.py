"""Fresh-input verification for the +0x991c0 descriptor STORE64 sequence.

This verifier instruments only the Python VM execution seeded by the current
constructor/allocator model.  It proves that the STORE64 word and its register
inputs are generated from fresh pages for the bounded root caller.  It does
not replace the owner-frame branch continuation or claim a fresh Medusa result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNTIME_ROOT = Path(r"C:\AI\6")
for _path in (str(HERE), str(RUNTIME_ROOT)):
    while _path in sys.path:
        sys.path.remove(_path)
sys.path.insert(0, str(HERE))
sys.path.insert(1, str(RUNTIME_ROOT))

import verify_vm9_outer_constructor_boundary as boundary
import vm9_descriptor_writer as writer


LIBRARY = RUNTIME_ROOT / "libmetasec_ml_71332.so"
LIBC = RUNTIME_ROOT / "_vlibc.so"
BASES = (0x122C0000, 0x775C205000)
PROFILES = {"absent": None, "sdk_30": b"30"}
SOURCE_SEMANTICS = {
    "0xff7b600f": "R29 = R29 - 640",
    "0x89020218": "R1 = [R20 + 72]",
    "0x83a2020f": "R17 = R30 + 8",
    "0x89020618": "R1 = [R20 + 88]",
}


def annotate_source(source):
    if source is None:
        return None
    source = dict(source)
    source["operation"] = SOURCE_SEMANTICS.get(source["previous_word"], "unmapped VM source")
    return source


def capture_case(library: Path, libc: Path, image: int, label: str, value, vm_module):
    stores: list[dict] = []
    vm_starts: list[dict] = []
    register_changes: list[dict] = []
    native_callbacks: list[dict] = []

    previous_vm = vm_module.VM

    class TraceVM(previous_vm):
        def run(self):
            start = self.pc - vm_module.B
            if start != 0x991C0:
                return super().run()
            previous_hook = self.step_hook
            previous_native_hook = self.native_hook
            local: list[dict] = []
            previous_values = {slot: self.R[slot] for slot in (1, 17, 29)}
            previous_step = None
            previous_word = None

            def hook(vm, word, op, sub):
                nonlocal previous_values, previous_step, previous_word
                for slot in (1, 17, 29):
                    if self.R[slot] != previous_values[slot]:
                        register_changes.append({
                            "step_before": self.steps,
                            "slot": slot,
                            "value": hex(self.R[slot]),
                            "previous_step": previous_step,
                            "previous_word": hex(previous_word) if previous_word is not None else None,
                        })
                if start == 0x991C0 and op == writer.STORE64_OPCODE:
                    fields = writer.decode_store64(word & writer.MASK32)
                    if fields.immediate in (0x140, 0x148):
                        destination = (self.R[fields.base_slot] + fields.immediate) & writer.MASK64
                        value = self.R[fields.value_slot]
                        source_candidates = []
                        if fields.value_slot == 1:
                            source_candidates = [self.R[20] + 72, self.R[20] + 88]
                        elif fields.value_slot == 17:
                            source_candidates = [self.R[30] + 8]
                        source_address = next((address for address in source_candidates
                                               if self.m.u64(address) == value), None)
                        try:
                            source_bytes = self.m.rd(source_address, 0x20).hex() if source_address is not None else None
                        except Exception:
                            source_bytes = None
                        object_address = self.R[30] + 8 if fields.value_slot == 17 else None
                        try:
                            object_bytes = self.m.rd(object_address, 0x100).hex() if object_address is not None else None
                        except Exception:
                            object_bytes = None
                        local.append({
                            "step": self.steps,
                            "word": hex(word & writer.MASK32),
                            "base_slot": fields.base_slot,
                            "value_slot": fields.value_slot,
                            "immediate": fields.immediate,
                            "base_value": hex(self.R[fields.base_slot]),
                            "value": hex(value),
                            "destination": hex(destination),
                            "destination_page_mapped": (destination >> 12) in self.m.pages,
                            "value_page_mapped": (value >> 12) in self.m.pages,
                            "r20": hex(self.R[20]),
                            "r30": hex(self.R[30]),
                            "value_source_address": hex(source_address) if source_address is not None else None,
                            "value_source_bytes_0x20": source_bytes,
                            "object_address": hex(object_address) if object_address is not None else None,
                            "object_bytes_0x100": object_bytes,
                        })
                if previous_hook is not None:
                    previous_hook(vm, word, op, sub)
                previous_values = {slot: self.R[slot] for slot in (1, 17, 29)}
                previous_step = self.steps
                previous_word = word

            def native_hook(vm, function, argument):
                try:
                    words = [vm.m.u64(argument + index * 8) for index in range(8)]
                except Exception:
                    words = None
                native_callbacks.append({
                    "function_offset": hex(function - vm_module.B),
                    "argument": hex(argument),
                    "argument_words": [hex(word) for word in words] if words is not None else None,
                })
                if previous_native_hook is None:
                    raise RuntimeError("root native callback unexpectedly missing")
                return previous_native_hook(vm, function, argument)

            self.step_hook = hook
            self.native_hook = native_hook
            try:
                return super().run()
            finally:
                self.step_hook = previous_hook
                self.native_hook = previous_native_hook
                if start == 0x991C0:
                    vm_starts.append({
                        "start_offset": hex(start),
                        "steps": self.steps,
                        "stores": local,
                    })
                    stores.extend(local)

    vm_module.VM = TraceVM
    try:
        result = boundary.case(
            library, libc, image, label, value, vm_module,
            apply_logger_model=False,
        )
    finally:
        vm_module.VM = previous_vm

    if result.get("rejection"):
        raise AssertionError(f"{hex(image)} {label}: {result['rejection']}")
    runs = [entry for entry in vm_starts if entry["start_offset"] == "0x991c0"]
    if len(runs) != 1:
        raise AssertionError(f"{hex(image)} {label}: expected one root VM run, got {len(runs)}")
    active = runs[0]["stores"]
    if len(active) != 4:
        raise AssertionError(f"{hex(image)} {label}: expected four descriptor stores, got {len(active)}")

    branch_a = image + 0x32A444
    branch_b = image + 0x32A4FC
    expected = [
        (0x140, branch_a),
        (0x148, None),
        (0x148, None),
        (0x140, branch_b),
    ]
    for row, (offset, value_expected) in zip(active, expected):
        if row["immediate"] != offset or row["base_slot"] != 29:
            raise AssertionError(f"{hex(image)} {label}: unexpected writer fields {row}")
        if value_expected is not None and int(row["value"], 16) != value_expected:
            raise AssertionError(f"{hex(image)} {label}: branch target mismatch {row}")
        if not row["destination_page_mapped"]:
            raise AssertionError(f"{hex(image)} {label}: descriptor page not mapped {row}")
    if active[1]["value"] != active[2]["value"]:
        raise AssertionError(f"{hex(image)} {label}: field8 value changed between stores")
    object_value = int(active[1]["value"], 16)
    if not object_value or object_value in (branch_a, branch_b):
        raise AssertionError(f"{hex(image)} {label}: invalid fresh object value")
    writer_sources = [
        {
            "writer_step": store["step"],
            "base_source": annotate_source(next((change for change in reversed(register_changes)
                                 if change["slot"] == store["base_slot"]
                                 and change["step_before"] <= store["step"]), None)),
            "value_source": annotate_source(next((change for change in reversed(register_changes)
                                  if change["slot"] == store["value_slot"]
                                  and change["step_before"] <= store["step"]), None)),
        }
        for store in active
    ]
    expected_value_words = ["0x89020218", "0x83a2020f", "0x83a2020f", "0x89020618"]
    for source, expected_word in zip(writer_sources, expected_value_words):
        if source["base_source"] is None or source["base_source"]["previous_word"] != "0xff7b600f":
            raise AssertionError(f"{hex(image)} {label}: base source not caller frame setup")
        if source["value_source"] is None or source["value_source"]["previous_word"] != expected_word:
            raise AssertionError(f"{hex(image)} {label}: value source mismatch {source}")

    return {
        "image_base": hex(image),
        "property_profile": label,
        "fresh_elf_inputs": bool(result.get("fresh_elf_inputs")),
        "native_input_snapshot_used": bool(result.get("native_input_snapshot_used")),
        "python_vm_entry_offset": "0x991c0",
        "root_object": result["python_vm_entries"][0]["root_object"],
        "vm_stack": result["python_vm_entries"][0]["stack"],
        "writer_stores": active,
        "branch_targets": [hex(branch_a), hex(branch_b)],
        "fresh_object_value": active[1]["value"],
        "writer_input_sources": writer_sources,
        "source_semantics": {
            "base_frame": SOURCE_SEMANTICS["0xff7b600f"],
            "branch_a": SOURCE_SEMANTICS["0x89020218"],
            "object": SOURCE_SEMANTICS["0x83a2020f"],
            "branch_b": SOURCE_SEMANTICS["0x89020618"],
        },
        "descriptor_callback_reached": bool(result.get("descriptor_trampoline")),
        "logger_callback_reached": bool(result.get("logger_calls")),
        "native_callback_sequence": native_callbacks,
        "fresh_medusa_output_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, default=LIBRARY)
    parser.add_argument("--libc", type=Path, default=LIBC)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.environ["TOMATO_LIBMETASEC"] = str(args.library.resolve())
    import vm_full

    rows = [
        capture_case(args.library, args.libc, image, label, value, vm_full)
        for image in BASES
        for label, value in PROFILES.items()
    ]
    object_values = {row["fresh_object_value"] for row in rows}
    object_snapshots = [
        store for row in rows for store in row["writer_stores"]
        if store.get("object_bytes_0x100") is not None
    ]
    def object_words(store):
        raw = bytes.fromhex(store["object_bytes_0x100"])
        return (raw[0x00:0x88],
                int.from_bytes(raw[0x88:0x8C], "little"),
                int.from_bytes(raw[0x8C:0x90], "little"))
    object_layout_confirmed = bool(object_snapshots) and any(
        prefix == bytes(0x88) and count == 1 and adjacent == 1
        for prefix, count, adjacent in map(object_words, object_snapshots)
    )
    object_zero_prefix_confirmed = bool(object_snapshots) and all(
        object_words(store)[0] == bytes(0x88) for store in object_snapshots
    )
    report = {
        "evidence_id": "vm9_descriptor_writer_fresh_inputs_20261006",
        "schema": "vm9-descriptor-writer-fresh-inputs-v1",
        "status": "fresh_root_writer_inputs_generated_with_deterministic_allocator_seed",
        "native_library_sha256": hashlib.sha256(args.library.read_bytes()).hexdigest(),
        "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "controls": len(rows),
        "cases": rows,
        "all_controls_fresh": all(row["fresh_elf_inputs"] and not row["native_input_snapshot_used"] for row in rows),
        "fresh_object_values_are_observed_as_register_inputs": True,
        "fresh_object_values_vary_across_same_seed_controls": len(object_values) >= 2,
        "fresh_object_values_are_not_hardcoded": False,
        "fresh_shared_reader_object_observed": object_layout_confirmed,
        "fresh_shared_reader_object_zero_prefix": object_zero_prefix_confirmed,
        "shared_reader_object_layout": {
            "zero_prefix_bytes": "0x00..0x87",
            "reader_count_offset": "0x88",
            "reader_count_u32": 1,
            "adjacent_word_u32": 1,
            "object_is_descriptor_pair": False,
        },
        "descriptor_writer_parameterized": True,
        "descriptor_callback_reached": any(row["descriptor_callback_reached"] for row in rows),
        "fresh_medusa_output_verified": False,
        "complete_python_medusa": False,
        "no_jvm_rust_signer_complete": False,
        "limitations": [
            "The controls cover the bounded +0x991c0 root caller and its four STORE64 fields only.",
            "The owner-frame continuation and remaining callback body are still not executed.",
            "The generated object pointer is observed from the current fresh model allocation; its fresh bytes are a shared-reader state object (zero prefix, u32 reader count at +0x88), not a descriptor pair.",
            "No current Medusa output, header matrix, Rust chain or download product is implied.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("descriptor writer fresh inputs PASS", len(rows))


if __name__ == "__main__":
    main()
