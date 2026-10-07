"""Fresh outer finalization: u32 hash, lazy formatter globals and JNI services.

Native final state remains expected-only. Component controls execute the actual
hash instructions with varied u32 inputs and poisoned caller storage. Integration
controls also check publication at its real place in the allocator transaction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from unicorn.arm64_const import UC_ARM64_REG_X8, UC_ARM64_REG_X11, UC_ARM64_REG_X29
from vm9_allocator import RefillUnsupported, _read_span, _write_span
import verify_vm9_outer_graph_fresh_20261007 as graph
import vm9_outer_constructor as outer


def hash_controls(library):
    rows = []
    for image in graph.BASES:
        for index, counter in enumerate((0, 1, 0x12345678, 0x80000000, 0xFFFFFFFF)):
            pages = graph.oracle.image_pages(library, image)
            pages.update(graph.oracle.fresh_pages())
            storage = graph.oracle.GUEST + (0x1FFC if index & 1 else 0x1800)
            _write_span(pages, image + 0x3D1994, counter.to_bytes(4, "little"))
            _write_span(pages, storage, b"\xA5" * 8)
            initial = {key: bytearray(value) for key, value in pages.items()}
            result = outer.update_outer_constructor_hash(pages, image_base=image,
                                                         caller_storage_address=storage)
            expected = {(image + 0x3D1994, 8): None, (storage, 8): None}
            _, _, allocations, ledger = graph.oracle.native(
                library, image, 0x27CDF0, [], initial, stop_offset=0x27CE48,
                extra_registers={UC_ARM64_REG_X8: 0, UC_ARM64_REG_X11: image + 0x3D1000,
                                 UC_ARM64_REG_X29: storage + 0x10},
                observed_memory=expected, instruction_limit=1000)
            assert not allocations and not ledger
            assert all(data == _read_span(pages, address, width)
                       for (address, width), data in expected.items())
            assert _read_span(pages, storage, 8) == counter.to_bytes(8, "little")
            rows.append(dict(image_base=hex(image), counter=counter,
                output_u32=result, caller_zero_extension_equal=True,
                output_equal=True, synthetic_caller_crosses_page=bool(index & 1),
                original_elf_instructions_executed=True,
                native_input_snapshot_used=False))
    return rows


def negative_hash_controls(library):
    image = graph.BASES[0]
    pages = graph.oracle.image_pages(library, image)
    original = {key: bytes(value) for key, value in pages.items()}
    try:
        outer.update_outer_constructor_hash(pages, image_base=image,
                                            caller_storage_address=0x64000000)
    except ValueError as exc:
        assert "missing checkpoint page" in str(exc)
    else:
        raise AssertionError("unmapped caller hash storage was accepted")
    assert {key: bytes(value) for key, value in pages.items()} == original
    return [dict(control="unmapped_caller_storage", rejected=True, pages_unchanged=True)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, default=graph.boundary.LIBRARY)
    parser.add_argument("--libc", type=Path, default=graph.boundary.LIBC)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == graph.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == graph.worker.LIBC_SHA256
    os.environ["TOMATO_LIBMETASEC"] = str(args.library.resolve())
    import vm_full
    component_rows = hash_controls(args.library)
    negatives = negative_hash_controls(args.library) + graph.negative_controls(args.library, args.libc)
    print("hash native components", len(component_rows), "PASS", flush=True)
    rows = []
    profiles = [(label, value, None) for label, value in graph.boundary.PROFILES.items()]
    profiles.append(("absent_changed_counter", None, 0x12345678))
    for image in graph.BASES:
        for label, value, counter in profiles:
            row = graph.case(args.library, args.libc, image, label, value, vm_full,
                             constructor_counter=counter, apply_publication=True)
            assert all(item["equal"] for item in row["additional_global_observations"].values())
            assert [item["allocation_index"] for item in row["live_allocation_mismatches"]] == [308]
            lengths = [item["length"] for item in row["logger_record_strings"]]
            padding = {index * 24 + offset for index, length in enumerate(lengths)
                       for offset in range(length + 2, 24)}
            assert all(int(offset, 16) in padding for offset in row["live_allocation_mismatches"][0]["mismatch_offsets"])
            rows.append(row)
            print("outer finalization", hex(image), label, "PASS", flush=True)
    report = dict(schema="vm9-outer-finalize-fresh-differential-v1", evidence_date="2026-10-07",
        sample_sha256=graph.oracle.LIBRARY_SHA256, libc_sha256=graph.worker.LIBC_SHA256,
        integration_controls=len(rows), cases=rows, hash_component_controls=component_rows,
        negative_controls=negatives,
        constructor_hash_generated_from_current_u32=True, caller_high_word_is_zero_extended=True,
        formatter_lazy_constants_and_guards_equal=True,
        publication_and_jni_service_ledger_equal=True,
        actual_jvm_used=False, actual_os_threads_created=False,
        native_input_snapshot_used=False, complete_native_outer_state_equal=False,
        fresh_input_signer_output_verified=False, complete_python_medusa=False,
        current_online_header_matrix_verified=False,
        supersedes_additional_global_mismatches="vm9_outer_graph_fresh_20261007.json",
        limitations=[
            "JNI attachment and Java dispatch/reference results are explicit services, not a real JVM.",
            "JSON parser/formatter temporary buffer contents are still allocator-ledger-only.",
            "Native short-string padding is not copied; Python zeroes unused bytes.",
            "All native writable globals, physical caller stack and concurrent thread execution are not covered.",
            "This verifies constructor finalization, not a fresh request signature or online acceptance."])
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("outer finalization", len(rows), "PASS; fresh request signing remains open", flush=True)


if __name__ == "__main__":
    main()
