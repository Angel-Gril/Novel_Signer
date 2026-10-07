"""Compare returned fresh Python outer graph against an independent native run.

Python is executed first from ELF/TLS/services; native terminal bytes are only
expected observations, never inputs. Public reports contain counts, offsets,
hashes and equality. Default record semantics are compared separately from
unused libc++ string padding and remaining native global effects.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path

from vm9_allocator import RefillUnsupported, _read_span, _write_span
import verify_vm9_outer_constructor_boundary as boundary
import verify_vm9_outer_signer_native as native
import verify_vm9_signer_objects as oracle
import verify_vm9_worker_allocator as worker
import verify_vm9_root_allocator as root_fixture
import vm9_outer_constructor as outer

BASES = (0x122C0000, 0x775C205000)
GLOBALS = (
    ("outer_slot_and_guard", 0x3D15D8, 16),
    ("refresh_lazy_globals", 0x3E08E8, 0x28),
    ("logger_sink", 0x382600, 0x40),
    ("publication_mutex_slot", 0x3E1E08, 8),
    ("publication_once_and_chain", 0x3E1DF8, 0x10),
    ("logger_record_singleton", 0x3E1B08, 0x18),
)


def _live_allocations(events):
    live = {}
    index = 0
    for event in events:
        if event[0] == "alloc":
            _, size, pointer, *_ = event
            live[pointer] = (index, size)
            index += 1
        elif event[0] == "free":
            live.pop(event[1], None)
    return live


def _snapshot(read, *, image, wrapper, allocation_sequence, allocator_events):
    def word(address):
        return int.from_bytes(read(address, 8), "little")
    outer = word(wrapper)
    internal = word(outer + 8)
    children = [word(outer + delta) for delta in (0x18, 0x20)]
    roles = {
        "singleton_wrapper": (wrapper, 16),
        "singleton_count": (word(wrapper + 8), 4),
        "outer_root": (outer, 40),
        "internal_root": (internal, 264),
        "internal_root_count": (word(outer + 0x10), 4),
        "internal_state": (word(internal + 0x100), 152),
    }
    for index, child in enumerate(children):
        pair = word(child + 0x20)
        handler = word(pair + 8)
        roles.update({
            f"child_{index}": (child, 40),
            f"child_{index}_state": (word(child + 8), 152),
            f"child_{index}_count": (word(child + 0x18), 4),
            f"child_{index}_callback_pair": (pair, 16),
            f"child_{index}_handler": (handler, 128 if index == 0 else 232),
            f"child_{index}_configuration_count": (word(handler + 0x48), 4),
        })
    mutex = word(image + 0x3E1E08)
    if mutex:
        roles["publication_recursive_mutex"] = (mutex, 40)
    record_container = word(image + 0x3E1B08)
    record = word(record_container + 0x28)
    roles["logger_record_container"] = (record_container, 64)
    short_strings = []
    for index in range(4):
        address = record + index * 24
        raw = read(address, 24)
        if raw[0] & 1:
            raise AssertionError("unexpected long string in default native record")
        length = raw[0] >> 1
        assert length <= 22 and raw[length + 1] == 0
        short_strings.append(dict(length=length,
                                  owned=raw[:length + 2],
                                  padding=raw[length + 2:]))
    live = _live_allocations(allocator_events)
    return {
        "short_strings": short_strings,
        "roles": {label: (address, read(address, size))
                  for label, (address, size) in roles.items()},
        "live": {index: (size, read(pointer, size))
                 for pointer, (index, size) in live.items()},
        "globals": {label: read(image + offset, size)
                    for label, offset, size in GLOBALS},
        "allocations": [item[:2] for item in allocation_sequence],
        "remaining_globals": {
            "constructor_hash_input_and_result": read(image + 0x3D1994, 8),
            "constructor_elapsed": read(image + 0x3E07C0, 8),
            "record_lazy_globals": read(image + 0x3E19D0, 0x110),
        },
    }


def _comparison(expected, actual):
    offsets = [index for index, (left, right) in enumerate(zip(expected, actual))
               if left != right]
    return dict(size=len(expected), equal=expected == actual,
                mismatch_offsets=[hex(index) for index in offsets],
                native_sha256=hashlib.sha256(expected).hexdigest(),
                python_sha256=hashlib.sha256(actual).hexdigest())


def case(library, libc, image, label, value, vm_module):
    snapshots = {}
    def python_terminal(pages, *, result, singleton_wrapper,
                        allocation_sequence, free_sequence, allocator_events):
        snapshots["python"] = _snapshot(
            lambda address, size: _read_span(pages, address, size),
            image=image, wrapper=singleton_wrapper,
            allocation_sequence=allocation_sequence, allocator_events=allocator_events)
    # Do not move native before this call: independence is part of the contract.
    python_result = boundary.case(library, libc, image, label, value, vm_module,
                                  terminal_observer=python_terminal)
    assert python_result["python_constructor_returned"]
    assert not python_result["rejected_at_boundary"] and python_result["rejection"] is None
    def native_terminal(cpu, *, wrapper, root, allocation_sequence,
                        free_sequence, allocator_events):
        snapshots["native"] = _snapshot(
            lambda address, size: bytes(cpu.mem_read(address, size)),
            image=image, wrapper=wrapper,
            allocation_sequence=allocation_sequence, allocator_events=allocator_events)
    native_result = native.case(library, libc, image, value,
                                terminal_observer=native_terminal)
    actual, expected = snapshots["python"], snapshots["native"]
    assert actual["allocations"] == expected["allocations"]
    assert [int(pointer, 16) for pointer in python_result["free_calls"]] == native_result["free_sequence"]
    assert set(actual["roles"]) == set(expected["roles"])
    graph = {}
    for role, (address, data) in actual["roles"].items():
        native_address, native_data = expected["roles"][role]
        row = _comparison(native_data, data)
        row["address_equal"] = address == native_address
        graph[role] = row
    assert all(item["equal"] and item["address_equal"] for item in graph.values())
    globals_result = {label: _comparison(expected["globals"][label], data)
                      for label, data in actual["globals"].items()}
    for global_label in ("outer_slot_and_guard", "refresh_lazy_globals", "logger_sink", "publication_mutex_slot"):
        assert globals_result[global_label]["equal"], global_label
    strings = []
    for index, (left, right) in enumerate(zip(expected["short_strings"], actual["short_strings"])):
        item = dict(index=index, length=left["length"],
                    owned_bytes=_comparison(left["owned"], right["owned"]),
                    unused_padding_equal=left["padding"] == right["padding"])
        assert left["length"] == right["length"] and item["owned_bytes"]["equal"]
        strings.append(item)
    assert all(item["equal"] for item in globals_result.values())
    assert set(actual["live"]) == set(expected["live"])
    live_mismatches = []
    for index, (size, data) in actual["live"].items():
        expected_size, native_data = expected["live"][index]
        assert size == expected_size
        if data != native_data:
            live_mismatches.append(dict(allocation_index=index, **_comparison(native_data, data)))
    wrappers = Counter(offset for run in python_result["python_vm_runs"]
                       if run["entry_offset"] == "0x991c0"
                       for offset in run["callback_wrapper_offsets"])
    root_runs = [run for run in python_result["python_vm_runs"] if run["entry_offset"] == "0x991c0"]
    assert len(root_runs) == 1 and root_runs[0]["stop_offset"] == "0x99f04"
    return dict(image_base=hex(image), property_profile=label,
                python_constructor_returned=True, native_outer_getter_returned=True,
                native_warm_getter_reuses_wrapper=native_result["warm_getter_reuses_wrapper_without_allocator_or_provider_effects"],
                python_root_vm_runs=root_runs,
                root_callback_wrapper_counts=dict(wrappers),
                logger_vm_callback_count=len(python_result["logger_calls"]),
                long_descriptor_trampoline_count=len(python_result["descriptor_trampoline"]),
                logger_observation_count=len(python_result["logger_observations"]),
                allocation_count=len(actual["allocations"]), free_count=len(python_result["free_calls"]),
                allocation_sequence_equal=True, free_sequence_equal=True,
                returned_core_graph_equal=True, core_object_spans=graph,
                global_spans=globals_result,
                additional_global_observations={
                    label: _comparison(expected["remaining_globals"][label], data)
                    for label, data in actual["remaining_globals"].items()},
                live_allocation_count=len(actual["live"]),
                live_allocation_mismatches=live_mismatches,
                logger_record_strings=strings,
                default_logger_record_semantics_equal=True,
                complete_native_outer_state_equal=False,
                native_input_snapshot_used=False, python_executed_before_native=True)


def negative_controls(library, libc):
    rows = []
    for label in ("nonzero_outer", "long_format", "existing_record", "busy_once"):
        image = BASES[0]
        pages, _, _ = root_fixture.fresh(library, libc, image, None)
        root_address = 0x70006000
        _write_span(pages, root_address, bytes(40))
        if label == "nonzero_outer":
            _write_span(pages, root_address, (1).to_bytes(4, "little"))
        elif label == "long_format":
            _write_span(pages, image + 0x6FA4A, b"A" * 24 + b"\0")
        elif label == "existing_record":
            _write_span(pages, image + 0x3E1B08, (1).to_bytes(8, "little"))
        else:
            _write_span(pages, image + 0x3E1E00, (1).to_bytes(8, "little"))
        before = {key: bytes(value) for key, value in pages.items()}
        try:
            outer._publish_default_logger_record(pages, image_base=image,
                outer_root_address=root_address, container=0x70006100,
                record=0x70006200)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError(f"unsupported record control accepted: {label}")
        assert {key: bytes(value) for key, value in pages.items()} == before
        rows.append(dict(control=label, rejected=True, pages_unchanged=True))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, default=boundary.LIBRARY)
    parser.add_argument("--libc", type=Path, default=boundary.LIBC)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == worker.LIBC_SHA256
    os.environ["TOMATO_LIBMETASEC"] = str(args.library.resolve())
    import vm_full
    rows = []
    for image in BASES:
        for label, value in boundary.PROFILES.items():
            row = case(args.library, args.libc, image, label, value, vm_full)
            rows.append(row)
            print("outer graph", hex(image), label, "core PASS; live differences",
                  [item["allocation_index"] for item in row["live_allocation_mismatches"]], flush=True)
    report = dict(schema="vm9-outer-graph-fresh-differential-v1", evidence_date="2026-10-07",
                  sample_sha256=oracle.LIBRARY_SHA256, libc_sha256=worker.LIBC_SHA256,
                  controls=len(rows), cases=rows,
                  negative_controls=negative_controls(args.library, args.libc),
                  supersedes_current_boundary_claim="vm9_outer_constructor_boundary_20261006.json",
                  returned_core_graph_equal=all(row["returned_core_graph_equal"] for row in rows),
                  default_logger_record_semantics_equal=all(row["default_logger_record_semantics_equal"] for row in rows),
                  complete_native_outer_state_equal=False,
                  native_input_snapshot_used=False, actual_os_threads_created=False,
                  explicit_virtual_os_and_jni=True, jvm_used=False,
                  fresh_input_signer_output_verified=False, complete_python_medusa=False,
                  current_online_header_matrix_verified=False,
                  limitations=[
                      "Core graph and default logger record semantics match; all native globals and stack effects are not covered.",
                      "JSON parser/formatter temporary buffer contents still reproduce the measured allocation ledger only.",
                      "Unused native short-string padding contains stack residue; Python generates zero padding and does not copy it.",
                      "Native JNI publication/cleanup runs in the native control; no Python publication equivalence is claimed.",
                      "Synthetic OS, clocks and virtual threads are explicit; no physical Android thread scheduling is tested.",
                      "A constructor return is not a fresh request signature or an online acceptance result."])
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("outer core graph/default record", len(rows), "PASS; full native state/signing remain open", flush=True)


if __name__ == "__main__":
    main()
