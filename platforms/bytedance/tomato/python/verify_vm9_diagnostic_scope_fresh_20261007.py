"""Fresh cold/warm diagnostic scopes versus original image and matching libc."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import verify_vm9_signer_objects as oracle
import verify_vm9_worker_allocator as worker
import vm9_diagnostics as model
from vm9_allocator import RefillUnsupported, _read_span, _write_span


def w(pages, address, value, width=8):
    _write_span(pages, address, value.to_bytes(width, "little"))


def fixture(library, image, label):
    pages = oracle.image_pages(library, image)
    pages.update(oracle.fresh_pages())
    tid = 77
    w(pages, oracle.GUEST + 0xD008, oracle.GUEST + 0xC000)
    w(pages, oracle.GUEST + 0xC010, tid, 4)
    obj = oracle.GUEST + (0x1FF8 if label == "cold_cross_page" else 0x1800)
    word = {"cold_zero": 0, "cold_last": 0xFF0, "cold_high_bits": 0xFFFF00000000A55F,
            "cold_cross_page": 0x1330}.get(label, 0x550)
    if label.startswith("warm_"):
        global_lock, table, entry = (oracle.GUEST + offset for offset in (0x2800, 0x3000, 0x3900))
        w(pages, image + model.GUARD, 0x10000000101)
        w(pages, image + model.GLOBAL_LOCK, global_lock)
        w(pages, global_lock, image + 0x34C738)
        _write_span(pages, global_lock + 8, bytes(40))
        if label != "warm_no_table":
            w(pages, image + model.TABLE, table)
            _write_span(pages, table, bytes(2048))
            if label != "warm_missing_entry":
                w(pages, table + ((word >> 4) & 255) * 8, entry)
                w(pages, entry, image + 0x34C738)
                _write_span(pages, entry + 8, bytes(40))
                state = 0x4000
                if label in ("warm_nested", "warm_saturated"):
                    state = 0x5FFD if label == "warm_saturated" else 0x4005
                    w(pages, entry + 12, tid, 4)
                w(pages, entry + 8, state, 2)
    return pages, obj, word, tid


def case(library, libc, image, label):
    pages, obj, word, tid = fixture(library, image, label)
    initial = {key: bytearray(data) for key, data in pages.items()}
    allocation = oracle.Allocator()
    ledger = []
    scope = model.enter_diagnostic_scope(pages, object_address=obj, input_word=word,
        image_base=image, thread_pointer=oracle.GUEST + 0xD000, thread_id=tid,
        allocate=allocation.model, observer=lambda *args: ledger.append(list(args)))
    observed = {(page << 12, 4096): None for page in pages if page << 12 != oracle.GUEST + 0xE000}
    _, expected, calls, native_ledger = oracle.native(library, image, 0x26C858,
        [obj, word], initial, libc=libc, real_singletons=True, real_mutexes=True,
        real_recursive_mutexes=True, real_diagnostics=True, thread_id=tid,
        observed_memory=observed, instruction_limit=10000)
    assert oracle.flatten(pages)[:0xA000] == expected, label + " guest enter differs"
    for (address, width), raw in observed.items():
        if oracle.GUEST + 0xA000 <= address < oracle.GUEST + oracle.GUEST_SIZE:
            continue  # Physical stack and guest pthread backing are oracle ABI inputs.
        assert _read_span(pages, address, width) == raw, (label, "enter page", hex(address))
    assert calls == allocation.calls, (label, "allocations", calls, allocation.calls)
    assert native_ledger == ledger, (label, "ledger", native_ledger, ledger)
    before_exit = {key: bytearray(data) for key, data in pages.items()}
    exit_ledger = []
    result = model.leave_diagnostic_scope(pages, object_address=obj, image_base=image,
        thread_pointer=oracle.GUEST + 0xD000,
        observer=lambda *args: exit_ledger.append(list(args)))
    observed = {(page << 12, 4096): None for page in pages if not oracle.GUEST <= page << 12 < oracle.GUEST + oracle.GUEST_SIZE}
    _, expected, calls_exit, native_exit = oracle.native(library, image, 0x26C9D0,
        [obj], before_exit, libc=libc, real_singletons=True, real_mutexes=True,
        real_recursive_mutexes=True, real_diagnostics=True, thread_id=tid,
        observed_memory=observed, instruction_limit=3000)
    assert oracle.flatten(pages)[:0xA000] == expected, label + " guest exit differs"
    assert all(_read_span(pages, a, n) == raw for (a, n), raw in observed.items())
    assert not calls_exit and native_exit == exit_ledger
    assert scope.lock_result == (11 if label == "warm_saturated" else 0)
    return dict(image_base=hex(image), profile=label, table_index=scope.table_index,
        allocation_sizes=list(scope.allocation_sizes), lock_result=scope.lock_result,
        exit_unlock_performed=result is not None, enter_and_exit_guest_memory_equal=True,
        all_image_pages_equal=True, ordered_mutex_and_gettid_events_equal=True,
        allocation_order_equal=True, original_diagnostic_bodies_executed=True,
        actual_matching_libc_mutex_bodies_executed=True, native_input_snapshot_used=False,
        scope_padding_preserved=True)


def negative_controls(library):
    image = 0x122C0000
    rows = []
    for label in ("unmapped_object", "invalid_word", "busy_guard", "global_lock_contention",
                  "entry_contention", "allocation_failure", "unmapped_table"):
        fixture_label = "warm_existing" if label in ("entry_contention", "unmapped_table") else "cold_zero"
        pages, obj, word, tid = fixture(library, image, fixture_label)
        if label == "unmapped_object": obj = 0x64000000
        if label == "invalid_word": word = -1
        if label == "busy_guard": w(pages, image + model.GUARD + 1, 2, 1)
        if label == "global_lock_contention": w(pages, image + model.GUARD_MUTEX, 2, 2)
        if label == "entry_contention":
            w(pages, oracle.GUEST + 0x3908, 0x4001, 2)
            w(pages, oracle.GUEST + 0x390C, 88, 4)
        if label == "unmapped_table": w(pages, image + model.TABLE, 0x64000000)
        before = {key: bytes(data) for key, data in pages.items()}
        allocator = oracle.Allocator()
        allocate = (lambda *_: 0) if label == "allocation_failure" else allocator.model
        try:
            model.enter_diagnostic_scope(pages, object_address=obj, input_word=word,
                image_base=image, thread_pointer=oracle.GUEST + 0xD000,
                thread_id=tid, allocate=allocate)
        except (RefillUnsupported, ValueError): pass
        else: raise AssertionError("negative accepted: " + label)
        assert {key: bytes(data) for key, data in pages.items()} == before
        rows.append(dict(control=label, rejected=True, guest_pages_unchanged=True))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, default=Path(r"C:\AI\6\libmetasec_ml_71332.so"))
    parser.add_argument("--libc", type=Path, default=Path(r"C:\AI\6\_vlibc.so"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == worker.LIBC_SHA256
    rows = []
    for image in (0x122C0000, 0x775C205000):
        for label in ("cold_zero", "cold_last", "cold_high_bits", "cold_cross_page",
                      "warm_no_table", "warm_missing_entry", "warm_existing",
                      "warm_nested", "warm_saturated"):
            rows.append(case(args.library, args.libc, image, label))
            print("diagnostic scope", hex(image), label, "PASS", flush=True)
    rejects = negative_controls(args.library)
    report = dict(schema="vm9-diagnostic-scope-fresh-differential-v1", evidence_date="2026-10-07",
        sample_sha256=oracle.LIBRARY_SHA256, libc_sha256=worker.LIBC_SHA256,
        controls=len(rows), cases=rows, negative_controls=rejects,
        complete_python_medusa=False, fresh_input_signer_output_verified=False,
        current_online_header_matrix_verified=False,
        limitations=["Allocation is an explicit nonreusing provider in these component comparisons.",
            "Guest lock memory and return codes are serial; host concurrency/wait/futex is unsupported.",
            "Physical stack scratch is excluded; image and object/heap memory are compared.",
            "This diagnostic scope is not signer state or whole outer/request native evidence.",
            "No actual JVM, live server request or signature output is used."])
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(len(rows), "native scope controls and", len(rejects), "rollback controls PASS")


if __name__ == "__main__":
    main()
