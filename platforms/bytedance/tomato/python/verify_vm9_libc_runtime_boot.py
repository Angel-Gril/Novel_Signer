"""Native differences for atfork registration and static TSD migration.

The public/internal allocation calls are explicit control boundaries. These
controls do not prove public malloc, CPU query, or a complete cold boot.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_TPIDR_EL0
import vm9_allocator as allocator
import vm9_libc_boot as boot
import verify_vm9_root_configuration as root
from verify_vm9_thread_key_cleanup import fresh, WORKER_TLS, TABLE, slot
from verify_vm9_pthread_exit import inputs
from verify_vm9_signer_objects import native, GUEST, LIBRARY_SHA256
from verify_vm9_libc_mapping import LIBC_SHA256
from verify_vm9_libc_arena_boot import put, get

LIBC = root.LIBC_BASE
DEST = GUEST + 0x2FC0
CALLERS = (LIBC + 0x8D9B4, LIBC + 0x8DA28, LIBC + 0x8DA9C)


def prepare(library, libc, image, kind, variant):
    pages = fresh(library, libc, image)
    allocator._write_span(pages, DEST - 0x40, bytes([0xA5]) * 0x180)
    if kind == "atfork":
        put(pages, LIBC + 0xE01C0, 0)
        put(pages, LIBC + 0xE01C8, 0)
        allocator._write_span(pages, LIBC + 0xDB380, bytes(40))
        if variant in ("one_node", "three_nodes"):
            count = 1 if variant == "one_node" else 3
            nodes = [GUEST + 0x4000 + i * 0x80 for i in range(count)]
            for i, node in enumerate(nodes):
                allocator._write_span(pages, node, bytes([0x5A]) * 0x40)
                put(pages, node, nodes[i + 1] if i + 1 < count else 0)
                put(pages, node + 8, nodes[i - 1] if i else 0)
            put(pages, LIBC + 0xE01C0, nodes[0])
            put(pages, LIBC + 0xE01C8, nodes[-1])
    else:
        static = LIBC + 0xDB6B8
        allocator._write_span(pages, static, bytes((i * 29 + 7) & 255 for i in range(128)))
        state = int(variant[-1]) if variant.startswith("state") else 1
        put(pages, static + 8, state, 4)
        key = 140 if variant == "last_key" else 0
        put(pages, LIBC + 0xE9F68, key | 0x80000000, 4)
        put(pages, TABLE + key * 16, 1)
        put(pages, slot(pages, key), 1)
        put(pages, slot(pages, key) + 8, static)
    return pages


def pointer(kind, variant):
    if variant == "allocation_null": return 0
    if variant == "alias_self": return LIBC + 0xDB6B8
    if variant == "alias_forward": return LIBC + 0xDB6C0
    return DEST


def case(library, libc, image, kind, variant):
    pages = prepare(library, libc, image, kind, variant)
    seed = prepare(library, libc, image, kind, variant)
    native_calls, model_calls = [], []
    entry = LIBC + (0x67374 if kind == "atfork" else 0x99C78)
    allocation = LIBC + (0x17BC0 if kind == "atfork" else 0x8E0EC)
    observed = {(LIBC + 0xE01C0, 16): None, (LIBC + 0xDB380, 48): None,
                (LIBC + 0xDB6B8, 128): None, (LIBC + 0xE9F68, 8): None,
                (TABLE, 141 * 16): None, (WORKER_TLS, 0xB00): None}
    def allocate_native(cpu):
        size = cpu.reg_read(UC_ARM64_REG_X0)
        value = pointer(kind, variant)
        native_calls.append([size, value])
        return value
    def allocate_model(staged, size):
        value = pointer(kind, variant)
        model_calls.append([size, value])
        return value
    def observe(cpu, pc):
        if pc == entry:
            for address, width in observed:
                if LIBC <= address < LIBC + 0x400000:
                    cpu.mem_write(address, allocator._read_span(seed, address, width))
    arguments = [*CALLERS, GUEST + 0x6000] if kind == "atfork" else []
    expected, memory, allocations, ledger = native(library, image, entry - image,
        arguments, inputs(seed), libc=libc, real_mutexes=True,
        instruction_observer=observe, host_imports={allocation - image: allocate_native},
        extra_registers={UC_ARM64_REG_TPIDR_EL0: WORKER_TLS},
        observed_memory=observed, instruction_limit=100000)
    assert not allocations and not ledger
    if kind == "atfork":
        actual = boot.register_atfork(pages, libc_base=LIBC, prepare=CALLERS[0],
            parent=CALLERS[1], child=CALLERS[2], dso=arguments[3],
            allocate_public=allocate_model)
        assert actual == expected == (12 if variant == "allocation_null" else 0)
    else:
        boot.migrate_static_tsd(pages, libc_base=LIBC, thread_pointer=WORKER_TLS,
            allocate_internal=allocate_model)
    assert native_calls == model_calls == [[48 if kind == "atfork" else 128, pointer(kind, variant)]]
    assert allocator._read_span(pages, GUEST, 0xA000) == memory, (kind, variant, "guest bytes")
    for (address, width), value in observed.items():
        data = allocator._read_span(pages, address, width)
        if data != value:
            differences = [(hex(address + i - LIBC), a, b) for i, (a, b) in enumerate(zip(data, value)) if a != b]
            raise AssertionError((kind, variant, "globals/TLS", differences[:8]))
    return dict(case=kind, variant=variant, image_base=hex(image),
        guest_globals_tls_and_ordered_allocation_match=True, untouched_padding_match=True,
        allocation_explicit_boundary=True, native_input_snapshot_used=False)


def rejection_cases(library, libc):
    results = []
    for label in ("atfork_contended", "atfork_missing_tail", "atfork_bad_provider",
                  "tsd_null_diagnostic", "tsd_missing_destination", "tsd_invalid_key",
                  "tsd_missing_generation", "tsd_late_provider_error"):
        kind = "atfork" if label.startswith("atfork") else "tsd"
        pages = prepare(library, libc, 0x122C0000, kind, "empty" if kind == "atfork" else "state1")
        if label == "atfork_contended": put(pages, LIBC + 0xDB380, 0x10, 4)
        if label == "atfork_missing_tail":
            put(pages, LIBC + 0xE01C8, 0x47000000)
        if label == "tsd_invalid_key": put(pages, LIBC + 0xE9F68, 0x8000008D, 4)
        if label == "tsd_missing_generation": del pages[TABLE >> 12]
        before = {k: bytes(v) for k, v in pages.items()}
        calls = []
        def allocate(staged, size):
            calls.append(size)
            if label == "atfork_bad_provider": return "invalid"
            if label == "tsd_null_diagnostic": return 0
            if label == "tsd_missing_destination": return 0x47000000
            if label == "tsd_late_provider_error":
                put(staged, DEST, 0x1234)
                raise allocator.RefillUnsupported("explicit allocation provider failure")
            return DEST
        try:
            if kind == "atfork":
                boot.register_atfork(pages, libc_base=LIBC, prepare=CALLERS[0],
                    parent=CALLERS[1], child=CALLERS[2], dso=0, allocate_public=allocate)
            else:
                boot.migrate_static_tsd(pages, libc_base=LIBC, thread_pointer=WORKER_TLS,
                    allocate_internal=allocate)
        except (allocator.RefillUnsupported, ValueError): pass
        else: raise AssertionError((label, "must reject"))
        assert before == {k: bytes(v) for k, v in pages.items()}, (label, "page rollback")
        results.append(dict(case=label, rejected=True, guest_pages_unchanged=True,
            external_calls=len(calls), external_provider_effects_rolled_back=False))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--libc", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == LIBC_SHA256
    cases = []
    for image in (0x122C0000, 0x775C205000):
        for kind, variants in (("atfork", ("empty", "one_node", "three_nodes", "allocation_null")),
                ("tsd", ("state0", "state1", "state2", "state3", "state4", "last_key", "alias_self", "alias_forward"))):
            for variant in variants:
                cases.append(case(args.library, args.libc, image, kind, variant))
                print("runtime boot", hex(image), kind, variant, "PASS", flush=True)
    rejected = rejection_cases(args.library, args.libc)
    report = dict(schema="vm9-libc-runtime-boot-components-v1", sample_sha256=LIBRARY_SHA256,
        libc_sha256=LIBC_SHA256, cases=cases, rejection_cases=rejected,
        allocation_explicit_boundary=True, actual_public_allocator_integrated=False,
        cpu_query_and_reentrant_malloc_restored=False, complete_tsd_fallback=False,
        python_malloc_cold_boot_complete=False, standalone_medusa_complete=False,
        native_input_snapshot_used=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(native_controls=len(cases), rejected=len(rejected))))


if __name__ == "__main__": main()
