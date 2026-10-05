"""Fresh native differences for bin/tcache boot and main/static TSD boot.

Base allocation is an explicit boundary in these controls. Composition runs
actual preinit from ELF to just before initial arena construction; it does not
claim actual malloc, complete TSD fallback, or Medusa request signing.
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
from verify_vm9_thread_key_cleanup import fresh, WORKER_TLS, TABLE
from verify_vm9_pthread_exit import inputs
from verify_vm9_signer_objects import native, GUEST, LIBRARY_SHA256
from verify_vm9_libc_mapping import LIBC_SHA256

LIBC = root.LIBC_BASE
BUFFER = GUEST + 0x1FE0
ALLOC = GUEST + 0x7000


def put(p, address, value, width=8):
    allocator._write_span(p, address, (value & ((1 << (width * 8)) - 1)).to_bytes(width, "little"))


def get(p, address, width=8):
    return int.from_bytes(allocator._read_span(p, address, width), "little")


def prepare(library, libc, base, kind, variant):
    p = fresh(library, libc, base)
    if kind not in ("bitmap", "tsd", "preinit_composed"):
        boot.preinit_prefix(p, libc_base=LIBC, thread_pointer=WORKER_TLS, brk=lambda *args: 0x13600000)
    allocator._write_span(p, ALLOC, bytes([0xA5]) * 0x1000)
    if kind == "bin":
        width, redzone, limit = variant
        allocator._write_span(p, BUFFER - 8, bytes([0xA5]) * 0x78)
        put(p, BUFFER, width)
        put(p, LIBC + 0xE69C8, redzone, 1)
        put(p, LIBC + 0xE9EA8, limit)
    elif kind == "bitmap":
        allocator._write_span(p, BUFFER - 8, bytes([0xA5]) * 0x68)
    elif kind == "arena":
        allocator._write_span(p, LIBC + 0xE9120, bytes([0xA5]) * (36 * 96))
        if variant in ("chunk16", "chunk20"):
            bits = int(variant[5:])
            put(p, LIBC + 0xDB668, bits)
            boot.chunk_boot(p, libc_base=LIBC, thread_pointer=WORKER_TLS, brk=lambda *args: 0x13600000)
        if variant == "redzone": put(p, LIBC + 0xE69C8, 1, 1)
        if variant == "negative_option": put(p, LIBC + 0xDB658, (1 << 64) - 1)
        if variant == "option64":
            put(p, LIBC + 0xDB658, 64)
            put(p, LIBC + 0xE67C8, 0x1234)
        if variant == "prior_maximum": put(p, LIBC + 0xE67C0, 0x10000)
    elif kind == "arena_create":
        boot.arena_bin_boot(p, libc_base=LIBC, allocate_base=lambda pages, size: ALLOC + 0x800)
        allocator._write_span(p, GUEST + 0x2000, bytes([0xA5]) * 0x7000)
    elif kind == "tcache":
        boot.arena_bin_boot(p, libc_base=LIBC, allocate_base=lambda pages, size: ALLOC + 0x800)
        options = {"negative": (1 << 64) - 1, "log0": 0, "log16": 16, "log31": 31, "log32": 32, "log48": 48}
        if variant in options: put(p, LIBC + 0xDB6A8, options[variant])
        put(p, LIBC + 0xE6A9C, 0xDEADBEEF, 4)
        if variant == "capacity_edges":
            for i, count in enumerate((0, 10, 11, 0x80000000, 0x8000000B)):
                put(p, LIBC + 0xE9120 + i * 96 + 0x20, count, 4)
    elif kind == "tsd":
        state = {"state0": 0, "state1": 1, "state2": 2, "state3": 3, "state4": 4}.get(variant, 0)
        allocator._write_span(p, LIBC + 0xDB6B8, bytes([0xA5]) * 0x80)
        put(p, LIBC + 0xDB6B8 + 8, state, 4)
        put(p, LIBC + 0xE6AAC, 0x1234, 4)
        if variant in ("occupied_three", "exhausted"):
            for i in range(3 if variant == "occupied_three" else 141):
                put(p, TABLE + i * 16, 1)
        if variant == "generation_wrap": put(p, TABLE, (1 << 64) - 2)
    return p


def case(library, libc, base, kind, variant):
    p = prepare(library, libc, base, kind, variant)
    seed = prepare(library, libc, base, kind, variant)
    observed = {(LIBC + 0xE67B8, 0x370): None, (LIBC + 0xE9110, 0xE60): None,
                (LIBC + 0xDB650, 0xF0): None, (WORKER_TLS, 0xB00): None,
                (TABLE, 141 * 16): None}
    if kind == "preinit_composed": observed[LIBC + 0xDE840, 8] = None
    entries = {"bin": 0x75DC0, "bitmap": 0x7DCE8, "arena": 0x7CF2C,
               "tcache": 0x99378, "tsd": 0x99938, "preinit_composed": 0x8E250, "arena_create": 0x7CCE8}
    entry = LIBC + entries[kind]
    arguments = ([0 if variant == "allocation_null" else variant] if kind == "arena_create" else [BUFFER] if kind == "bin" else [BUFFER, variant] if kind == "bitmap" else [])
    stop = LIBC + 0x8E31C - base if kind == "preinit_composed" else None
    nalloc = []
    malloc = []
    nsys = []
    msys = []
    def alloc_result(index):
        return 0 if variant == "allocation_null" else GUEST + 0x2000 if kind == "arena_create" else ALLOC + index * 0x200
    def allocate_native(cpu):
        size = cpu.reg_read(UC_ARM64_REG_X0)
        pointer = alloc_result(len(nalloc))
        nalloc.append([size, pointer])
        return pointer
    def allocate_model(pages, size):
        pointer = alloc_result(len(malloc))
        malloc.append([size, pointer])
        return pointer
    def syscall(cpu, number):
        assert kind == "preinit_composed" and number == 214 and cpu.reg_read(UC_ARM64_REG_X0) == 0
        nsys.append(0)
        return 0x13600000
    def brk(staged, target):
        msys.append(target)
        return 0x13600000
    def observe(cpu, pc):
        if pc == entry:
            # Direct controls receive independently constructed, explicit
            # inputs. Composition keeps actual fresh globals and applies
            # only the inactive key fixture, never Python boot output.
            spans = [(TABLE, 141 * 16)] if kind == "preinit_composed" else list(observed)
            for address, width in spans:
                if LIBC <= address < LIBC + 0x400000:
                    cpu.mem_write(address, allocator._read_span(seed, address, width))
    expected, memory, _, ledger = native(library, base, entry - base, arguments,
        inputs(seed), libc=libc, real_mutexes=True, instruction_observer=observe,
        syscall_handler=syscall, observed_memory=observed,
        host_imports={LIBC + 0x7D998 - base: allocate_native},
        extra_registers={UC_ARM64_REG_TPIDR_EL0: WORKER_TLS},
        instruction_limit=100000, stop_offset=stop)
    assert not ledger
    if kind == "bin":
        actual = boot.initialize_bin_layout(p, bin_address=BUFFER, libc_base=LIBC)
    elif kind == "bitmap":
        actual = boot.initialize_bitmap_description(p, descriptor_address=BUFFER, bits=variant)
    elif kind == "arena":
        actual = boot.arena_bin_boot(p, libc_base=LIBC, allocate_base=allocate_model)
    elif kind == "arena_create":
        actual = boot.construct_arena(p, libc_base=LIBC, arena_index=arguments[0], allocate_base=allocate_model)
    elif kind == "tcache":
        actual = boot.tcache_boot(p, libc_base=LIBC, allocate_base=allocate_model)
    elif kind == "tsd":
        actual = boot.tsd_boot(p, libc_base=LIBC, thread_pointer=WORKER_TLS)
    else:
        assert boot.preinit_until_arena_construct(p, libc_base=LIBC,
            thread_pointer=WORKER_TLS, brk=brk, allocate_base=allocate_model) == 0x8E31C
        actual = 0
    assert actual is None or actual == expected, (kind, variant, "return", actual, expected)
    assert nalloc == malloc and nsys == msys, (kind, variant, "ordered effects")
    assert allocator._read_span(p, GUEST, 0xA000) == memory, (kind, variant, "guest bytes")
    for (address, width), value in observed.items():
        if allocator._read_span(p, address, width) != value:
            actual_bytes = allocator._read_span(p, address, width)
            differences = [(hex(address + i - LIBC), a, b) for i, (a, b) in enumerate(zip(actual_bytes, value)) if a != b]
            raise AssertionError((kind, variant, "globals/TLS", differences[:8]))
    return dict(case=kind, variant=variant, image_base=hex(base), return_guest_globals_tls_and_calls_match=True,
        untouched_padding_match=True, base_allocation_calls=len(malloc),
        base_allocation_explicit_boundary=kind in ("arena", "arena_create", "tcache", "preinit_composed"),
        actual_preinit_entry_composed=kind == "preinit_composed", native_input_snapshot_used=False)


def rejection_cases(library, libc):
    results = []
    for label in ("bin_zero_width", "bin_budget", "bitmap_oversized", "arena_missing_bin_page",
                  "arena_bad_geometry", "base_provider_missing", "base_provider_bad_pointer", "tcache_missing_rows", "tsd_missing_generation_page"):
        kind = "bin" if label.startswith("bin_") else "bitmap" if label.startswith("bitmap_") else "tcache" if label.startswith("tcache_") else "tsd" if label.startswith("tsd_") else "arena"
        variant = (48, 0, 0x3E000) if kind == "bin" else 64 if kind == "bitmap" else "default"
        p = prepare(library, libc, 0x122C0000, kind, variant)
        if label == "bin_zero_width": put(p, BUFFER, 0)
        if label == "arena_bad_geometry": put(p, LIBC + 0xE9F38, 17)
        if label in ("arena_missing_bin_page", "tcache_missing_rows"): del p[(LIBC + 0xE9120) >> 12]
        if label == "tsd_missing_generation_page": del p[TABLE >> 12]
        before = {k: bytes(v) for k, v in p.items()}
        effects = []
        def allocate(pages, size):
            effects.append(size)
            if label == "base_provider_missing": raise allocator.RefillUnsupported("base allocation unavailable")
            return -1 if label == "base_provider_bad_pointer" else ALLOC
        try:
            if kind == "bin": boot.initialize_bin_layout(p, bin_address=BUFFER, libc_base=LIBC, max_pages=1 if label == "bin_budget" else 256)
            elif kind == "bitmap": boot.initialize_bitmap_description(p, descriptor_address=BUFFER, bits=0x1000001)
            elif kind == "tsd": boot.tsd_boot(p, libc_base=LIBC, thread_pointer=WORKER_TLS)
            elif kind == "tcache": boot.tcache_boot(p, libc_base=LIBC, allocate_base=allocate)
            else: boot.arena_bin_boot(p, libc_base=LIBC, allocate_base=allocate)
        except (allocator.RefillUnsupported, ValueError): pass
        else: raise AssertionError((label, "expected rejection"))
        assert before == {k: bytes(v) for k, v in p.items()}, label
        results.append(dict(case=label, rejected=True, guest_pages_unchanged=True,
                            external_effects=len(effects), external_provider_effects_rolled_back=False))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--libc", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == LIBC_SHA256
    controls = []
    for base in (0x122C0000, 0x775C205000):
        cases = [("bin", (w, r, limit)) for w in (8, 48, 14336) for r in (0, 1) for limit in (0x3E000, 0x8000)]
        cases += [("bitmap", b) for b in (0, 1, 64, 65, 4096, 4097, 262144)]
        cases += [("arena", v) for v in ("default", "redzone", "chunk16", "chunk20", "allocation_null", "negative_option", "option64", "prior_maximum")]
        cases += [("tcache", v) for v in ("negative", "log0", "log16", "log31", "log32", "log48", "capacity_edges", "allocation_null")]
        cases += [("tsd", v) for v in ("state0", "state1", "state2", "state3", "state4", "occupied_three", "exhausted", "generation_wrap")]
        cases += [("preinit_composed", "default")]
        cases += [("arena_create", v) for v in (0, 137, "allocation_null")]
        for kind, variant in cases:
            controls.append(case(args.library, args.libc, base, kind, variant))
            print("allocator boot", hex(base), kind, variant, "PASS", flush=True)
    rejected = rejection_cases(args.library, args.libc)
    report = dict(schema="vm9-libc-arena-tcache-tsd-boot-v1", sample_sha256=LIBRARY_SHA256,
        libc_sha256=LIBC_SHA256, cases=controls, rejection_cases=rejected,
        preinit_composed_stop_offset="0x8e31c", real_base_allocator_integrated=False,
        initial_arena_published_in_composed_controls=False, isolated_arena_constructor_verified=True, complete_tsd_fallback=False,
        python_preinit_complete=False, python_malloc_cold_boot_complete=False,
        standalone_medusa_complete=False, native_input_snapshot_used=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(allocator_boot=len(controls), rejected=len(rejected))))


if __name__ == "__main__": main()
