"""Fresh-input native differences for matching base/DSS/chunk/rtree boot."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_TPIDR_EL0
import vm9_allocator as allocator
import vm9_libc_boot as boot
import verify_vm9_root_configuration as root
from verify_vm9_thread_key_cleanup import fresh, WORKER_TLS
from verify_vm9_pthread_exit import inputs
from verify_vm9_signer_objects import native, GUEST, LIBRARY_SHA256
from verify_vm9_libc_mapping import LIBC_SHA256


def case(library, libc, base, kind, variant):
    p = fresh(library, libc, base)
    seed = fresh(library, libc, base)
    patches = {}
    stop = None
    address = GUEST + (0x1FE0 if variant == "cross_page" else 0x1000)
    brk_cache = root.LIBC_BASE + 0xDE840
    if kind == "mutex":
        offset = 0x932EC
        arguments = [address]
        patches[address - 8] = bytes([0xA5]) * 64
    elif kind == "base_tree":
        offset = 0x89460
        arguments = [address]
        patches[address - 8] = bytes([0xA5]) * 0x80
    elif kind == "rtree":
        offset = 0x94EF4
        arguments = [address, variant, root.LIBC_BASE + 0x7DE34, 0]
        patches[address - 8] = bytes([0xA5]) * 0x90
    elif kind == "preinit_prefix":
        offset = 0x8E250
        arguments = []
        stop = root.LIBC_BASE + 0x8E2C4 - base
    elif kind == "configuration_preinit":
        offset = 0x8CE70
        arguments = []
        patches[root.LIBC_BASE + 0xE6978] = (address if variant == "empty_string" else 0).to_bytes(8, "little")
        patches[address] = b"\0" + bytes([0xA5]) * 15
    elif kind == "extent_boot":
        offset = 0x89410
        arguments = []
        patches[root.LIBC_BASE + 0xE68C8] = bytes([0xA5]) * 0x68
    elif kind == "base_boot":
        offset = 0x7DC7C
        arguments = []
        patches[root.LIBC_BASE + 0xE67E8] = bytes([0xA5]) * 0xA0
    else:
        offset = 0x7F46C if kind == "dss_boot" else 0x7F13C
        arguments = []
        patches[root.LIBC_BASE + 0xE6888] = bytes([0xA5]) * 0x50
        patches[brk_cache] = (0x13600000 if variant == "warm" else 0).to_bytes(8, "little")
        if kind == "chunk_boot":
            patches[root.LIBC_BASE + 0xDB668] = variant.to_bytes(8, "little")
            patches[root.LIBC_BASE + 0xE9EC0] = bytes([0xA5]) * 0x80
    for pages in (p, seed):
        for a, data in patches.items():
            allocator._write_span(pages, a, data)
    observed = {(a, len(data)): None for a, data in patches.items()}
    observed[WORKER_TLS, 0xB00] = None
    if kind == "preinit_prefix":
        observed.update({(root.LIBC_BASE + o, n): None for o, n in
            ((0xE67D0, 0x210), (0xE9EC0, 0x80), (0xDE840, 8))})
    ncalls = []
    mcalls = []
    entry = root.LIBC_BASE + offset
    def observe(cpu, pc):
        if pc == entry:
            for a, data in patches.items():
                cpu.mem_write(a, data)
    def syscall(cpu, number):
        assert number == 214 and cpu.reg_read(UC_ARM64_REG_X0) == 0
        ncalls.append(0)
        return 0x13600000
    expected, memory, _, _ = native(library, base, entry - base, arguments, inputs(seed),
        libc=libc, real_mutexes=True, instruction_observer=observe, syscall_handler=syscall,
        observed_memory=observed, extra_registers={UC_ARM64_REG_TPIDR_EL0: WORKER_TLS},
        instruction_limit=20000, stop_offset=stop)
    def brk(staged, target):
        assert target == 0
        mcalls.append(target)
        return 0x13600000
    if kind == "mutex":
        actual = boot.initialize_allocator_mutex(p, mutex_address=address)
    elif kind == "base_tree":
        boot.initialize_base_tree(p, tree_address=address)
        actual = None
    elif kind == "rtree":
        actual = boot.initialize_rtree(p, tree_address=address, bits=variant,
            allocate_address=arguments[2], free_address=0)
    elif kind == "preinit_prefix":
        assert boot.preinit_prefix(p, libc_base=root.LIBC_BASE, thread_pointer=WORKER_TLS, brk=brk) == 0x8E2C4
        actual = 0
    elif kind == "configuration_preinit":
        actual = boot.configuration_preinit(p, libc_base=root.LIBC_BASE)
    elif kind == "extent_boot":
        actual = boot.extent_boot(p, libc_base=root.LIBC_BASE)
    elif kind == "base_boot":
        actual = boot.base_boot(p, libc_base=root.LIBC_BASE)
    elif kind == "dss_boot":
        actual = boot.dss_boot(p, libc_base=root.LIBC_BASE, thread_pointer=WORKER_TLS, brk=brk)
    else:
        actual = boot.chunk_boot(p, libc_base=root.LIBC_BASE, thread_pointer=WORKER_TLS, brk=brk)
    assert actual is None or actual == expected, (kind, variant, "return")
    assert ncalls == mcalls, (kind, variant, "OS calls")
    assert allocator._read_span(p, GUEST, 0xA000) == memory, (kind, variant, "guest bytes")
    assert all(allocator._read_span(p, a, n) == v for (a, n), v in observed.items()), (kind, variant, "globals/TLS")
    return dict(case=kind, variant=variant, image_base=hex(base), return_guest_globals_tls_and_calls_match=True,
                untouched_padding_match=True, native_input_snapshot_used=False)


def rejections(library, libc):
    results = []
    for label in ("invalid_exponent", "missing_tree_page", "missing_mutex_page", "missing_dss_cache", "brk_provider_failure", "nonempty_configuration", "prefix_registration_flag"):
        p = fresh(library, libc, 0x122C0000)
        if label == "prefix_registration_flag":
            allocator._write_span(p, root.LIBC_BASE + 0xE6A98, b"\1")
        elif label == "nonempty_configuration":
            allocator._write_span(p, root.LIBC_BASE + 0xE6978, (GUEST + 0x1000).to_bytes(8, "little"))
            allocator._write_span(p, GUEST + 0x1000, b"unknown:value\0")
        elif label == "invalid_exponent":
            allocator._write_span(p, root.LIBC_BASE + 0xDB668, (64).to_bytes(8, "little"))
        elif label == "missing_tree_page":
            del p[(root.LIBC_BASE + 0xE9ED0) >> 12]
        elif label == "missing_mutex_page":
            del p[(root.LIBC_BASE + 0xE6860) >> 12]
        elif label == "missing_dss_cache":
            del p[(root.LIBC_BASE + 0xDE840) >> 12]
        before = {k: bytes(v) for k, v in p.items()}
        def brk(staged, target):
            if label == "brk_provider_failure":
                raise allocator.RefillUnsupported("explicit missing program-break service")
            return 0x13600000
        try:
            if label == "prefix_registration_flag":
                boot.preinit_prefix(p, libc_base=root.LIBC_BASE, thread_pointer=WORKER_TLS, brk=brk)
            elif label == "nonempty_configuration":
                boot.configuration_preinit(p, libc_base=root.LIBC_BASE)
            elif label == "missing_mutex_page":
                boot.base_boot(p, libc_base=root.LIBC_BASE)
            else:
                boot.chunk_boot(p, libc_base=root.LIBC_BASE, thread_pointer=WORKER_TLS, brk=brk)
        except (allocator.RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError((label, "expected rejection"))
        assert before == {k: bytes(v) for k, v in p.items()}, label
        results.append(dict(case=label, rejected=True, guest_pages_unchanged=True))
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
        cases = [(k, v) for k in ("mutex", "base_tree") for v in ("same_page", "cross_page")]
        cases += [("rtree", v) for v in (1, 15, 16, 17, 31, 32, 33, 46, 48, 49, 63, 64)]
        cases += [("configuration_preinit", "null"), ("configuration_preinit", "empty_string"), ("extent_boot", "cold"), ("preinit_prefix", "cold")]
        cases += [("base_boot", "cold"), ("dss_boot", "cold"), ("dss_boot", "warm")]
        cases += [("chunk_boot", v) for v in (12, 18, 32, 48, 63)]
        for kind, variant in cases:
            controls.append(case(args.library, args.libc, base, kind, variant))
            print("boot", hex(base), kind, variant, "PASS", flush=True)
    rejected = rejections(args.library, args.libc)
    report = dict(schema="vm9-libc-boot-components-v1", sample_sha256=LIBRARY_SHA256,
        libc_sha256=LIBC_SHA256, cases=controls, rejection_cases=rejected,
        python_preinit_complete=False, python_malloc_cold_boot_complete=False,
        standalone_medusa_complete=False, native_input_snapshot_used=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(boot=len(controls), rejected=len(rejected))))


if __name__ == "__main__":
    main()
