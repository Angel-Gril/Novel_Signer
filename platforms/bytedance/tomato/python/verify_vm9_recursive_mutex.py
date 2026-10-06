"""Matching-libc recursive mutex through the real signer PLT/native constructor.

Private serial semantics reuse the existing stdio mutex owner. Unknown attrs,
contention, shared/error-checking/destroyed states are explicit closed boundaries.
No native memory or host thread is published or used as Python input.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL0, UC_ARM64_REG_X0, UC_ARM64_REG_X30
import vm9_allocator as a
import vm9_libc_stdio as model
from vm9_libc_boot import _u, _w
import verify_vm9_signer_objects as oracle
from verify_vm9_libc_mapping import LIBC_SHA256

LIBC = 0x51000000
TLS = oracle.GUEST + 0xA000
MUTEXES = (oracle.GUEST + 0x1000, oracle.GUEST + 0x1FF0)
LABELS = ("constructor", "init_attribute", "init_null", "first_lock", "recursive_lock",
          "recursive_unlock", "last_unlock", "overflow", "wrong_owner_unlock", "idle_unlock")


def fixture(address, label):
    p = oracle.fresh_pages()
    _w(p, TLS + 8, TLS + 0x200)
    _w(p, TLS + 0x210, 137, 4)
    _w(p, oracle.GUEST + 0x3000, 1)
    if label not in ("constructor", "init_attribute", "init_null"):
        model.initialize_recursive_mutex(p, mutex_address=address)
        if label in ("recursive_lock", "last_unlock"):
            _w(p, address, 0x4001, 2); _w(p, address + 4, 137, 4)
        if label == "recursive_unlock":
            _w(p, address, 0x4009, 2); _w(p, address + 4, 137, 4)
        if label == "overflow":
            _w(p, address, 0x5FFD, 2); _w(p, address + 4, 137, 4)
        if label == "wrong_owner_unlock":
            _w(p, address, 0x4001, 2); _w(p, address + 4, 271, 4)
    return p


def bindings(libc):
    with libc.open("rb") as stream:
        elf = ELFFile(stream)
        return {symbol.name: LIBC + symbol["st_value"] for symbol in elf.get_section_by_name(".dynsym").iter_symbols()
                if symbol["st_shndx"] != "SHN_UNDEF"}


def controls(library, libc, image, address, label, exports):
    p = fixture(address, label); seed = {k: bytearray(v) for k, v in p.items()}
    events = Counter()
    def observe(cpu, pc):
        for name in ("pthread_mutex_init", "pthread_mutex_lock", "pthread_mutex_unlock",
                     "pthread_mutexattr_init", "pthread_mutexattr_settype", "pthread_mutexattr_destroy"):
            if pc == exports[name]: events[name] += 1
    def redirect(name):
        def call(cpu): cpu.reg_write(UC_ARM64_REG_PC, exports[name])
        return call
    host = {offset: redirect(name) for offset, name in
        ((0x347EC0, "pthread_mutexattr_init"), (0x347ED0, "pthread_mutexattr_settype"),
         (0x347EF0, "pthread_mutexattr_destroy"))}
    lock = label in ("first_lock", "recursive_lock", "overflow")
    if label == "constructor": offset, args = 0x329F88, [address]
    elif label.startswith("init_"):
        offset, args = 0x347EE0, [address, oracle.GUEST + 0x3000 if label == "init_attribute" else 0]
    else: offset, args = (0x347F00 if lock else 0x347F10), [address]
    observed = {(address - 8, 56): None}
    result, memory, allocations, ledger = oracle.native(library, image, offset, args, seed,
        libc=libc, real_mutexes=True, real_recursive_mutexes=True,
        extra_registers={UC_ARM64_REG_TPIDR_EL0: TLS}, instruction_observer=observe,
        observed_memory=observed, host_imports=host)
    assert not allocations
    if label in ("constructor", "init_attribute"):
        model.initialize_recursive_mutex(p, mutex_address=address); expected = 0
    elif label == "init_null":
        a._write_span(p, address, bytes(40)); expected = 0
    else:
        operation = model.lock_recursive_mutex if lock else model.unlock_recursive_mutex
        expected = operation(p, mutex_address=address, thread_pointer=TLS)
    if label != "constructor": assert result == expected
    assert oracle.flatten(p)[:0xA000] == memory
    assert observed[address - 8, 56] == a._read_span(p, address - 8, 56)
    assert sum(events.values()) == (4 if label == "constructor" else 1)
    return dict(case=label, image_base=hex(image), cross_page=address == MUTEXES[1],
        defined_return_matches=label != "constructor", constructor_return_is_unspecified=label == "constructor",
        mutex_and_surrounding_guest_bytes_match=True, actual_export_counts=dict(events),
        final_state=hex(_u(p, address, 2)), final_owner=_u(p, address + 4, 4),
        explicit_tls_thread_id=137, normal_default_oracle_boundary_preserved=True)



def serial_sequence(library, libc, image, address, tid, exports):
    p = fixture(address, "constructor"); _w(p, TLS + 0x210, tid, 4)
    seed = {k: bytearray(v) for k, v in p.items()}
    actions = ["constructor", "lock", "lock", "unlock", "unlock", "lock", "unlock"]
    pending = list(actions); results = []; states = []
    continuation = oracle.GUEST + 0xF720
    def redirect(name):
        def call(cpu): cpu.reg_write(UC_ARM64_REG_PC, exports[name])
        return call
    def dispatch(cpu):
        if not pending:
            cpu.reg_write(UC_ARM64_REG_PC, oracle.STOP); return
        action = pending.pop(0)
        offset = {"constructor": 0x329F88, "lock": 0x347F00, "unlock": 0x347F10}[action]
        cpu.reg_write(UC_ARM64_REG_X0, address)
        cpu.reg_write(UC_ARM64_REG_X30, continuation)
        cpu.reg_write(UC_ARM64_REG_PC, image + offset)
    def returned(cpu):
        index = len(results); action = actions[index]
        if action == "constructor": model.initialize_recursive_mutex(p, mutex_address=address)
        else:
            operation = model.lock_recursive_mutex if action == "lock" else model.unlock_recursive_mutex
            assert cpu.reg_read(UC_ARM64_REG_X0) == operation(p, mutex_address=address, thread_pointer=TLS)
        assert bytes(cpu.mem_read(oracle.GUEST, 0xA000)) == oracle.flatten(p)[:0xA000]
        states.append(hex(_u(p, address, 2))); results.append(action)
        dispatch(cpu)
    imports = {continuation - image: returned, 0x347EC0: redirect("pthread_mutexattr_init"),
        0x347ED0: redirect("pthread_mutexattr_settype"), 0x347EF0: redirect("pthread_mutexattr_destroy")}
    pending.pop(0)
    _, _, allocations, _ = oracle.native(library, image, 0x329F88, [address], seed,
        libc=libc, real_mutexes=True, real_recursive_mutexes=True, thread_id=137,
        extra_registers={UC_ARM64_REG_TPIDR_EL0: TLS, UC_ARM64_REG_X30: continuation}, host_imports=imports)
    assert results == actions and not allocations
    assert states == ["0x4000", "0x4001", "0x4005", "0x4001", "0x4000", "0x4001", "0x4000"]
    assert _u(p, address + 4, 4) == 0
    return dict(case="same_run_constructor_recursive_acquire_release_reacquire", image_base=hex(image),
        cross_page=address == MUTEXES[1], explicit_tls_thread_id=tid, singleton_gettid_provider=137,
        states=states, guest_bytes_match_at_every_return=True, same_run_sequence_returns=len(results),
        final_owner_cleared=True, no_native_state_seeds_python=True)


def rejection_controls(library, libc):
    rows = []; image = 0x122C0000; address = MUTEXES[0]
    labels = ("recursive_opt_in_missing", "recursive_attribute_opt_in_missing", "unknown_attribute",
        "shared_attribute", "errorcheck_attribute", "shared_state", "errorcheck_state", "destroyed_state",
        "contended_state", "foreign_owner_lock", "missing_owner", "inconsistent_idle_owner", "zero_tid")
    for label in labels:
        p = fixture(address, "first_lock"); operation = 0x347F00; args = [address]
        if label.endswith("attribute") or label == "recursive_attribute_opt_in_missing":
            operation = 0x347EE0; args.append(oracle.GUEST + 0x3000)
            _w(p, oracle.GUEST + 0x3000, {"unknown_attribute": 3, "shared_attribute": 0x11,
                "errorcheck_attribute": 2}.get(label, 1))
        if label in ("shared_state", "errorcheck_state", "destroyed_state", "contended_state"):
            _w(p, address, {"shared_state": 0x6000, "errorcheck_state": 0x8000,
                "destroyed_state": 0xFFFF, "contended_state": 0x4002}[label], 2)
        if label in ("foreign_owner_lock", "missing_owner"):
            _w(p, address, 0x4001, 2); _w(p, address + 4, 271 if label == "foreign_owner_lock" else 0, 4)
        if label == "inconsistent_idle_owner": _w(p, address + 4, 137, 4)
        if label == "zero_tid": _w(p, TLS + 0x210, 0, 4)
        before = {k: bytes(v) for k, v in p.items()}; reached = []
        try:
            oracle.native(library, image, operation, args, p, libc=libc, real_mutexes=True,
                real_recursive_mutexes="opt_in_missing" not in label,
                extra_registers={UC_ARM64_REG_TPIDR_EL0: TLS},
                instruction_observer=lambda cpu, pc: reached.append(pc))
        except a.RefillUnsupported: pass
        else: raise AssertionError((label, "expected explicit oracle rejection"))
        assert reached == [image + operation] and before == {k: bytes(v) for k, v in p.items()}
        if label not in ("recursive_opt_in_missing", "recursive_attribute_opt_in_missing", "unknown_attribute",
                          "shared_attribute", "errorcheck_attribute", "errorcheck_state", "destroyed_state"):
            try: model.lock_recursive_mutex(p, mutex_address=address, thread_pointer=TLS)
            except a.RefillUnsupported: pass
            else: raise AssertionError((label, "expected Python rejection"))
            assert before == {k: bytes(v) for k, v in p.items()}
        rows.append(dict(case=label, rejected_before_native_export=True, input_pages_unchanged=True))
    for label in ("recursive_requires_libc", "recursive_requires_real_mutexes"):
        p = fixture(address, "first_lock"); before = {k: bytes(v) for k, v in p.items()}
        try:
            oracle.native(library, image, 0x347F00, [address], p,
                libc=None if label == "recursive_requires_libc" else libc,
                real_mutexes=label != "recursive_requires_real_mutexes", real_recursive_mutexes=True)
        except ValueError: pass
        else: raise AssertionError((label, "expected preflight rejection"))
        assert before == {k: bytes(v) for k, v in p.items()}
        rows.append(dict(case=label, rejected_at_preflight=True, input_pages_unchanged=True))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == LIBC_SHA256
    exports = bindings(args.libc)
    rows = [controls(args.library, args.libc, base, address, label, exports)
            for base in (0x122C0000, 0x775C205000) for address in MUTEXES for label in LABELS]
    sequences = [serial_sequence(args.library, args.libc, base, address, tid, exports)
                 for base in (0x122C0000, 0x775C205000) for address in MUTEXES for tid in (137, 271)]
    rows.extend(sequences)
    rejected = rejection_controls(args.library, args.libc)
    report = dict(schema="vm9-recursive-mutex-native-v1", sample_sha256=oracle.LIBRARY_SHA256,
        libc_sha256=LIBC_SHA256, cases=rows, rejection_cases=rejected, native_controls=len(rows),
        rejection_checks=len(rejected), private_serial_recursive_transitions_verified=True,
        native_constructor_attribute_sequence_verified=True, native_input_snapshot_used=False,
        host_threads_or_jvm_used=False, shared_or_waiting_paths_restored=False,
        full_python_outer_constructor_verified=False, standalone_medusa_complete=False)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("recursive mutex", len(rows), "native /", len(rejected), "rejection PASS", flush=True)


if __name__ == "__main__": main()
