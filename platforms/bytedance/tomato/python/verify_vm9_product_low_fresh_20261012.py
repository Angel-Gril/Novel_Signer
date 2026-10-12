"""Fresh ELF original interpreter controls for op17/sub39 hidden-low copy.

The guest hidden low slot is authoritative when a backing array is supplied.
No whole physical stack or concurrent execution equivalence is claimed.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os

import verify_vm9_signer_objects as oracle
import verify_vm9_signed_multiply_fresh_20261012 as multiply
from vm9_allocator import _read_span, _write_span

G, CODE, BACK = multiply.G, multiply.CODE, multiply.BACK


def compare(library, base, label, value, dst, *, intervene=False, product=False):
    import vm_full
    profile = dict(lhs=0xFEDCBA9876543210, rhs=0x123456789ABCDEF0)
    initial, regs, mulwords = multiply.fresh(library, base, profile, False)
    def w(pages, address, word):
        _write_span(pages, address, (word & multiply.MASK).to_bytes(8, 'little'))
    w(initial, BACK + 0x100, value)
    if dst == 31:
        regs[30] = oracle.STOP
        w(initial, BACK + 30 * 8, oracle.STOP)
    exitword = 17 | (30 << 6) | ((30 if dst == 31 else 31) << 22)
    words = ([mulwords[0]] if product else []) + [17 | (39 << 6) | (dst << 12) | (9 << 17) | (10 << 22) | (11 << 27), exitword]
    _write_span(initial, CODE, b''.join(word.to_bytes(4, 'little') for word in words))
    observed = {(BACK, 0x118): None, (G, 0xA000): None}
    copied = []
    interventions = []
    def see(cpu, address):
        if address == base + 0x16AE4C:
            copied.append(True)
            if intervene:
                cpu.mem_write(BACK + 0x100, (value ^ multiply.MASK).to_bytes(8, 'little'))
                interventions.append(True)
    _, _, allocations, services = oracle.native(library, base, 0x168324,
        [CODE, G + 0x5000, base + 0x35E230, base + 0x35E690, multiply.DESC], initial,
        observed_memory=observed, instruction_observer=see, instruction_limit=100000)
    assert copied == [True] and interventions == ([True] if intervene else [])
    assert not allocations and not services
    rows = []
    for backed in ((True,) if intervene else (False, True)):
        pages = {k: bytearray(v) for k, v in initial.items()}
        mem = vm_full.Mem()
        mem.pages = pages
        old = vm_full.B
        vm_full.B = base
        vm = vm_full.VM(mem, CODE - base, G + 0x5000, base + 0x35E230,
            base + 0x35E690, base + 0x28587C, oracle.STOP, maxsteps=len(words))
        vm.R = list(regs)
        vm._vm_tmp32, vm._vm_tmp33 = (mem.u64(BACK + x) for x in (0x100, 0x108))
        vm._vm_ll_word = mem.u64(BACK + 0x110)
        if backed:
            vm.register_backing_base = BACK
            for i, word in enumerate(regs):
                mem.w64(BACK + i * 8, word)
        before = {k: bytes(v) for k, v in pages.items()}
        def step(vm, word, op, sub):
            if intervene and op == 17 and sub == 39:
                mem.w64(BACK + 0x100, value ^ multiply.MASK)
        vm.step_hook = step
        try:
            try:
                vm.run()
            except vm_full.VMExit:
                pass
            else:
                raise AssertionError('VM did not exit')
        finally:
            vm_full.B = old
        native = [int.from_bytes(observed[BACK, 0x118][i * 8:i * 8 + 8], 'little') for i in range(35)]
        assert vm.R == native[:32], (label, backed, 'registers')
        assert [vm._vm_tmp32, vm._vm_tmp33, vm._vm_ll_word] == native[32:], (label, backed, 'hidden')
        assert _read_span(pages, G, 0xA000) == observed[G, 0xA000]
        expected = {k: bytearray(v) for k, v in before.items()}
        if backed:
            for i in ({dst, 32, 33} if product else ({dst, 32} if intervene else {dst})):
                w(expected, BACK + i * 8, native[i])
            assert _read_span(pages, BACK, 0x118) == observed[BACK, 0x118]
        assert {k: bytes(v) for k, v in pages.items()} == {k: bytes(v) for k, v in expected.items()}
        rows.append(dict(image_base=hex(base), case=label, guest_backing=backed,
            original_interpreter_returned=True, original_hidden_low_load_observed=True,
            all_32_registers_and_3_hidden_slots_match=True, exact_Python_write_set_matches=True,
            authoritative_backing_intervention=intervene, signed_multiply_composition=product,
            entire_backing_matches=backed, no_allocator_or_service_calls=True,
            native_snapshot_input=False))
        print('PASS hidden low copy', hex(base), label, 'backed' if backed else 'abstract', flush=True)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--group', choices=('core', 'edges', 'all'), default='core')
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC'] = str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent == Path(__file__).resolve().parent
    cases = []
    for base in multiply.BASES:
        if args.group in ('core', 'all'):
            for label, value, dst in (
                ('zero_R8', 0, 8), ('one_R0', 1, 0), ('negative_one_R31', multiply.MASK, 31),
                ('signed_min_R16', 1 << 63, 16), ('signed_max_R30', (1 << 63) - 1, 30),
                ('high_W_bits_R4', 0xFEDCBA9876543210, 4),
                ('bit32_R29', 1 << 32, 29), ('low_W_sign_R15', 0x80000000, 15)):
                cases.extend(compare(args.library, base, label, value, dst))
        if args.group in ('edges', 'all'):
            cases.extend(compare(args.library, base, 'authoritative_backing', 0x123456789ABCDEF0, 9, intervene=True))
            cases.extend(compare(args.library, base, 'signed_product_then_copy', 0, 8, product=True))
    args.output.write_text(json.dumps(dict(component='VM hidden low product copy', cases=cases,
        native_Python_controls=len(cases), native_input_snapshot_used=False,
        whole_physical_stack_bytes_compared=False, alternate_opaque_path_verified=False,
        whole_request_native_differential_verified=False, actual_URL_header_JNI_conversion_verified=False,
        complete_python_medusa=False, fresh_signer_output_verified=False,
        live_server_matrix_verified=False), indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS', len(cases), 'fresh hidden low controls', flush=True)


if __name__ == '__main__':
    main()
