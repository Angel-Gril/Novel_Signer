"""Fresh ELF interpreter controls for op17/sub53 signed 64-bit multiplication.

Both inputs are independently constructed. Original MUL/SMULH instructions
produce hidden slots 32/33; optional sub52 copies the high half into a slot.
The physical stack outside the register backing array is not compared.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os

from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span, _write_span

G = oracle.GUEST
CODE = G + 0x1000
DESC = G + 0x2000
TOP = G + 0xE000
BACK = TOP - 0x118
BASES = (0x122C0000, 0x775C205000)
MASK = (1 << 64) - 1


def profiles():
    pairs = (
        ('zero', 0, 0), ('zero_negative', 0, MASK), ('one', 1, 1),
        ('negative_one', MASK, MASK), ('negative_positive', MASK - 1, 41),
        ('positive_negative', 41, MASK - 1), ('negative_negative', MASK - 1, MASK - 2),
        ('signed_min_one', 1 << 63, 1), ('signed_min_negative_one', 1 << 63, MASK),
        ('signed_min_square', 1 << 63, 1 << 63),
        ('signed_max_square', (1 << 63) - 1, (1 << 63) - 1),
        ('opposite_limits', 1 << 63, (1 << 63) - 1),
        ('unsigned_W_boundary', 0xFFFFFFFF, 0x100000001),
        ('bit32_square', 1 << 32, 1 << 32),
        ('mixed_bits', 0xFEDCBA9876543210, 0x123456789ABCDEF0),
        ('sign_ext_W', 0xFFFFFFFF80000000, 0xFFFFFFFFFFFFFFFF),
    )
    result = [(name, dict(lhs=a, rhs=b)) for name, a, b in pairs]
    result.extend((name, dict(lhs=MASK - 7, rhs=0x123456789ABCDEF0, **kw))
        for name, kw in (
            ('same_source', dict(b=8, c=8)), ('source_R0', dict(b=0)),
            ('source_R4', dict(b=4)), ('source_R29', dict(c=29)),
            ('source_R31', dict(c=31)), ('source_R30_R16', dict(b=30, c=16)),
            ('ignored_fields_zero', dict(a=0, d=0)),
            ('ignored_fields_max', dict(a=31, d=31)),
            ('ignored_fields_alias_sources', dict(a=8, d=10)),
        ))
    return result


def fresh(library, base, profile, consume):
    pages = oracle.image_pages(library, base)
    pages.update(oracle.fresh_pages())
    def w(address, value):
        _write_span(pages, address, (value & MASK).to_bytes(8, 'little'))
    for i in range(35):
        w(BACK + i * 8, (0x1122334455667700 + i) if i >= 32 else 0)
    a, b, c, d = (profile.get(k, v) for k, v in (('a', 9), ('b', 8), ('c', 10), ('d', 11)))
    w(BACK + b * 8, profile['lhs'])
    w(BACK + c * 8, profile['rhs'])
    w(DESC, base + 0x28587C)
    w(DESC + 8, TOP)
    w(DESC + 16, oracle.STOP)
    words = [17 | (53 << 6) | (a << 12) | (b << 17) | (c << 22) | (d << 27)]
    if consume:
        words.append(17 | (52 << 6) | (b << 17))
    words.append(0x07C00791)
    _write_span(pages, CODE, b''.join(word.to_bytes(4, 'little') for word in words))
    regs = [int.from_bytes(_read_span(pages, BACK + i * 8, 8), 'little') for i in range(32)]
    regs[0] = 0
    regs[4:8] = [G + 0x5000, base + 0x35E230, base + 0x35E690, base + 0x28587C]
    regs[29] = (TOP - 0x130) & ~15
    regs[31] = oracle.STOP
    return pages, regs, words


def compare(library, base, label, profile, backed, consume):
    import vm_full
    initial, regs, words = fresh(library, base, profile, consume)
    observed = {(BACK, 0x118): None, (G, 0xA000): None}
    handlers = []
    returns = []
    def see(cpu, address):
        if address in (base + 0x16B214, base + 0x16B21C):
            handlers.append(address - base)
        if address == base + 0x172440:
            returns.append(True)
    _, _, allocations, services = oracle.native(library, base, 0x168324,
        [CODE, G + 0x5000, base + 0x35E230, base + 0x35E690, DESC], initial,
        observed_memory=observed, instruction_observer=see, instruction_limit=100000)
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
        for i, value in enumerate(regs):
            mem.w64(BACK + i * 8, value)
    before = {k: bytes(v) for k, v in pages.items()}
    try:
        try:
            vm.run()
        except vm_full.VMExit:
            pass
        else:
            raise AssertionError('VM did not exit')
    finally:
        vm_full.B = old
    native_regs = [int.from_bytes(observed[BACK, 0x118][i * 8:i * 8 + 8], 'little') for i in range(35)]
    assert returns == [True] and handlers == [0x16B214, 0x16B21C]
    assert not allocations and not services
    assert vm.R == native_regs[:32], (label, 'registers')
    assert [vm._vm_tmp32, vm._vm_tmp33, vm._vm_ll_word] == native_regs[32:], (label, 'hidden slots')
    assert _read_span(pages, G, 0xA000) == observed[G, 0xA000], (label, 'guest data')
    expected = {k: bytearray(v) for k, v in before.items()}
    if backed:
        for i in (32, 33):
            _write_span(expected, BACK + i * 8, native_regs[i].to_bytes(8, 'little'))
        if consume:
            b = profile.get('b', 8)
            _write_span(expected, BACK + b * 8, native_regs[b].to_bytes(8, 'little'))
        assert _read_span(pages, BACK, 0x118) == observed[BACK, 0x118]
    assert {k: bytes(v) for k, v in pages.items()} == {k: bytes(v) for k, v in expected.items()}
    print('PASS signed MUL64', hex(base), label, 'backed' if backed else 'abstract', 'consume' if consume else '', flush=True)
    return dict(image_base=hex(base), case=label, guest_backing=backed,
        high_half_consumed=consume, original_interpreter_returned=True,
        original_MUL_SMULH_observed=True, all_32_registers_and_3_hidden_slots_match=True,
        guest_data_and_exact_Python_write_set_match=True, entire_backing_matches=backed,
        no_allocator_or_service_calls=True, native_snapshot_input=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--group', choices=('core', 'consume', 'all'), default='core')
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC'] = str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent == Path(__file__).resolve().parent
    cases = []
    for base in BASES:
        for label, profile in profiles():
            for consume in (False, True):
                if args.group != 'all' and consume != (args.group == 'consume'):
                    continue
                for backed in (False, True):
                    cases.append(compare(args.library, base, label, profile, backed, consume))
    args.output.write_text(json.dumps(dict(component='VM signed 64-bit MUL/SMULH', cases=cases,
        native_Python_controls=len(cases), native_input_snapshot_used=False,
        whole_physical_stack_bytes_compared=False, alternate_opaque_path_verified=False,
        whole_request_native_differential_verified=False, actual_URL_header_JNI_conversion_verified=False,
        complete_python_medusa=False, fresh_signer_output_verified=False,
        live_server_matrix_verified=False), indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS', len(cases), 'fresh signed multiply controls', flush=True)


if __name__ == '__main__':
    main()
