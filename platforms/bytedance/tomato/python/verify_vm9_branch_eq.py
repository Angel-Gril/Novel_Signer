"""Native differences for OP45 register equality and its signed displacement.

All instructions and register values are synthetic. The native handler is the
oracle only; the Python interpreter never consumes native checkpoint inputs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
from unicorn.arm64_const import (UC_ARM64_REG_X19, UC_ARM64_REG_X21,
    UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X28, UC_ARM64_REG_X30)
from verify_vm9_signer_objects import native, fresh_pages, GUEST, LIBRARY_SHA256
from vm9_allocator import _write_span


def encode_branch(a, b, displacement):
    if not (0 <= a < 32 and 0 <= b < 32 and -32768 <= displacement <= 32767):
        raise ValueError('invalid equality branch operands')
    imm = displacement & 0xffff
    return (45 | (a & 15) << 22 | (a >> 4) << 31 |
        (b & 15) << 7 | (b >> 4) << 21 | (imm & 31) << 16 |
        ((imm >> 5) & 31) << 26 | ((imm >> 10) & 31) << 11 |
        (imm >> 15) << 6)


def controls():
    # Exercise every register index and both values of the disputed high bit.
    for b in range(32):
        a = (b + 9) % 32
        for displacement in (9, -31744):
            for equal in (True, False):
                regs = [0x100000000 + i * 17 for i in range(32)]
                regs[a] = 0xffffffffffffffff
                regs[b] = regs[a] if equal else 0x7fffffffffffffff
                yield a, b, displacement, regs
    # Former "sub=0/33/53" guesses must also match ordinary register equality.
    for a, b, displacement in ((7, 0, 0), (19, 0, -1), (8, 10, -31744)):
        for left, right in ((0, 0), (0, 1), (0xffffffffffffffff, 0), (1, 1)):
            regs = [i + 10 for i in range(32)]
            regs[a], regs[b] = left, right
            yield a, b, displacement, regs
    for displacement in (-32768, -1024, -1, 1, 1023, 1024, 32767):
        for equal in (False, True):
            regs = [i + 10 for i in range(32)]
            regs[31], regs[16] = 17, 17 if equal else 18
            yield 31, 16, displacement, regs


def probe(library, vm_module, base, a, b, displacement, registers):
    pc = base + 0x120000
    word = encode_branch(a, b, displacement)
    pages = fresh_pages()
    pages[pc >> 12] = bytearray(4096)
    _write_span(pages, pc, word.to_bytes(4, 'little'))
    _write_span(pages, GUEST + 0x100, pc.to_bytes(8, 'little'))
    _write_span(pages, GUEST + 0x1000,
        b''.join(value.to_bytes(8, 'little') for value in registers))
    _, memory, allocations, effects = native(library, base, 0x16ECEC, [], pages,
        extra_registers={UC_ARM64_REG_X19:GUEST+0x100,
            UC_ARM64_REG_X28:GUEST+0x1000, UC_ARM64_REG_X22:GUEST+0x200,
            UC_ARM64_REG_X23:GUEST+0x208, UC_ARM64_REG_X30:GUEST+0x210,
            UC_ARM64_REG_X21:0}, stop_offset=0x16EE38)
    expected = int.from_bytes(memory[0x100:0x108], 'little')
    assert int.from_bytes(memory[0x200:0x204], 'little') == a
    assert int.from_bytes(memory[0x208:0x20c], 'little') == b
    assert int.from_bytes(memory[0x210:0x212], 'little') == displacement & 0xffff
    assert not allocations and not effects
    backing = b''.join(v.to_bytes(8, 'little') for v in registers)
    assert memory[0x1000:0x1100] == backing
    model_memory = object.__new__(vm_module.Mem)
    model_memory.pages = {}
    model_memory.w32(pc, word)
    previous = vm_module.B
    try:
        vm_module.B = base
        model = vm_module.VM(model_memory, pc-base, 0, 0, 0, 0, 0, maxsteps=1)
        model.R = list(registers)
        try:
            model.run()
        except RuntimeError as exc:
            assert str(exc).startswith('step limit @')
        else:
            raise AssertionError('one-instruction control failed to stop')
        assert model.pc == expected, (a, b, displacement,
            hex(model.pc-pc), hex(expected-pc))
        assert model.R == registers, 'register clobber'
    finally:
        vm_module.B = previous
    return registers[a] == registers[b]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC'] = str(args.library.resolve())
    import vm_full
    results = []
    for base in (0x122c0000, 0x775c205000):
        taken = [probe(args.library, vm_full, base, *control) for control in controls()]
        results.append(dict(image_base=hex(base), controls=len(taken),
            taken=sum(taken), not_taken=len(taken)-sum(taken),
            all_register_indices_covered=True, signed_displacement_edges_match=True,
            native_operand_decode_match=True, next_pc_match=True,
            all_32_registers_unchanged=True))
    report = dict(library_sha256=LIBRARY_SHA256, cases=results,
        native_runs=sum(r['controls'] for r in results),
        synthetic_inputs=True, native_input_snapshot_used=False,
        native_code_used_by_python_model=False,
        handler_entry_offset='0x16ecec', stop_offset='0x16ee38',
        opcode=45, operation='64-bit register equality',
        second_register_high_bit=21, sub_bits_are_operands=True,
        complete_python_medusa=False)
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(native_runs=report['native_runs'], equality_branches_match=True)))


if __name__ == '__main__':
    main()
