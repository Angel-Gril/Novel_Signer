"""Synthetic fresh-input checks for unsigned W operands and hidden product slots."""
from __future__ import annotations
import argparse,hashlib,json,os
from pathlib import Path
from unicorn.arm64_const import (UC_ARM64_REG_X17,UC_ARM64_REG_X19,
 UC_ARM64_REG_X21,UC_ARM64_REG_X22,UC_ARM64_REG_X23,UC_ARM64_REG_X24,
 UC_ARM64_REG_X25,UC_ARM64_REG_X28,UC_ARM64_REG_X29)
from verify_vm9_signer_objects import native,fresh_pages,GUEST,LIBRARY_SHA256
from vm9_allocator import _write_span


def encode(a,c,b,d):return 17|(57<<6)|(a<<12)|(b<<17)|(c<<22)|(d<<27)


def controls():
    for a,c in ((1,8),(31,16),(0,0),(7,7)):
        for left,right in ((0,0),(1,1),(0xFFFFFFFF,2),(0x80000000,2),
              (0xFFFFFFFF,0xFFFFFFFF),(0x80000000,0x80000000),
              (0xFFFFFFFF80000081,0xDEADBEEF000000FF)):
            yield a,c,11,19,left,right
    for index in range(32):yield index,(index+17)&31,(index+1)&31,(index+2)&31,0xDEADBEEFffffffff,0xABCDEF0080000000


def probe(library,vm_module,base,control,backed):
    a,c,b,d,left,right=control;registers=[0x100000000+i*53 for i in range(32)]
    registers[a]=left;registers[c]=right
    backing=GUEST+0x1000;frame=GUEST+0x2000;pc=GUEST+0x3000
    pages=fresh_pages();word=encode(a,c,b,d)
    _write_span(pages,backing,b''.join(v.to_bytes(8,'little') for v in registers))
    _write_span(pages,backing+0x100,bytes.fromhex('aabbccddeeff00112233445566778899'))
    _write_span(pages,frame-0x18,(backing+0x108).to_bytes(8,'little'))
    _write_span(pages,GUEST+0x100,pc.to_bytes(8,'little'))
    _write_span(pages,pc,word.to_bytes(4,'little')+b'\x11\0\0\0')
    _,memory,allocations,effects=native(library,base,0x16B618,[],pages,stop_offset=0x16B6E4,
        extra_registers={UC_ARM64_REG_X21:word,UC_ARM64_REG_X28:backing,
         UC_ARM64_REG_X29:frame,UC_ARM64_REG_X19:GUEST+0x100,
         UC_ARM64_REG_X17:backing+0x100,UC_ARM64_REG_X22:GUEST+0x200,
         UC_ARM64_REG_X23:GUEST+0x210,UC_ARM64_REG_X24:GUEST+0x220,
         UC_ARM64_REG_X25:GUEST+0x230},instruction_limit=1000)
    assert not allocations and not effects
    expected=tuple(int.from_bytes(memory[x:x+8],'little') for x in (0x1100,0x1108))
    assert memory[0x1000:0x1100]==b''.join(v.to_bytes(8,'little') for v in registers)
    assert [int.from_bytes(memory[x:x+4],'little') for x in (0x200,0x210,0x220,0x230)]==[c,a,d,b]
    mem=object.__new__(vm_module.Mem);mem.pages={key:bytearray(value) for key,value in pages.items()}
    previous=vm_module.B
    try:
        vm_module.B=base;vm=vm_module.VM(mem,pc-base,0,0,0,0,0,maxsteps=1)
        vm.R=list(registers);vm.register_backing_base=backing if backed else None
        try:vm.run()
        except RuntimeError as exc:assert str(exc).startswith('step limit @')
        assert (vm._vm_tmp32,vm._vm_tmp33)==expected,(control,backed,expected)
        assert vm.R==registers
        if backed:assert mem.rd(backing+0x100,16)==memory[0x1100:0x1110]
        else:assert mem.rd(backing+0x100,16)==bytes.fromhex('aabbccddeeff00112233445566778899')
        assert vm.pc==pc+4
    finally:vm_module.B=previous
    return dict(image_base=hex(base),operand_indices=[a,c],upper_words_ignored=True,
        hidden_backing_supplied=backed,low_and_high_signed_words_match=True,
        visible_32_registers_unchanged=True,native_input_snapshot_used=False)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve());import vm_full
    cases=[probe(args.library,vm_full,base,control,backed) for base in (0x122C0000,0x775C205000)
        for control in controls() for backed in (False,True)]
    report=dict(library_sha256=LIBRARY_SHA256,native_runs=len(cases),cases=cases,
        handler_entry_offset='0x16b618',native_stop_offset='0x16b6e4',opcode=17,subopcode=57,
        operation='unsigned W multiplication with sign-extended low and high product words',
        native_input_snapshot_used=False,complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),multiply_hidden_slots_match=True)))
if __name__=='__main__':main()
