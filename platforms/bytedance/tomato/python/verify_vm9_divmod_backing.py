"""Compare VM divmod/backing semantics with the captured ARM64 handlers."""
import json
import sys
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import *

import argparse
parser = argparse.ArgumentParser(description="Compare virtual/native register backing against ARM64 handlers.")
parser.add_argument("--memory-image", type=Path, required=True, help="Private paired vm9_m0.bin image mapped at 0x12290000.")
parser.add_argument("--output", type=Path, required=True, help="Sanitized JSON result path.")
options = parser.parse_args()
import vm_full as model
model.B = 0x122C0000
image = options.memory_image.read_bytes()
backing = 0x130F1000
frame = 0x130F2000
protected = 0x12641B28
pointer = 0x1250C59C
cases = []

class InstructionDone(Exception):
    pass

def run_one(vm, encoding):
    vm.m.w32(vm.pc, encoding)
    count = [0]
    def hook(*_):
        count[0] += 1
        if count[0] == 2:
            raise InstructionDone
    vm.step_hook = hook
    try:
        vm.run()
    except InstructionDone:
        pass

for lhs, rhs in ((1, 32), (0xffffffff, 1), (0x80000000, 3),
                 (0x123456789abcdef0, 32), (0xffffffff, 0), (0, 0)):
    for supplied in (False, True):
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpu.mem_map(0x12290000, 0x4c0000)
        cpu.mem_write(0x12290000, image)
        cpu.mem_map(0x130f0000, 0x10000)
        mem = model.Mem()
        vm = model.VM(mem, 0x9a6f0, 0, 0, 0, 0, 0)
        vm.R[1], vm.R[5], vm.R[28] = lhs, rhs, 0x12641b20
        vm.register_backing_base = backing if supplied else None
        mem.w64(protected, pointer)
        cpu.mem_write(protected, pointer.to_bytes(8, 'little'))
        for i, value in enumerate(vm.R):
            cpu.mem_write(backing + i * 8, (value & model.M64).to_bytes(8, 'little'))
        cpu.mem_write(frame - 0x18, (backing + 0x108).to_bytes(8, 'little'))
        cpu.mem_write(frame - 0x80, (0x130f3000).to_bytes(8, 'little'))
        for reg, value in ((UC_ARM64_REG_X21, 0x28020691),
                           (UC_ARM64_REG_X28, backing), (UC_ARM64_REG_X29, frame),
                           (UC_ARM64_REG_X17, backing + 0x100),
                           (UC_ARM64_REG_X19, frame - 0x80),
                           (UC_ARM64_REG_X22, frame - 0x70),
                           (UC_ARM64_REG_X23, frame - 0x60),
                           (UC_ARM64_REG_X24, frame - 0x50),
                           (UC_ARM64_REG_X25, frame - 0x40)):
            cpu.reg_write(reg, value)
        cpu.emu_start(0x1242b97c, 0x1242b9cc)
        run_one(vm, 0x28020691)
        q = int.from_bytes(cpu.mem_read(backing + 0x100, 8), 'little')
        r = int.from_bytes(cpu.mem_read(backing + 0x108, 8), 'little')
        assert (vm._vm_tmp32, vm._vm_tmp33) == (q, r)
        if supplied:
            assert (mem.u64(backing + 0x100), mem.u64(backing + 0x108)) == (q, r)
        cpu.reg_write(UC_ARM64_REG_X21, 0x20d11)
        cpu.emu_start(0x1242ad08, 0x1242ad30)
        run_one(vm, 0x20d11)
        assert vm.R[1] == int.from_bytes(cpu.mem_read(backing + 8, 8), 'little')
        if supplied:
            assert mem.u64(backing + 8) == vm.R[1]
        else:
            assert backing >> 12 not in mem.pages
        assert mem.u64(protected) == pointer
        assert int.from_bytes(cpu.mem_read(protected, 8), 'little') == pointer
        cases.append({'lhs': hex(lhs), 'rhs': hex(rhs),
                      'backing_supplied': supplied, 'quotient': hex(q),
                      'remainder': hex(r), 'native_match': True,
                      'unrelated_callback_pointer_preserved': True})

output = options.output
output.write_text(json.dumps({'cases': cases}, indent=2) + '\n', encoding='utf-8')
print(f'PASS native handler pairs={len(cases)}')
