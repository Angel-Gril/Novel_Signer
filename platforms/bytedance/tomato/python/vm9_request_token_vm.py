"""Bounded +0x287500 nested request VM, with independently generated inputs.

Only the two leading constant callbacks are recovered here. The first random
callback is returned as an explicit boundary; no request pages are published.
"""
from dataclasses import dataclass
from vm9_allocator import RefillUnsupported, _PageTransaction
from vm9_request_caller import prepare_request_token_vm_caller, RequestVmCallerFrame
from vm9_objects import decode_masked_bytes


@dataclass(frozen=True)
class RequestTokenVmPrefix:
    staged: object
    frame: RequestVmCallerFrame
    registers: tuple[int, ...]
    callbacks: tuple
    decoded: tuple
    pc: int
    steps: int


def execute_request_token_vm_prefix(pages, *, vm_module, maxsteps=4000, **inputs):
    """Run fresh caller state to +0x288b08 -> +0x26cc8c, transactionally.

    The backing register words come from caller memory. No native output is
    used to initialize this VM; an unknown callback remains unsupported.
    """
    if type(maxsteps) is not int or maxsteps < 1:
        raise RefillUnsupported('request token VM budget must be positive')
    staged = _PageTransaction(pages)
    frame = prepare_request_token_vm_caller(staged, **inputs)
    image = inputs['image_base']
    class StrictMem(vm_module.Mem):
        def __init__(self): self.pages = staged
        def _pg(self, address):
            if address >> 12 not in self.pages:
                raise RefillUnsupported(f'unmapped request token VM page {address:#x}')
            return self.pages[address >> 12]
    class Boundary(Exception): pass
    callbacks, decoded = [], []
    previous = vm_module.B
    try:
        vm_module.B = image
        vm = vm_module.VM(StrictMem(), frame.bytecode_offset,
            frame.packed_arguments_address, image + 0x35F5E0,
            image + 0x35F650, image + 0x2884AC,
            inputs['return_address'], maxsteps=maxsteps)
        vm.R = list(frame.registers)
        vm.register_backing_base = frame.register_backing_address
        def callback(vm, function, argument):
            words = tuple(vm.m.u64(argument + i * 8) for i in range(4))
            wrapper, target = function - image, words[0] - image
            callbacks.append((wrapper, target, argument, words))
            if (wrapper, target) == (0x288AF4, 0x167E54):
                length = decode_masked_bytes(staged, source_address=words[1],
                    destination_address=words[2], mask_address=words[3])
                decoded.append((words[2], length))
            elif (wrapper, target) == (0x288B08, 0x26CC8C):
                raise Boundary()
            else:
                raise RefillUnsupported(f'unknown request token callback +{wrapper:#x} -> +{target:#x}')
        vm.native_hook = callback
        try: vm.run()
        except Boundary:
            return RequestTokenVmPrefix(staged, frame, tuple(vm.R), tuple(callbacks),
                tuple(decoded), vm.pc, vm.steps)
        except vm_module.VMExit as exc:
            raise RefillUnsupported('request token VM exited before its supported boundary') from exc
        raise RefillUnsupported('request token VM budget exhausted before its boundary')
    finally: vm_module.B = previous
