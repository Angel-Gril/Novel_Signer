"""Bounded +287474 second request VM with an independently generated caller."""
from dataclasses import dataclass
from vm9_allocator import _PageTransaction,RefillUnsupported
from vm9_request_caller import prepare_request_287474_vm_caller,RequestVmCallerFrame
from vm9_objects import decode_masked_bytes


@dataclass(frozen=True)
class RequestVm287474Prefix:
    staged: object
    frame: RequestVmCallerFrame
    registers: tuple[int,...]
    callbacks: tuple
    decoded: tuple
    pc: int
    steps: int


def execute_request_287474_vm_prefix(pages, *, vm_module, maxsteps=4000, **inputs):
    """Execute known decoder callbacks and retain the first unknown boundary.

    Undefined virtual words retain the independently supplied caller memory.
    A bounded result never publishes pages or claims a complete nested return.
    """
    if type(maxsteps) is not int or maxsteps<1:
        raise RefillUnsupported('second request VM budget must be positive')
    staged=_PageTransaction(pages);frame=prepare_request_287474_vm_caller(staged,**inputs)
    image=inputs['image_base']
    class StrictMem(vm_module.Mem):
        def __init__(self):self.pages=staged
        def _pg(self,address):
            if address>>12 not in self.pages:
                raise RefillUnsupported(f'unmapped second request VM page {address:#x}')
            return self.pages[address>>12]
    class Boundary(Exception):pass
    callbacks,decoded=[],[];previous=vm_module.B
    try:
        vm_module.B=image
        vm=vm_module.VM(StrictMem(),frame.bytecode_offset,frame.packed_arguments_address,
            image+0x35EDF0,image+0x35F3D0,image+0x2884AC,inputs['return_address'],maxsteps=maxsteps)
        vm.R=list(frame.registers);vm.register_backing_base=frame.register_backing_address
        def callback(vm,function,argument):
            words=tuple(vm.m.u64(argument+i*8) for i in range(4))
            wrapper,target=function-image,words[0]-image
            callbacks.append((wrapper,target,argument,words))
            if (wrapper,target) in ((0x288AF4,0x167E54),(0x2884B8,0x167E54)):
                length=decode_masked_bytes(staged,source_address=words[1],destination_address=words[2],mask_address=words[3])
                decoded.append((words[2],length))
            else:raise Boundary()
        vm.native_hook=callback
        try:vm.run()
        except Boundary:
            return RequestVm287474Prefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps)
        except vm_module.VMExit as exc:
            raise RefillUnsupported('second request VM return is not recovered') from exc
        raise RefillUnsupported('second request VM budget exhausted before a boundary')
    finally:vm_module.B=previous
