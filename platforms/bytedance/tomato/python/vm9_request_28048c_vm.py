"""Bounded +28048c child VM with its actual +2885ac hidden-X8 wrapper."""
from dataclasses import dataclass
from vm9_allocator import _PageTransaction,RefillUnsupported,_read_span,_write_span
from vm9_request_caller import prepare_request_28048c_vm_caller,RequestVmCallerFrame
from vm9_objects import decode_masked_bytes
@dataclass(frozen=True)
class RequestVm28048cPrefix:
    staged:object
    frame:RequestVmCallerFrame
    registers:tuple[int,...]
    callbacks:tuple
    decoded:tuple
    pc:int
    steps:int
def prepare_request_28048c_wrapper_caller(pages, *, argument_block_address,
        entry_stack_address,return_address,thread_pointer,image_base,
        saved_frame_pointer=0,saved_x28=0,saved_x19=0):
    """+2885ac saves LR, loads packed X0/X8/W1/X2 and calls +28048c."""
    if type(entry_stack_address) is not int or entry_stack_address<0xF30 or entry_stack_address&15:
        raise RefillUnsupported('child wrapper stack must be aligned')
    if type(return_address) is not int or not 0<=return_address<1<<56:
        raise RefillUnsupported('child wrapper return must be an untagged address')
    p=_PageTransaction(pages)
    try:
        _write_span(p,entry_stack_address-16,return_address.to_bytes(8,'little'))
        def word(offset):return int.from_bytes(_read_span(p,argument_block_address+offset,8),'little')
        x0=word(16);target=word(0);x8=word(8)
        w1=int.from_bytes(_read_span(p,argument_block_address+24,4),'little');x2=word(32)
        if target!=image_base+0x28048C:raise RefillUnsupported('unrecovered child wrapper target')
        frame=prepare_request_28048c_vm_caller(p,entry_stack_address=entry_stack_address-16,
            return_address=image_base+0x2885C8,thread_pointer=thread_pointer,image_base=image_base,
            output_x8=x8,argument_x0=x0,argument_x1=w1,argument_x2=x2,
            saved_frame_pointer=saved_frame_pointer,saved_x28=saved_x28,saved_x19=saved_x19)
    except ValueError as exc:raise RefillUnsupported('child wrapper memory is unmapped') from exc
    p.commit();return frame
def execute_request_28048c_vm_prefix(pages, *, vm_module,maxsteps=4000,**inputs):
    """Run the first known decode; stop before the next unsupported consumer.

    The actual wrapper spill and child caller are independently generated.
    No bounded child pages publish to the supplied page map.
    """
    if type(maxsteps) is not int or maxsteps<1:raise RefillUnsupported('child VM budget must be positive')
    staged=_PageTransaction(pages);frame=prepare_request_28048c_wrapper_caller(staged,**inputs)
    image=inputs['image_base'];callbacks=[];decoded=[];previous=vm_module.B
    class StrictMem(vm_module.Mem):
        def __init__(self):self.pages=staged
        def _pg(self,address):
            if address>>12 not in self.pages:raise RefillUnsupported(f'unmapped child VM page {address:#x}')
            return self.pages[address>>12]
    class Boundary(Exception):pass
    try:
        vm_module.B=image
        vm=vm_module.VM(StrictMem(),frame.bytecode_offset,frame.packed_arguments_address,
            image+0x35D6B0,image+0x35D970,image+0x281414,image+0x2885C8,maxsteps=maxsteps)
        vm.R=list(frame.registers);vm.register_backing_base=frame.register_backing_address
        def callback(vm,function,argument):
            words=tuple(vm.m.u64(argument+i*8) for i in range(4));wrapper=function-image;target=words[0]-image
            callbacks.append((wrapper,target,argument,words))
            if (wrapper,target)==(0x281420,0x167E54):
                size=decode_masked_bytes(staged,source_address=words[1],destination_address=words[2],mask_address=words[3])
                decoded.append((words[2],size))
            else:raise Boundary()
        vm.native_hook=callback
        try:vm.run()
        except Boundary:return RequestVm28048cPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps)
        except vm_module.VMExit as exc:raise RefillUnsupported('child VM return is not recovered') from exc
        raise RefillUnsupported('child VM exhausted its budget before a boundary')
    finally:vm_module.B=previous
