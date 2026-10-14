"""Bounded +204e50/+204ed4 helper VMs through their actual +2814c8 wrapper."""
from dataclasses import dataclass
from vm9_allocator import _PageTransaction,RefillUnsupported,_read_span,_write_span
from vm9_request_caller import prepare_request_environment_vm_caller,RequestVmCallerFrame
from vm9_objects import decode_masked_bytes

@dataclass(frozen=True)
class RequestEnvironmentVmPrefix:
    staged:object
    frame:RequestVmCallerFrame
    registers:tuple[int,...]
    callbacks:tuple
    decoded:tuple
    pc:int
    steps:int

@dataclass(frozen=True)
class RequestEnvironmentVmAcquisitionPrefix(RequestEnvironmentVmPrefix):
    acquisitions:tuple

def prepare_request_environment_wrapper_caller(pages, *, helper_offset,
        argument_block_address,entry_stack_address,return_address,
        thread_pointer,image_base,saved_frame_pointer=0,saved_x28=0,saved_x19=0):
    """+2814c8 saves LR/X19, loads target, sets X19=packed and calls helper.

    The completed wrapper's packed+8 W result is outside this bounded caller.
    No packed bytes are initialized or overwritten while entering the helper.
    """
    if type(entry_stack_address) is not int or entry_stack_address<0x510 or entry_stack_address&15:
        raise RefillUnsupported('request environment wrapper stack must be aligned')
    if type(return_address) is not int or not 0<=return_address<1<<56:
        raise RefillUnsupported('request environment wrapper return must be untagged')
    if type(saved_x19) is not int or not 0<=saved_x19<1<<64:
        raise RefillUnsupported('request environment wrapper saved X19 must fit uint64')
    p=_PageTransaction(pages)
    try:
        _write_span(p,entry_stack_address-16,return_address.to_bytes(8,'little')+saved_x19.to_bytes(8,'little'))
        target=int.from_bytes(_read_span(p,argument_block_address,8),'little')
        if helper_offset not in (0x204E50,0x204ED4) or target!=image_base+helper_offset:
            raise RefillUnsupported('unrecovered request environment wrapper target')
        frame=prepare_request_environment_vm_caller(p,helper_offset=helper_offset,
            entry_stack_address=entry_stack_address-16,return_address=image_base+0x2814D8,
            thread_pointer=thread_pointer,image_base=image_base,saved_frame_pointer=saved_frame_pointer,
            saved_x28=saved_x28,saved_x19=argument_block_address)
    except ValueError as exc:raise RefillUnsupported('request environment wrapper memory is unmapped') from exc
    p.commit();return frame

def execute_request_environment_vm_prefix(pages, *, vm_module,maxsteps=4000,
        acquire_environment=None,**inputs):
    """Execute known decoders and the optional environment acquisition callback.

    Independent caller generation retains existing packed/padding bytes.
    Bounded pages never publish to the supplied page map.
    """
    if type(maxsteps) is not int or maxsteps<1:raise RefillUnsupported('request environment VM budget must be positive')
    if acquire_environment is not None and not callable(acquire_environment):
        raise RefillUnsupported('request environment acquisition provider must be callable')
    staged=_PageTransaction(pages);frame=prepare_request_environment_wrapper_caller(staged,**inputs)
    image=inputs['image_base'];callbacks=[];decoded=[];previous=vm_module.B
    acquisitions=[]
    class StrictMem(vm_module.Mem):
        def __init__(self):self.pages=staged
        def _pg(self,address):
            if address>>12 not in self.pages:raise RefillUnsupported(f'unmapped request environment VM page {address:#x}')
            return self.pages[address>>12]
    class Boundary(Exception):pass
    try:
        vm_module.B=image
        vm=vm_module.VM(StrictMem(),frame.bytecode_offset,frame.packed_arguments_address,
            frame.vm_call_registers[2],frame.vm_call_registers[3],image+0x2050E4,image+0x2814D8,maxsteps=maxsteps)
        vm.R=list(frame.registers);vm.register_backing_base=frame.register_backing_address
        def callback(vm,function,argument):
            words=tuple(vm.m.u64(argument+i*8) for i in range(4));wrapper=function-image;target=words[0]-image
            callbacks.append((wrapper,target,argument,words))
            if (wrapper,target) in ((0x205044,0x167E54),(0x2050F0,0x167E54)):
                size=decode_masked_bytes(staged,source_address=words[1],destination_address=words[2],mask_address=words[3])
                decoded.append((words[2],size))
            elif acquire_environment is not None and (wrapper,target)==(0x205058,0x26EDC4):
                result=apply_request_environment_acquisition_callback(staged,
                    argument_block_address=argument,image_base=image,
                    entry_stack_address=frame.native_stack_address-0x180,
                    acquire_environment=acquire_environment)
                acquisitions.append((words[1],result))
            else:raise Boundary()
        vm.native_hook=callback
        try:vm.run()
        except Boundary:
            if acquisitions:
                return RequestEnvironmentVmAcquisitionPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,tuple(acquisitions))
            return RequestEnvironmentVmPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps)
        except vm_module.VMExit as exc:raise RefillUnsupported('request environment VM return is not recovered') from exc
        raise RefillUnsupported('request environment VM exhausted its budget before a boundary')
    finally:vm_module.B=previous


def apply_request_environment_acquisition_callback(pages, *, argument_block_address,
        image_base,entry_stack_address,acquire_environment):
    """+205058 tail-calls +26edc4 with packed+8 output pair and unchanged SP.

    The supplied owner executes actual TLS/JavaVM services. No packed result
    or environment value is synthesized. Page transactions cannot reverse
    external JavaVM/provider effects.
    """
    if not callable(acquire_environment):raise RefillUnsupported('request environment acquisition provider is required')
    if type(entry_stack_address) is not int or entry_stack_address<0xE0 or entry_stack_address&15:
        raise RefillUnsupported('request environment acquisition stack must be aligned')
    p=_PageTransaction(pages)
    target=int.from_bytes(_read_span(p,argument_block_address,8),'little')
    output=int.from_bytes(_read_span(p,argument_block_address+8,8),'little')
    if target!=image_base+0x26EDC4:raise RefillUnsupported('unrecovered request environment acquisition target')
    result=acquire_environment(p,entry_stack_address=entry_stack_address,output_pair_address=output)
    p.commit();return result
