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

@dataclass(frozen=True)
class RequestEnvironmentVmStringsPrefix(RequestEnvironmentVmAcquisitionPrefix):
    strings:tuple

@dataclass(frozen=True)
class RequestEnvironmentVmLoggedPrefix(RequestEnvironmentVmStringsPrefix):
    logs:tuple
    vm_exit_observed:bool

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
        acquire_environment=None,consumer_services=None,**inputs):
    """Execute known decoders, optional acquisition and StringObject callbacks.

    Independent caller generation retains existing packed/padding bytes.
    Bounded pages never publish to the supplied page map.
    """
    if type(maxsteps) is not int or maxsteps<1:raise RefillUnsupported('request environment VM budget must be positive')
    if acquire_environment is not None and not callable(acquire_environment):
        raise RefillUnsupported('request environment acquisition provider must be callable')
    if consumer_services is not None and (not isinstance(consumer_services,dict) or
            any(not callable(consumer_services.get(n)) for n in ('allocate','free'))):
        raise RefillUnsupported('request environment strings require allocation and free services')
    logger_services=consumer_services.get('logger_services') if consumer_services is not None else None
    if logger_services is not None and (not isinstance(logger_services,dict) or
            any(not callable(logger_services.get(n)) for n in ('read_property','syscall')) or
            type(logger_services.get('errno_address')) is not int):
        raise RefillUnsupported('request environment logger services are invalid')
    staged=_PageTransaction(pages);frame=prepare_request_environment_wrapper_caller(staged,**inputs)
    image=inputs['image_base'];callbacks=[];decoded=[];previous=vm_module.B
    acquisitions=[]
    strings=[]
    logs=[]
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
            elif consumer_services is not None and (wrapper,target) in ((0x205064,0x248344),(0x205094,0x2484B8)):
                result=apply_request_environment_string_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image,
                    allocate=consumer_services['allocate'],free=consumer_services['free'])
                strings.append((wrapper,target,argument,result))
            elif logger_services is not None and (wrapper,target)==(0x205074,0x26E9E0):
                result=apply_request_environment_logger_callback(staged,
                    argument_block_address=argument,image_base=image,
                    entry_stack_address=frame.native_stack_address-0x180,**logger_services)
                logs.append((argument,result))
            else:raise Boundary()
        vm.native_hook=callback
        try:vm.run()
        except Boundary:
            if logs:
                return RequestEnvironmentVmLoggedPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,tuple(acquisitions),tuple(strings),tuple(logs),False)
            if strings:
                return RequestEnvironmentVmStringsPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,tuple(acquisitions),tuple(strings))
            if acquisitions:
                return RequestEnvironmentVmAcquisitionPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,tuple(acquisitions))
            return RequestEnvironmentVmPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps)
        except vm_module.VMExit as exc:
            if logs:
                # Record the VM exit boundary without publishing pages or
                # claiming the helper's native caller epilogue has returned.
                return RequestEnvironmentVmLoggedPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,tuple(acquisitions),tuple(strings),tuple(logs),True)
            raise RefillUnsupported('request environment VM return is not recovered') from exc
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


def apply_request_environment_string_callback(pages, *, wrapper_offset,
        argument_block_address,image_base,allocate,free,max_source_bytes=0x100000):
    """Actual +205064 constructor and +205094 destructor tail wrappers.

    Both load target/object before calling their existing StringObject owner;
    construction also loads packed+16 source. Neither writes a packed result.
    Page rollback cannot reverse allocation/free provider external effects.
    """
    from vm9_objects import construct_string_object,destroy_string_object
    p=_PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(p,argument_block_address+offset,8),'little')
    pair=wrapper_offset,word(0)-image_base;object_address=word(8)
    if pair==(0x205064,0x248344):
        if not callable(allocate):raise RefillUnsupported('environment string allocation provider is required')
        result=construct_string_object(p,object_address=object_address,source_address=word(16),
            allocate=allocate,vtable_address=image_base+0x34F5F8,
            empty_descriptor_address=image_base+0x6E168,max_source_bytes=max_source_bytes)
    elif pair==(0x205094,0x2484B8):
        if not callable(free):raise RefillUnsupported('environment string free provider is required')
        result=destroy_string_object(p,object_address=object_address,image_base=image_base,free=free)
    else:raise RefillUnsupported('unrecovered request environment StringObject callback')
    p.commit();return result


def apply_request_environment_logger_callback(pages, *, argument_block_address,
        image_base,entry_stack_address,read_property,syscall,errno_address):
    """+205074 calls the existing literal logger at wrapper SP-16.

    Target/object/format are packed Q words at offsets0/8/16. Store only the
    returned low W at packed+24; preserve its upper padding. Supported sink
    and format behavior remains owned by vm9_logger.log_literal_unavailable.
    Physical register spills and external provider rollback are not modeled.
    """
    from vm9_logger import log_literal_unavailable
    if type(entry_stack_address) is not int or not 0x600<=entry_stack_address<1<<64 or entry_stack_address&15:
        raise RefillUnsupported('request environment logger stack must be aligned')
    if not callable(read_property) or not callable(syscall):
        raise RefillUnsupported('request environment logger providers must be callable')
    p=_PageTransaction(pages)
    words=tuple(int.from_bytes(_read_span(p,argument_block_address+i*8,8),'little') for i in range(3))
    if words[0]!=image_base+0x26E9E0:raise RefillUnsupported('unrecovered request environment logger target')
    result=log_literal_unavailable(p,object_address=words[1],format_address=words[2],
        entry_stack_address=entry_stack_address-16,image_base=image_base,
        read_property=read_property,syscall=syscall,errno_address=errno_address)
    _write_span(p,argument_block_address+24,(result.return_value&0xFFFFFFFF).to_bytes(4,'little'))
    p.commit();return result
