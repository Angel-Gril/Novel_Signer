"""Bounded +28048c child VM with its actual +2885ac hidden-X8 wrapper."""
from dataclasses import dataclass
from vm9_allocator import _PageTransaction,RefillUnsupported,_read_span,_write_span
from vm9_request_caller import prepare_request_28048c_vm_caller,RequestVmCallerFrame
from vm9_objects import decode_masked_bytes
from vm9_effects import require_effect_journal
@dataclass(frozen=True)
class RequestVm28048cPrefix:
    staged:object
    frame:RequestVmCallerFrame
    registers:tuple[int,...]
    callbacks:tuple
    decoded:tuple
    pc:int
    steps:int

@dataclass(frozen=True)
class RequestVm28048cHelperPrefix(RequestVm28048cPrefix):
    helper_prefix:object

@dataclass(frozen=True)
class RequestVm28048cAvailabilityPrefix(RequestVm28048cPrefix):
    helper_prefix:object
    availability:tuple

@dataclass(frozen=True)
class RequestVm28048cEnvironmentPrefix(RequestVm28048cAvailabilityPrefix):
    acquisitions:tuple

@dataclass(frozen=True)
class RequestVm28048cStringsPrefix(RequestVm28048cEnvironmentPrefix):
    strings:tuple

@dataclass(frozen=True)
class RequestVm28048cRegistryPrefix(RequestVm28048cStringsPrefix):
    registry_reads:tuple

@dataclass(frozen=True)
class RequestVm28048cExitPrefix(RequestVm28048cRegistryPrefix):
    vm_exit_observed:bool

@dataclass(frozen=True)
class RequestVm28048cReturnedPrefix(RequestVm28048cExitPrefix):
    caller_return:object
    exit_state:object
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
def execute_request_28048c_vm_prefix(pages, *, vm_module,maxsteps=4000,
        consumer_services=None,continue_caller_return=False,effect_journal=None,**inputs):
    """Run known child callbacks; stop before the next unsupported consumer.

    The actual wrapper spill and child caller are independently generated.
    Bounded child pages remain private. An explicitly continued, validated
    caller return publishes child pages into the containing transaction.
    """
    if type(maxsteps) is not int or maxsteps<1:raise RefillUnsupported('child VM budget must be positive')
    if type(continue_caller_return) is not bool:raise RefillUnsupported('child return continuation must be boolean')
    effect_journal=require_effect_journal(effect_journal)
    if consumer_services is not None and (not isinstance(consumer_services,dict) or
            any(not callable(consumer_services.get(n)) for n in ('allocate','free'))):
        raise RefillUnsupported('child request consumers require allocation and free services')
    if consumer_services is not None and consumer_services.get('jni_availability_services') is not None:
        services=consumer_services['jni_availability_services']
        if not isinstance(services,dict) or not callable(services.get('invoke_jni')):
            raise RefillUnsupported('child JNI availability requires an explicit JNI service')
    staged=_PageTransaction(pages);frame=prepare_request_28048c_wrapper_caller(staged,**inputs)
    image=inputs['image_base'];callbacks=[];decoded=[];previous=vm_module.B
    helpers=[]
    availability=[]
    acquisitions=[]
    strings=[]
    registry_reads=[]
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
            elif consumer_services is not None and (wrapper,target) in (
                    (0x281434,0x248274),(0x281448,0x347F20),
                    (0x28145C,0x347F60),(0x281470,0x2A9280)):
                apply_request_28048c_consumer(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image,
                    allocate=consumer_services['allocate'])
            elif consumer_services is not None and wrapper==0x2814C8 and target in (0x204E50,0x204ED4):
                from vm9_request_environment_vm import execute_request_environment_vm_prefix
                helper=execute_request_environment_vm_prefix(staged,vm_module=vm_module,
                    acquire_environment=consumer_services.get('acquire_environment'),
                    consumer_services=consumer_services,
                    continue_caller_return=consumer_services.get('logger_services') is not None,
                    effect_journal=effect_journal,
                    helper_offset=target,argument_block_address=argument,
                    entry_stack_address=frame.native_stack_address-0x180,
                    return_address=image+0x16AA4C,thread_pointer=inputs['thread_pointer'],image_base=image,
                    saved_frame_pointer=frame.native_stack_address-0x60,
                    saved_x28=frame.register_backing_address,saved_x19=frame.register_backing_address-8)
                helpers.append(helper)
                if getattr(helper,'caller_return',None) is None:raise Boundary()
            elif consumer_services is not None and (wrapper,target)==(0x2814C8,0x204B80) and consumer_services.get('jni_availability_services') is not None:
                from vm9_request_caller import execute_request_jni_availability_wrapper
                returned=execute_request_jni_availability_wrapper(staged,image_base=image,
                    entry_stack_address=frame.native_stack_address-0x180,
                    argument_block_address=argument,return_address=image+0x16AA4C,
                    thread_pointer=inputs['thread_pointer'],
                    saved_frame_pointer=frame.native_stack_address-0x60,
                    saved_x28=frame.register_backing_address,saved_x19=frame.register_backing_address-8,
                    acquire_environment=consumer_services.get('acquire_environment'),
                    invoke_jni=consumer_services['jni_availability_services']['invoke_jni'])
                availability.append((argument,returned))
            elif consumer_services is not None and (wrapper,target)==(0x2814E4,0x26EDC4) and consumer_services.get('acquire_environment') is not None:
                from vm9_request_environment_vm import apply_request_environment_acquisition_callback
                acquired=apply_request_environment_acquisition_callback(staged,
                    argument_block_address=argument,image_base=image,
                    entry_stack_address=frame.native_stack_address-0x180,
                    acquire_environment=consumer_services['acquire_environment'],
                    effect_journal=effect_journal)
                acquisitions.append((argument,acquired))
            elif consumer_services is not None and (wrapper,target) in ((0x28155C,0x248344),(0x28158C,0x2484B8)):
                from vm9_request_environment_vm import apply_request_environment_string_callback
                constructed=apply_request_environment_string_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image,
                    allocate=consumer_services['allocate'],free=consumer_services['free'])
                strings.append((wrapper,target,argument,constructed))
            elif consumer_services is not None and (wrapper,target)==(0x28156C,0x256A18):
                value=apply_request_28048c_registry_read_callback(staged,
                    argument_block_address=argument,image_base=image,
                    entry_stack_address=frame.native_stack_address-0x180)
                registry_reads.append((argument,value))
            else:raise Boundary()
        vm.native_hook=callback
        try:vm.run()
        except Boundary:
            if registry_reads:
                return RequestVm28048cRegistryPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    helpers[-1] if helpers else None,tuple(availability),tuple(acquisitions),tuple(strings),tuple(registry_reads))
            if strings:
                return RequestVm28048cStringsPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    helpers[-1] if helpers else None,tuple(availability),tuple(acquisitions),tuple(strings))
            if acquisitions:
                return RequestVm28048cEnvironmentPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    helpers[-1] if helpers else None,tuple(availability),tuple(acquisitions))
            if availability:
                return RequestVm28048cAvailabilityPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    helpers[-1] if helpers else None,tuple(availability))
            if helpers:
                return RequestVm28048cHelperPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,helpers[-1])
            return RequestVm28048cPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps)
        except vm_module.VMExit as exc:
            if registry_reads and strings and strings[-1][:2]==(0x28158C,0x2484B8):
                result=RequestVm28048cExitPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    helpers[-1] if helpers else None,tuple(availability),tuple(acquisitions),tuple(strings),tuple(registry_reads),True)
                if not continue_caller_return:return result
                from vm9_request_caller import validate_request_28048c_vm_exit,finish_request_28048c_wrapper_caller
                exit_state=validate_request_28048c_vm_exit(staged,image_base=image,pc=vm.pc,registers=tuple(vm.R))
                caller_return=finish_request_28048c_wrapper_caller(staged,image_base=image,
                    entry_stack_address=inputs['entry_stack_address'],thread_pointer=inputs['thread_pointer'],
                    callback_sentinel=int.from_bytes(_read_span(staged,frame.descriptor_address,8),'little'))
                returned=RequestVm28048cReturnedPrefix(**vars(result),caller_return=caller_return,exit_state=exit_state)
                staged.commit();return returned
            raise RefillUnsupported('child VM return is not recovered') from exc
        raise RefillUnsupported('child VM exhausted its budget before a boundary')
    finally:vm_module.B=previous


def apply_request_28048c_registry_read_callback(pages, *, argument_block_address,
        image_base,entry_stack_address,max_nodes=4096,max_bytes=0x100000):
    """+28156c invokes +256a18 at SP-16 and stores low W at packed+24.

    Only the getter's declared scoped guard is modeled on the stack; full
    wrapper spills and physical return registers are not part of this owner.
    """
    from vm9_registry import read_configuration_u32
    if type(entry_stack_address) is not int or entry_stack_address<0x60 or entry_stack_address&15:
        raise RefillUnsupported('child configuration wrapper stack must be aligned')
    p=_PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(p,argument_block_address+offset,8),'little')
    target=word(0);registry=word(8);key=word(16)
    if target!=image_base+0x256A18:raise RefillUnsupported('unrecovered child configuration read target')
    value=read_configuration_u32(p,registry_address=registry,key_address=key,
        entry_stack_address=entry_stack_address-16,image_base=image_base,
        max_nodes=max_nodes,max_bytes=max_bytes)
    _write_span(p,argument_block_address+24,value.to_bytes(4,'little'))
    p.commit();return value


def apply_request_28048c_consumer(pages, *, wrapper_offset,
        argument_block_address,image_base,allocate,max_bytes=0x100000):
    """Actual child filled-string, memset, memcpy and local-copy wrappers.

    Filled construction reads BYTE fill and W length; memset reads BYTE fill
    and Q size. Only +281470 stores the returned destination at packed+32.
    Imported memcpy requires disjoint ranges or identical pointers. +2a9280
    shares the second VM's ordered scalar/vector copy owner.
    """
    from vm9_objects import construct_filled_string_object
    from vm9_request_287474_vm import _copy_request_287474_bytes
    if type(max_bytes) is not int or not 0<=max_bytes<=0x100000:
        raise RefillUnsupported('invalid child request consumer size bound')
    p=_PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(p,argument_block_address+offset,8),'little')
    pair=wrapper_offset,word(0)-image_base;destination=word(8)
    if pair==(0x281434,0x248274):
        fill=_read_span(p,argument_block_address+16,1)[0]
        length=int.from_bytes(_read_span(p,argument_block_address+20,4),'little')
        result=construct_filled_string_object(p,object_address=destination,
            fill=fill,length=length,image_base=image_base,allocate=allocate,
            max_payload_bytes=max_bytes)
    elif pair==(0x281448,0x347F20):
        fill=_read_span(p,argument_block_address+16,1)[0];length=word(24)
        if length>max_bytes:raise RefillUnsupported('child memset exceeds the explicit bound')
        if length:_write_span(p,destination,bytes([fill])*length)
        result=destination
    elif pair in ((0x28145C,0x347F60),(0x281470,0x2A9280)):
        source,length=word(16),word(24)
        if length>max_bytes:raise RefillUnsupported('child copy exceeds the explicit bound')
        if pair[0]==0x28145C:
            if source!=destination and length and abs(destination-source)<length:
                raise RefillUnsupported('overlapping imported memcpy is not recovered')
            if length:_write_span(p,destination,_read_span(p,source,length))
        else:
            _copy_request_287474_bytes(p,destination,source,length)
            _write_span(p,argument_block_address+32,destination.to_bytes(8,'little'))
        result=destination
    else:raise RefillUnsupported('unrecovered child request consumer')
    p.commit();return result
