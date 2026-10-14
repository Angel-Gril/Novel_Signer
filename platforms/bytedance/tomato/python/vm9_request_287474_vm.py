"""Bounded +287474 second request VM with an independently generated caller."""
from dataclasses import dataclass
from vm9_allocator import _PageTransaction,RefillUnsupported,_read_span,_write_span
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


@dataclass(frozen=True)
class RequestVm287474ChildPrefix(RequestVm287474Prefix):
    child_prefix: object


@dataclass(frozen=True)
class RequestVm287474StringsPrefix(RequestVm287474ChildPrefix):
    strings: tuple


@dataclass(frozen=True)
class RequestVm287474ReaderPrefix(RequestVm287474StringsPrefix):
    reader_acquisitions: tuple


@dataclass(frozen=True)
class RequestVm287474DiagnosticPrefix(RequestVm287474ReaderPrefix):
    diagnostics: tuple


@dataclass(frozen=True)
class RequestVm287474DiagnosticCleanupPrefix(RequestVm287474DiagnosticPrefix):
    diagnostic_leaves: tuple


def execute_request_287474_vm_prefix(pages, *, vm_module, maxsteps=4000,
        consumer_services=None, **inputs):
    """Execute known decoder callbacks and retain the first unknown boundary.

    Undefined virtual words retain the independently supplied caller memory.
    A bounded result never publishes pages or claims a complete nested return.
    """
    if type(maxsteps) is not int or maxsteps<1:
        raise RefillUnsupported('second request VM budget must be positive')
    if consumer_services is not None and (not isinstance(consumer_services,dict) or
            any(not callable(consumer_services.get(n)) for n in ('allocate','free'))):
        raise RefillUnsupported('second request consumers require allocation and free services')
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
    children=[]
    strings=[]
    reader_acquisitions=[]
    diagnostics=[]
    diagnostic_leaves=[]
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
            elif consumer_services is not None and (wrapper,target) in (
                    (0x2884CC,0x2481AC),(0x2884CC,0x2484B8),
                    (0x288578,0x248274),(0x2884D8,0x347F60),(0x28858C,0x2A9280)):
                apply_request_287474_consumer(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image,
                    allocate=consumer_services['allocate'],free=consumer_services['free'])
            elif consumer_services is not None and (wrapper,target)==(0x288530,0x26C858):
                from vm9_request_token_vm import apply_token_diagnostic_callback
                scope=apply_token_diagnostic_callback(staged,argument_block_address=argument,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    allocate=consumer_services['allocate'],thread_id=consumer_services.get('thread_id'),
                    observer=consumer_services.get('diagnostic_observer'))
                diagnostics.append((argument,scope))
            elif consumer_services is not None and (wrapper,target)==(0x288540,0x26C9D0):
                from vm9_request_token_vm import apply_token_diagnostic_callback
                result=apply_token_diagnostic_callback(staged,argument_block_address=argument,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    allocate=consumer_services['allocate'],thread_id=consumer_services.get('thread_id'),
                    observer=consumer_services.get('diagnostic_observer'))
                diagnostic_leaves.append((argument,result))
            elif consumer_services is not None and (wrapper,target)==(0x2885E0,0x32A444):
                readers=apply_request_287474_reader_acquisition_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image)
                reader_acquisitions.append((argument,readers))
            elif consumer_services is not None and (wrapper,target)==(0x2885D0,0x248344):
                from vm9_request_environment_vm import apply_request_environment_string_callback
                constructed=apply_request_environment_string_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image,
                    allocate=consumer_services['allocate'],free=consumer_services['free'])
                strings.append((wrapper,target,argument,constructed))
            elif consumer_services is not None and (wrapper,target)==(0x2885AC,0x28048C):
                from vm9_request_28048c_vm import execute_request_28048c_vm_prefix
                child=execute_request_28048c_vm_prefix(staged,vm_module=vm_module,
                    maxsteps=20000,consumer_services=consumer_services,continue_caller_return=True,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    return_address=image+0x16AA4C,thread_pointer=inputs['thread_pointer'],image_base=image,
                    saved_frame_pointer=frame.native_stack_address-0x60,
                    saved_x28=frame.register_backing_address,saved_x19=frame.register_backing_address-8)
                children.append(child)
                if getattr(child,'caller_return',None) is None:raise Boundary()
            else:raise Boundary()
        vm.native_hook=callback
        try:vm.run()
        except Boundary:
            if diagnostic_leaves:
                return RequestVm287474DiagnosticCleanupPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves))
            if diagnostics:
                return RequestVm287474DiagnosticPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics))
            if reader_acquisitions:
                return RequestVm287474ReaderPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions))
            if strings:
                return RequestVm287474StringsPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings))
            if children:
                return RequestVm287474ChildPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,children[-1])
            return RequestVm287474Prefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps)
        except vm_module.VMExit as exc:
            raise RefillUnsupported('second request VM return is not recovered') from exc
        raise RefillUnsupported('second request VM budget exhausted before a boundary')
    finally:vm_module.B=previous


def apply_request_287474_reader_acquisition_callback(pages, *, wrapper_offset,
        argument_block_address,image_base):
    """+2885e0 tail-calls the existing +32a444 shared-reader owner.

    Declare receiver/packed bytes and reuse normal mutex transitions. Native
    physical guard/canary/PAC and concurrent/writer/wait paths stay outside
    this semantic callback. The returned reader count is internal metadata.
    """
    from vm9_objects import acquire_uncontended_shared_reader
    p=_PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(p,argument_block_address+offset,8),'little')
    if (wrapper_offset,word(0)-image_base)!=(0x2885E0,0x32A444):
        raise RefillUnsupported('unrecovered second shared-reader callback')
    readers=acquire_uncontended_shared_reader(p,mutex_address=word(8))
    p.commit();return readers


def apply_request_287474_consumer(pages, *, wrapper_offset,
        argument_block_address, image_base, allocate, free, max_bytes=0x100000):
    """Actual second-VM lifecycle, imported memcpy and local copy wrappers.

    +288578 loads a byte fill and W length. Only +28858c publishes X0 at
    packed+32; the tail wrappers leave their packed bytes alone. Imported
    memcpy accepts disjoint ranges or identical pointers. The local +2a9280
    owner preserves its own ordered loads/stores, including overlapping ranges.
    """
    import vm9_objects as objects
    if type(max_bytes) is not int or not 0<=max_bytes<=0x100000:
        raise RefillUnsupported('invalid second request consumer size bound')
    p=_PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(p,argument_block_address+offset,8),'little')
    pair=wrapper_offset,word(0)-image_base
    destination=word(8)
    if pair==(0x2884CC,0x2481AC):
        result=objects.construct_string_object(p,object_address=destination,source_address=0,
            allocate=allocate,vtable_address=image_base+0x34F5F8,
            empty_descriptor_address=image_base+0x6E168)
    elif pair==(0x2884CC,0x2484B8):
        result=objects.destroy_string_object(p,object_address=destination,
            image_base=image_base,free=free)
    elif pair==(0x288578,0x248274):
        fill=_read_span(p,argument_block_address+16,1)[0]
        length=int.from_bytes(_read_span(p,argument_block_address+20,4),'little')
        result=objects.construct_filled_string_object(p,object_address=destination,
            fill=fill,length=length,image_base=image_base,allocate=allocate,
            max_payload_bytes=max_bytes)
    elif pair in ((0x2884D8,0x347F60),(0x28858C,0x2A9280)):
        source,length=word(16),word(24)
        if length>max_bytes:
            raise RefillUnsupported('second request copy exceeds the explicit bound')
        if pair[0]==0x2884D8:
            if source!=destination and length and abs(destination-source)<length:
                raise RefillUnsupported('overlapping imported memcpy is not recovered')
            if length:_write_span(p,destination,_read_span(p,source,length))
        else:
            _copy_request_287474_bytes(p,destination,source,length)
            _write_span(p,argument_block_address+32,destination.to_bytes(8,'little'))
        result=destination
    else:raise RefillUnsupported('unrecovered second request consumer')
    p.commit()
    return result


def _copy_request_287474_bytes(pages,destination,source,length):
    """+2a9280 ordered scalar/vector loads and forward/backward aligned loops."""
    end_source,end_destination=source+length,destination+length
    def load(address,width=16):return _read_span(pages,address,width)
    def store(address,data):_write_span(pages,address,data)
    if length<=32:
        if length>=16:width=16
        elif length>=8:width=8
        elif length>=4:width=4
        elif length:
            first,last,middle=load(source,1),load(end_source-1,1),load(source+(length>>1),1)
            store(destination,first);store(destination+(length>>1),middle);store(end_destination-1,last)
            return
        else:return
        first,last=load(source,width),load(end_source-width,width)
        store(destination,first);store(end_destination-width,last)
        return
    if length<=128:
        first,second,last_two,last=load(source),load(source+16),load(end_source-32),load(end_source-16)
        if length>64:
            third,fourth=load(source+32),load(source+48)
            if length>96:
                tail_four,tail_three=load(end_source-64),load(end_source-48)
                store(end_destination-64,tail_four);store(end_destination-48,tail_three)
            store(destination,first);store(destination+16,second)
            store(destination+32,third);store(destination+48,fourth)
        else:
            store(destination,first);store(destination+16,second)
        store(end_destination-32,last_two);store(end_destination-16,last)
        return
    if destination==source:return
    if (destination-source)&0xFFFFFFFFFFFFFFFF>=length:
        first=load(source);alignment=destination&15
        output=destination&~15;current=source-alignment
        a=load(current+16);store(destination,first)
        b,c,d=load(current+32),load(current+48),load(current+64)
        current+=64;remaining=length+alignment-144
        while remaining>0:
            store(output+16,a);a=load(current+16)
            store(output+32,b);b=load(current+32)
            store(output+48,c);c=load(current+48)
            store(output+64,d);output+=64;current+=64;d=load(current)
            remaining-=64
        tail_a=load(end_source-64);store(output+16,a)
        tail_b=load(end_source-48);store(output+32,b)
        tail_c=load(end_source-32);store(output+48,c)
        tail_d=load(end_source-16);store(output+64,d)
        store(end_destination-64,tail_a);store(end_destination-48,tail_b)
        store(end_destination-32,tail_c);store(end_destination-16,tail_d)
    else:
        last=load(end_source-16);alignment=end_destination&15
        current=end_source-alignment;output=end_destination-alignment
        a=load(current-16);store(end_destination-16,last)
        b,c,d=load(current-32),load(current-48),load(current-64)
        current-=64;remaining=length-alignment-128
        while remaining>0:
            store(output-16,a);a=load(current-16)
            store(output-32,b);b=load(current-32)
            store(output-48,c);c=load(current-48)
            store(output-64,d);output-=64;current-=64;d=load(current)
            remaining-=64
        head_d=load(source+48);store(output-16,a)
        head_c=load(source+32);store(output-32,b)
        head_b=load(source+16);store(output-48,c)
        head_a=load(source);store(output-64,d)
        store(destination+48,head_d);store(destination+32,head_c)
        store(destination+16,head_b);store(destination,head_a)
