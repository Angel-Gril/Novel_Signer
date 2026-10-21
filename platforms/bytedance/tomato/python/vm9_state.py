"""Observed state VM/caller from guest inputs and explicit environment effects.

Default shared reference, %s/%% formatting, unavailable log/file/socket profile
and one-entry scoped writer tree are bounded component models. No native or
captured VM prelude is required by construct_state_caller. Unsupported branches
reject page writes; external effects are outside transactional rollback.
"""
from __future__ import annotations
from dataclasses import dataclass
import math
import struct
import vm9_objects as objects
import vm9_configuration_init as configuration
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported


def find_state_member(pages, *, root_address, key_address,
        max_nodes=4096, max_comparisons=0x100000):
    """+0x24a0a0 ASCII case-insensitive linked member lookup.

    Preserve NULL-root/key and identical-key-pointer short circuits. Keys are
    C strings even when the caller's StringObject declares a longer length.
    Bounds count visited nodes and actual byte-pair comparisons, respectively.
    """
    for value in (max_nodes, max_comparisons):
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 0x100000:
            raise ValueError('invalid state lookup bound')
    if not root_address or not key_address:
        return 0
    node = int.from_bytes(_read_span(pages, root_address + 0x10, 8), 'little')
    seen = set()
    comparisons = 0
    while node:
        if node in seen or len(seen) == max_nodes:
            raise RefillUnsupported('state member cycle or node bound exceeded')
        seen.add(node)
        name = int.from_bytes(_read_span(pages, node + 0x38, 8), 'little')
        if name:
            if name == key_address:
                return node
            offset = 0
            while True:
                if comparisons == max_comparisons:
                    raise RefillUnsupported('state member comparison bound exceeded')
                left = _read_span(pages, key_address + offset, 1)[0]
                right = _read_span(pages, name + offset, 1)[0]
                comparisons += 1
                folded_left = left | 0x20 if 0x41 <= left <= 0x5A else left
                folded_right = right | 0x20 if 0x41 <= right <= 0x5A else right
                if folded_left != folded_right:
                    break
                if not left:
                    return node
                offset += 1
        node = int.from_bytes(_read_span(pages, node, 8), 'little')
    return 0


def read_state_integer_member(pages, *, service_address, key_object_address,
        max_nodes=4096, max_comparisons=0x100000):
    """+0x269bf4/+0x269c80 nested shared-reader lookup and FCVTZS W0.

    Type byte must equal 8. Missing or nonnumeric values convert -1.0.
    ARM64 conversion truncates toward zero, saturates overflow and maps NaN
    to zero. Return the zero-extended W0 bits. Only serialized, uncontended
    shared-reader state is supported; failure rolls back all page bytes.
    """
    transaction = _PageTransaction(pages)
    def acquire():
        mutex = int.from_bytes(_read_span(transaction, service_address + 0x20, 8), 'little')
        objects.acquire_uncontended_shared_reader(transaction, mutex_address=mutex + 8)
        _write_span(transaction, mutex + 0x94, b'\x01')
        return mutex
    def release(mutex):
        if _read_span(transaction, mutex + 0x94, 1)[0] != 1:
            raise RefillUnsupported('state numeric reader changed to writer mode')
        objects.release_uncontended_shared_reader(transaction, mutex_address=mutex + 8)
    outer_mutex = acquire()
    inner_mutex = acquire()
    root = int.from_bytes(_read_span(transaction, service_address + 0x18, 8), 'little')
    key = int.from_bytes(_read_span(transaction, key_object_address + 0x10, 8), 'little')
    node = find_state_member(transaction, root_address=root, key_address=key,
        max_nodes=max_nodes, max_comparisons=max_comparisons)
    if node and _read_span(transaction, node + 0x18, 1)[0] == 8:
        value = struct.unpack('<d', _read_span(transaction, node + 0x30, 8))[0]
    else:
        value = -1.0
    release(inner_mutex)
    release(outer_mutex)
    if math.isnan(value):
        result = 0
    elif value >= 0x7FFFFFFF:
        result = 0x7FFFFFFF
    elif value <= -0x80000000:
        result = -0x80000000
    else:
        result = math.trunc(value)
    transaction.commit()
    return result & 0xFFFFFFFF


def get_state_service_reference(pages, *, entry_stack_address, thread_pointer,
        image_base, vm_module, allocate, reallocate, free, get_tls,
        initialize_registry, broadcast, read_property, syscall, errno_address,
        mkdir, register_destructor, thread_id=None, prepare_format=None,
        logger_observer=None, diagnostic_scope=None):
    """+0x26a3ac serialized lazy state service, including its cold VM body.

    Loaded ELF owns the lazy key. The caller supplies environment services;
    native output and captured preludes are never used. Cold state creation
    requires singleton136 already initialized by the outer constructor.
    Preserve allocation,
    temporary cleanup and guard publication order. External service effects
    remain outside page rollback; contention and concurrent guards reject.
    An explicit diagnostic_scope enables the state VM's diagnostic callbacks;
    the default retains the historical component exclusion.
    """
    if not isinstance(entry_stack_address, int) or entry_stack_address & 15:
        raise RefillUnsupported('state service requires an aligned entry stack')
    transaction = _PageTransaction(pages)
    def address(offset):return objects._image_address(image_base, offset)
    def word(pointer,value):_write_span(transaction,pointer,objects._word(value))
    _read_span(transaction,entry_stack_address-0x60,0x60)
    _read_span(transaction,thread_pointer+0x28,8)
    if int.from_bytes(_read_span(transaction,address(0x3DED50),4),'little') == 0:
        objects.decode_masked_bytes(transaction,source_address=address(0xA4674),
            destination_address=address(0x3DED4C),mask_address=address(0xA4688))
        _write_span(transaction,address(0x3DED50),(1).to_bytes(4,'little'))
    guard_address,slot_address=address(0x3DED68),address(0x3DED60)
    guard=_read_span(transaction,guard_address,8)
    slot=int.from_bytes(_read_span(transaction,slot_address,8),'little')
    if guard[0] or guard[1] == 1:
        transaction.commit()
        return objects.LazyReference(guard_address,slot_address,slot,0,0,0)
    if guard[1] & 2:
        raise RefillUnsupported('state service guard is recursive or contended')
    if not isinstance(thread_id,int) or not 0 <= thread_id <= 0xFFFFFFFF:
        raise RefillUnsupported('cold state service requires an explicit uint32 thread id')
    sdk_guard=_read_span(transaction,address(0x3D1680),2)
    sdk_slot=int.from_bytes(_read_span(transaction,address(0x3D1678),8),'little')
    if not (sdk_guard[0] or sdk_guard[1] == 1) or not sdk_slot:
        raise RefillUnsupported('cold state service requires initialized singleton136')
    _write_span(transaction,guard_address+4,thread_id.to_bytes(4,'little'))
    _write_span(transaction,guard_address+1,b'\x02')
    wrapper=objects._allocate(transaction,allocate,16)
    payload=objects._allocate(transaction,allocate,48)
    temporary=entry_stack_address-0x60
    objects.construct_string_object(transaction,object_address=temporary,
        source_address=address(0x3DED4C),allocate=allocate,
        vtable_address=address(0x34F5F8),empty_descriptor_address=address(0x6E168))
    construct_initialized_state_owner(transaction,object_address=payload,
        source_object_address=temporary,flag=1,entry_stack_address=temporary,
        return_address=address(0x26A498),thread_pointer=thread_pointer,image_base=image_base,
        vm_module=vm_module,allocate=allocate,reallocate=reallocate,free=free,
        get_tls=get_tls,initialize_registry=initialize_registry,broadcast=broadcast,
        read_property=read_property,syscall=syscall,errno_address=errno_address,mkdir=mkdir,
        register_destructor=register_destructor,thread_id=thread_id,
        prepare_format=prepare_format,logger_observer=logger_observer,
        diagnostic_scope=diagnostic_scope)
    if diagnostic_scope is None:
        counter=objects.construct_reference_wrapper(transaction,object_address=wrapper,
            referenced_address=payload,allocate=allocate)
    else:
        import vm9_reference_scopes
        # The prefix's +1625b4 saves its uint32 flag (one here) in X19.
        # Its zero high word survives as +25728c's diagnostic scope padding.
        _write_span(transaction,entry_stack_address-0xA4,bytes(4))
        counter=vm9_reference_scopes.construct_scoped_string_reference(transaction,
            reference_address=wrapper,string_address=payload,
            entry_stack_address=entry_stack_address-0x60,image_base=image_base,
            thread_pointer=thread_pointer,allocate=allocate,thread_id=thread_id,
            diagnostic_observer=lambda *event:diagnostic_scope.setdefault('events',[]).append(list(event)))
    objects.destroy_string_object(transaction,object_address=temporary,image_base=image_base,free=free)
    word(slot_address,wrapper)
    _write_span(transaction,guard_address,b'\x01')
    _write_span(transaction,guard_address+1,b'\x01')
    transaction.commit()
    return objects.LazyReference(guard_address,slot_address,wrapper,payload,48,counter)


def read_request_elapsed_seconds(pages, *, object_address, read_clock):
    """+0x26bf90/+0x26bf18 elapsed getter under a serialized shared reader.

    Read the saved millisecond word before invoking the realtime provider.
    Wrapped signed-positive deltas are selected; other deltas select the
    current clock word. The final division treats that word as unsigned.
    Clock errors and unsupported mutex transitions roll back page bytes;
    provider effects outside guest pages remain external.
    """
    import vm9_callbacks
    staged=_PageTransaction(pages)
    objects.acquire_uncontended_shared_reader(staged,mutex_address=object_address+8)
    _write_span(staged,object_address+0x94,b'\x01')
    start=int.from_bytes(_read_span(staged,object_address+0x98,8),'little')
    mask=(1<<64)-1
    now=vm9_callbacks.read_realtime_milliseconds(staged,read_clock=read_clock)&mask
    delta=(now-start)&mask
    selected=delta if 0<delta<(1<<63) else now
    if _read_span(staged,object_address+0x94,1)!=b'\x01':
        raise RefillUnsupported('request elapsed reader changed to writer mode')
    objects.release_uncontended_shared_reader(staged,mutex_address=object_address+8)
    staged.commit()
    return selected//1000


def construct_request_clock_state(pages, *, object_address, entry_stack_address,
        image_base, get_state_service, allocate, free, get_tls,
        initialize_registry, broadcast, max_nodes=4096, max_comparisons=0x100000):
    """+0x26bdfc state construction with numeric default and writer cleanup.

    The provider returns the original lazy wrapper from current guest state.
    Diagnostic scopes are excluded here. The global reference must retain
    positive ownership after the temporary copy is released; deleting a state
    service through this helper remains unsupported.
    """
    if not isinstance(entry_stack_address,int) or entry_stack_address & 15:
        raise RefillUnsupported('request clock state requires an aligned stack')
    staged=_PageTransaction(pages)
    stack=entry_stack_address-0x60
    _read_span(staged,stack,0x20)
    _write_span(staged,object_address,bytes(0x98))
    objects.construct_mutex_state(staged,object_address=object_address,image_base=image_base)
    _write_span(staged,object_address+0x98,bytes(8))
    wrapper=get_state_service(staged,stack)
    objects.copy_reference_wrapper(staged,object_address=stack,source_address=wrapper)
    service=int.from_bytes(_read_span(staged,stack,8),'little')
    flag=image_base+0x3DED80
    if int.from_bytes(_read_span(staged,flag,4),'little') == 0:
        objects.decode_masked_bytes(staged,source_address=image_base+0xA5580,
            destination_address=image_base+0x3DED70,mask_address=image_base+0xA5590)
        _write_span(staged,flag,(1).to_bytes(4,'little'))
    key=stack+0x10
    objects.construct_string_object(staged,object_address=key,source_address=image_base+0x3DED70,
        allocate=allocate,vtable_address=image_base+0x34F5F8,empty_descriptor_address=image_base+0x6E168)
    value=read_state_integer_member(staged,service_address=service,key_object_address=key,
        max_nodes=max_nodes,max_comparisons=max_comparisons)
    # +0x269c34 leaves its successful shared-acquire W status in this
    # scratch word. The later scoped TLS node copies three of its bytes
    # as padding; retain the upper four bytes from caller memory.
    _write_span(staged,stack-0x40,bytes(4))
    objects.destroy_string_object(staged,object_address=key,image_base=image_base,free=free)
    objects.construct_single_scoped_lock(staged,object_address=key,mutex_address=object_address,
        scratch_address=stack-0x48,image_base=image_base,allocate=allocate,get_tls=get_tls,
        initialize_registry=initialize_registry)
    signed=0 if value == 0xFFFFFFFF else objects._s32(value)
    _write_span(staged,object_address+0x98,objects._word(signed & ((1<<64)-1)))
    objects.destroy_single_scoped_lock(staged,object_address=key,image_base=image_base,free=free,
        get_tls=get_tls,initialize_registry=initialize_registry,broadcast=broadcast,
        entry_stack_address=stack)
    counter=int.from_bytes(_read_span(staged,stack+8,8),'little')
    if counter:
        remaining=(int.from_bytes(_read_span(staged,counter,4),'little')-1)&0xFFFFFFFF
        if objects._s32(remaining)<=0:
            raise RefillUnsupported('request clock state cannot delete its shared state service')
        _write_span(staged,counter,remaining.to_bytes(4,'little'))
    staged.commit()
    return signed & ((1<<64)-1)


@dataclass
class StateResult:
    steps: int
    stop_offset: int
    registers: tuple[int,...]
    modeled_callbacks: list[dict]


class StateCallbacks:
    def __init__(self, *, image_base, native_stack_address, allocate, reallocate,
            free, get_tls, initialize_registry, broadcast, read_property,
            syscall, errno_address, mkdir, register_destructor,
            thread_id=None, prepare_format=None, logger_observer=None,
            thread_pointer=None, diagnostic_scope=None):
        if diagnostic_scope is not None:
            if not isinstance(diagnostic_scope,dict):
                raise RefillUnsupported('state diagnostic scope requires a dictionary')
            if type(thread_pointer) is not int or not 0<=thread_pointer<1<<64:
                raise RefillUnsupported('state diagnostic scope requires an explicit thread pointer')
        self.base,self.stack=image_base,native_stack_address
        self.allocate,self.reallocate,self.free=allocate,reallocate,free
        self.get_tls,self.initialize_registry,self.broadcast=get_tls,initialize_registry,broadcast
        self.read_property,self.syscall,self.errno,self.mkdir=read_property,syscall,errno_address,mkdir
        self.register,self.thread_id,self.prepare_format=register_destructor,thread_id,prepare_format
        self.logger_observer=logger_observer
        self.thread_pointer,self.diagnostic_scope=thread_pointer,diagnostic_scope
        self.modeled=[]

    def __call__(self,vm,function,argument):
        b,p=self.base,vm.m.pages;wrapper=function-b
        words=[vm.m.u64(argument+i*8) for i in range(4)];target=words[0]-b
        allocate,reallocate,free=self.allocate,self.reallocate,self.free
        if (wrapper,target)==(0x26A4C8,0x167E54):
            objects.decode_masked_bytes(p,source_address=words[1],destination_address=words[2],mask_address=words[3])
        elif (wrapper,target)==(0x26A4DC,0x268EB0):
            objects.construct_single_scoped_lock(p,object_address=words[1],mutex_address=words[2],
                scratch_address=self.stack-0x1C8,image_base=b,allocate=allocate,
                get_tls=self.get_tls,initialize_registry=self.initialize_registry)
        elif (wrapper,target)==(0x26A4EC,0x25EE84):
            copy_reference=assign_reference=release_reference=construct_reference=None
            if self.diagnostic_scope is not None:
                import vm9_reference_scopes
                def construct_reference(tx,**kw):
                    return vm9_reference_scopes.construct_scoped_string_reference(tx,**kw,
                        image_base=b,thread_pointer=self.thread_pointer,allocate=allocate,
                        thread_id=self.thread_id,diagnostic_observer=lambda *event:
                            self.diagnostic_scope.setdefault('events',[]).append(list(event)))
                def copy_reference(tx,**kw):
                    return vm9_reference_scopes.copy_scoped_string_reference(tx,**kw,
                        image_base=b,thread_pointer=self.thread_pointer,allocate=allocate,
                        thread_id=self.thread_id,diagnostic_observer=lambda *event:
                            self.diagnostic_scope.setdefault('events',[]).append(list(event)))
                def assign_reference(tx,**kw):
                    return vm9_reference_scopes.assign_scoped_owned_string_reference(tx,**kw,
                        image_base=b,thread_pointer=self.thread_pointer,allocate=allocate,free=free,
                        thread_id=self.thread_id,diagnostic_observer=lambda *event:
                            self.diagnostic_scope.setdefault('events',[]).append(list(event)))
                def release_reference(tx,**kw):
                    return vm9_reference_scopes.release_scoped_string_reference(tx,**kw,
                        image_base=b,thread_pointer=self.thread_pointer,allocate=allocate,free=free,
                        thread_id=self.thread_id,diagnostic_observer=lambda *event:
                            self.diagnostic_scope.setdefault('events',[]).append(list(event)))
            configuration.construct_environment_reference(p,output_reference_address=words[1],
                entry_stack_address=self.stack-0x190,image_base=b,allocate=allocate,reallocate=reallocate,
                free=free,read_property=self.read_property,syscall=self.syscall,errno_address=self.errno,
                mkdir=self.mkdir,thread_id=self.thread_id,register_destructor=self.register,
                prepare_format=self.prepare_format,logger_observer=self.logger_observer,
                reference_copier=copy_reference,reference_assigner=assign_reference,
                reference_releaser=release_reference,thread_pointer=self.thread_pointer,
                reference_constructor=construct_reference)
        elif wrapper==0x26A500 and target in (0x2481AC,0x2484B8,0x2484FC):
            if target==0x2481AC:
                objects.construct_string_object(p,object_address=words[1],source_address=0,allocate=allocate,
                    vtable_address=b+0x34F5F8,empty_descriptor_address=b+0x6E168)
            else:objects.destroy_string_object(p,object_address=words[1],image_base=b,free=free,delete_object=target==0x2484FC)
        elif (wrapper,target)==(0x26A50C,0x258780):
            if self.diagnostic_scope is None:
                objects.construct_digest_reference(p,object_address=words[1],source_object_address=words[2],
                    algorithm='sha1',flag=words[3]&255,image_base=b,allocate=allocate,reallocate=reallocate,free=free)
            else:
                import vm9_reference_scopes
                vm9_reference_scopes.construct_scoped_digest_reference(p,
                    output_reference_address=words[1],source_object_address=words[2],
                    entry_stack_address=self.stack-0x190,image_base=b,thread_pointer=self.thread_pointer,
                    algorithm='sha1',flag=words[3]&255,allocate=allocate,reallocate=reallocate,free=free,
                    thread_id=self.thread_id,diagnostic_observer=lambda *event:
                        self.diagnostic_scope.setdefault('events',[]).append(list(event)))
        elif (wrapper,target)==(0x26A52C,0x248908):
            configuration.format_string_object(p,object_address=words[1],format_address=words[2],
                argument_addresses=(words[3],vm.m.u64(argument+32),vm.m.u64(argument+40)),image_base=b,
                allocate=allocate,reallocate=reallocate,free=free,prepare_format=self.prepare_format)
        elif wrapper in (0x26A544,0x26A560) and target in (0x26C858,0x26C9D0):
            if self.diagnostic_scope is not None:
                import vm9_diagnostics
                context=self.diagnostic_scope
                def observe(*event):context.setdefault('events',[]).append(list(event))
                if (wrapper,target)==(0x26A544,0x26C858):
                    scope=vm9_diagnostics.enter_diagnostic_scope(p,
                        object_address=words[1],input_word=words[2],image_base=b,
                        thread_pointer=self.thread_pointer,allocate=allocate,
                        thread_id=self.thread_id,observer=observe)
                    context.setdefault('scopes',[]).append(scope)
                elif (wrapper,target)==(0x26A560,0x26C9D0):
                    result=vm9_diagnostics.leave_diagnostic_scope(p,
                        object_address=words[1],image_base=b,
                        thread_pointer=self.thread_pointer,observer=observe)
                    context.setdefault('leaves',[]).append(result)
                else:raise RefillUnsupported('unexpected state diagnostic wrapper/target pair')
        elif (wrapper,target)==(0x26A554,0x32A264):free(p,words[1])
        elif (wrapper,target)==(0x26A56C,0x25DDEC):
            vm.m.wb(argument+16,int(configuration.environment_path_exists(p,object_address=words[1],
                syscall=self.syscall,errno_address=self.errno)))
        elif (wrapper,target)==(0x26A628,0x24A4D8):
            vm.m.w64(argument+8,configuration.construct_empty_state_container(p,image_base=b,allocate=allocate))
        elif (wrapper,target)==(0x26A644,0x268FBC):
            objects.destroy_single_scoped_lock(p,object_address=words[1],image_base=b,free=free,
                get_tls=self.get_tls,initialize_registry=self.initialize_registry,broadcast=self.broadcast,
                entry_stack_address=self.stack-0x180)
        else:raise RefillUnsupported(f'unrecovered state callback +{wrapper:#x} -> +{target:#x}')
        self.modeled.append({'wrapper_offset':hex(wrapper),'target_offset':hex(target)})


def construct_state_caller(pages, *, object_address, source_object_address,
        entry_stack_address, return_address, thread_pointer, image_base,
        vm_module, allocate, reallocate, free, get_tls, initialize_registry,
        broadcast, read_property, syscall, errno_address, mkdir,
        register_destructor, thread_id=None, prepare_format=None, max_steps=100000,
        logger_observer=None, diagnostic_scope=None):
    """+0x269988 prelude and observed +0xa46a0 VM, returning all32 virtual slots."""
    if not isinstance(max_steps,int) or not 1<=max_steps<=1000000:
        raise ValueError('invalid state instruction bound')
    if entry_stack_address&15:raise RefillUnsupported('state caller stack must be aligned')
    if not isinstance(return_address,int) or not 0<=return_address<1<<56:
        raise RefillUnsupported('PAC-tagged state return address is unsupported')
    staged=_PageTransaction(pages);stack=entry_stack_address-0x6D0
    _read_span(staged,stack-0x400,0xAD8);_read_span(staged,image_base+0xA46A0,4)
    def word(address,value):
        if not isinstance(value,int) or not 0<=value<1<<64:raise RefillUnsupported('state caller word must fit uint64')
        _write_span(staged,address,value.to_bytes(8,'little'))
    word(stack,object_address);word(stack+8,source_object_address)
    word(stack+16,image_base+0x26A650);word(stack+24,stack+0x6A0);word(stack+32,return_address)
    _write_span(staged,entry_stack_address-0x28,_read_span(staged,thread_pointer+0x28,8))
    initial=[int.from_bytes(_read_span(staged,stack+0x588+i*8,8),'little') for i in range(32)]
    class StrictMem(vm_module.Mem):
        def __init__(self,pages):self.pages=pages
        def _pg(self,address):
            if address>>12 not in self.pages:raise RefillUnsupported('unmapped state guest page')
            return self.pages[address>>12]
    previous=vm_module.B
    try:
        vm_module.B=image_base
        vm=vm_module.VM(StrictMem(staged),0xA46A0,stack,image_base+0x35D2D0,
            image_base+0x35D330,image_base+0x26A650,return_address,maxsteps=max_steps)
        vm.R=initial;vm.R[0]=0;vm.R[4:8]=[stack,image_base+0x35D2D0,image_base+0x35D330,image_base+0x26A650]
        vm.R[29]=(stack+0x570)&~15;vm.R[31]=return_address
        callbacks=StateCallbacks(image_base=image_base,native_stack_address=stack,
            allocate=allocate,reallocate=reallocate,free=free,get_tls=get_tls,
            initialize_registry=initialize_registry,broadcast=broadcast,read_property=read_property,
            syscall=syscall,errno_address=errno_address,mkdir=mkdir,register_destructor=register_destructor,
            thread_id=thread_id,prepare_format=prepare_format,logger_observer=logger_observer,
            thread_pointer=thread_pointer,diagnostic_scope=diagnostic_scope)
        vm.native_hook=callbacks
        try:vm.run()
        except vm_module.VMExit:pass
        else:raise RefillUnsupported('state caller did not reach explicit VM exit')
        result=StateResult(vm.steps,vm.pc-image_base,tuple(vm.R),callbacks.modeled)
        staged.commit();return result
    finally:vm_module.B=previous


def construct_initialized_state_owner(pages, *, object_address, source_object_address,
        flag, entry_stack_address, return_address, thread_pointer, image_base,
        vm_module, allocate, **environment):
    """+0x2698f0 prefix and tail caller; source X1 reloads the cloned string."""
    staged=_PageTransaction(pages)
    context=environment.get('diagnostic_scope')
    construct_reference=None
    if context is not None:
        if not isinstance(context,dict):
            raise RefillUnsupported('state diagnostic scope requires a dictionary')
        import vm9_reference_scopes
        def construct_reference(p,*,reference_address,string_address):
            return vm9_reference_scopes.construct_scoped_string_reference(p,
                reference_address=reference_address,string_address=string_address,
                entry_stack_address=entry_stack_address-0x40,image_base=image_base,
                thread_pointer=thread_pointer,allocate=allocate,
                thread_id=environment.get('thread_id'),diagnostic_observer=lambda *event:
                    context.setdefault('events',[]).append(list(event)))
    objects.construct_mutex_backed_string_owner_prefix(staged,object_address=object_address,
        source_object_address=source_object_address,flag=flag,image_base=image_base,allocate=allocate,
        reference_constructor=construct_reference)
    # Measured surviving +0x1625a4/operator-new and +0x17d7e0 spill words.
    # They occupy otherwise retained virtual slots in the tail caller backing.
    # Generate these ABI inputs from current frame/ELF/TLS/clone addresses;
    # do not import the later native VM entry prelude to fill them.
    def word(address,value):_write_span(staged,address,value.to_bytes(8,'little'))
    word(entry_stack_address-0xB0,entry_stack_address-0x70)
    word(entry_stack_address-0xA8,image_base+0x1625E4)
    word(entry_stack_address-0xA0,int.from_bytes(_read_span(staged,object_address+8,8),'little'))
    _write_span(staged,entry_stack_address-0x78,_read_span(staged,thread_pointer+0x28,8))
    word(entry_stack_address-0x70,entry_stack_address-0x40)
    word(entry_stack_address-0x68,image_base+0x269940)
    word(entry_stack_address-0x58,image_base+0x269964)
    source=int.from_bytes(_read_span(staged,object_address+8,8),'little')
    result=construct_state_caller(staged,object_address=object_address,source_object_address=source,
        entry_stack_address=entry_stack_address,return_address=return_address,thread_pointer=thread_pointer,
        image_base=image_base,vm_module=vm_module,allocate=allocate,**environment)
    staged.commit();return result
