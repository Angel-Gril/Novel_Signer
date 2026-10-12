"""Bounded +0x287500 nested request VM, with independently generated inputs.

Constants, random, shared readers, scopes and string lifecycle reuse owners.
The next StringObject append is an explicit boundary; no pages are published.
"""
from dataclasses import dataclass
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
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


def execute_request_token_vm_prefix(pages, *, vm_module, maxsteps=4000,
        random_services=None, continue_shared_readers=False, diagnostic_services=None,
        string_services=None, **inputs):
    """Run a recovered prefix to the next explicit callback boundary.

    The backing register words come from caller memory. No native output is
    used to initialize this VM; an unknown callback remains unsupported.
    """
    if type(maxsteps) is not int or maxsteps < 1:
        raise RefillUnsupported('request token VM budget must be positive')
    if type(continue_shared_readers) is not bool:
        raise RefillUnsupported('request token shared-reader continuation must be boolean')
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
                if random_services is None:
                    raise Boundary()
                from vm9_request_random import store_request_random_callback
                store_request_random_callback(staged,argument_block_address=argument,
                    entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    libc_base=random_services['libc_base'],syscall=random_services['syscall'],
                    errno_address=random_services['errno_address'],thread_id=random_services.get('thread_id'))
            elif random_services is not None and (wrapper,target) in (
                    (0x288B24,0x32A444),(0x288B24,0x32A4FC)):
                if not continue_shared_readers:
                    raise Boundary()
                apply_token_shared_reader_callback(staged,argument_block_address=argument,
                    image_base=image,entry_stack_address=frame.native_stack_address-0x180,
                    thread_pointer=inputs['thread_pointer'])
            elif continue_shared_readers and (wrapper,target)==(0x288B30,0x26C858):
                if diagnostic_services is None:
                    raise Boundary()
                scope=apply_token_diagnostic_callback(staged,argument_block_address=argument,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    allocate=diagnostic_services['allocate'],thread_id=diagnostic_services.get('thread_id'),
                    observer=diagnostic_services.get('observer'))
                diagnostic_services.setdefault('entered_scopes',[]).append(scope)
            elif diagnostic_services is not None and (wrapper,target)==(0x288B40,0x26C9D0):
                apply_token_diagnostic_callback(staged,argument_block_address=argument,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    allocate=diagnostic_services['allocate'],thread_id=diagnostic_services.get('thread_id'),
                    observer=diagnostic_services.get('observer'))
            elif diagnostic_services is not None and (wrapper,target)==(0x288B4C,0x2483E0):
                if string_services is None:
                    raise Boundary()
                apply_token_string_lifecycle_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image,
                    allocate=string_services['allocate'],free=string_services['free'])
            elif string_services is not None and (wrapper,target) in (
                    (0x288B5C,0x32A264),(0x288B68,0x2481AC),
                    (0x288B68,0x2484B8),(0x288B68,0x2484FC)):
                apply_token_string_lifecycle_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image,
                    allocate=string_services['allocate'],free=string_services['free'])
            elif string_services is not None and (wrapper,target)==(0x288B74,0x248908):
                apply_token_string_transform_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image,
                    entry_stack_address=frame.native_stack_address-0x180,
                    allocate=string_services['allocate'],reallocate=string_services['reallocate'],
                    free=string_services['free'],prepare_format=string_services.get('prepare_format'))
            elif string_services is not None and (wrapper,target) in (
                    (0x288B8C,0x2481FC),(0x288BA0,0x248780)):
                apply_token_string_transform_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image,
                    entry_stack_address=frame.native_stack_address-0x180,
                    allocate=string_services['allocate'],reallocate=string_services['reallocate'],
                    free=string_services['free'])
            elif string_services is not None and (wrapper,target)==(0x288BBC,0x25874C):
                apply_token_digest_callback(staged,argument_block_address=argument,image_base=image,
                    entry_stack_address=frame.native_stack_address-0x180,
                    thread_pointer=inputs['thread_pointer'],allocate=string_services['allocate'],
                    reallocate=string_services['reallocate'],free=string_services['free'],
                    thread_id=diagnostic_services.get('thread_id'),observer=diagnostic_services.get('observer'))
            elif string_services is not None and (wrapper,target)==(0x288BDC,0x287580):
                apply_token_cipher_callback(staged,argument_block_address=argument,image_base=image,
                    entry_stack_address=frame.native_stack_address-0x180,
                    thread_pointer=inputs['thread_pointer'],allocate=string_services['allocate'],
                    reallocate=string_services['reallocate'],free=string_services['free'])
            elif string_services is not None and (wrapper,target)==(0x288BF0,0x248684):
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


def apply_token_shared_reader_callback(pages, *, argument_block_address,
        image_base, entry_stack_address, thread_pointer):
    """+0x288b24 -> +0x32a444/+0x32a4fc, reusing serial reader owners.

    Acquire keeps the defined local pointer, byte flag and canary; physical
    register spills and PAC are separate boundaries. The normal native return
    is the final mutex-unlock result, zero, rather than the new reader count.
    """
    from vm9_objects import acquire_uncontended_shared_reader,release_uncontended_shared_reader
    if (type(entry_stack_address) is not int or entry_stack_address<0x80
            or entry_stack_address>=1<<64 or entry_stack_address&15):
        raise RefillUnsupported('shared-reader callback stack must be aligned')
    p=_PageTransaction(pages)
    target=int.from_bytes(_read_span(p,argument_block_address,8),'little')-image_base
    pointer=int.from_bytes(_read_span(p,argument_block_address+8,8),'little')
    if target==0x32A444:
        canary=entry_stack_address-0x38
        _write_span(p,canary,_read_span(p,thread_pointer+0x28,8))
        _write_span(p,entry_stack_address-0x48,pointer.to_bytes(8,'little'))
        _write_span(p,entry_stack_address-0x40,b'\1')
        acquire_uncontended_shared_reader(p,mutex_address=pointer)
        if _read_span(p,canary,8)!=_read_span(p,thread_pointer+0x28,8):
            raise RefillUnsupported('shared-reader callback stack canary mismatch')
    elif target==0x32A4FC:
        release_uncontended_shared_reader(p,mutex_address=pointer)
    else:
        raise RefillUnsupported('unrecovered token shared-reader callback target')
    p.commit()
    return 0


def apply_token_diagnostic_callback(pages, *, argument_block_address,
        image_base, thread_pointer, allocate, thread_id=None, observer=None):
    """+0x288b30/+0x288b40 enter/leave consumers using the accepted scope owner.

    Native callback results are communicated through guest objects. This
    adapter does not claim a physical X0 return ABI for scope constructors.
    """
    import vm9_diagnostics as scopes
    p=_PageTransaction(pages)
    target=int.from_bytes(_read_span(p,argument_block_address,8),'little')-image_base
    obj=int.from_bytes(_read_span(p,argument_block_address+8,8),'little')
    if target==0x26C858:
        word=int.from_bytes(_read_span(p,argument_block_address+16,8),'little')
        result=scopes.enter_diagnostic_scope(p,object_address=obj,input_word=word,
            image_base=image_base,thread_pointer=thread_pointer,allocate=allocate,
            thread_id=thread_id,observer=observer)
    elif target==0x26C9D0:
        result=scopes.leave_diagnostic_scope(p,object_address=obj,
            image_base=image_base,thread_pointer=thread_pointer,observer=observer)
    else:
        raise RefillUnsupported('unrecovered token diagnostic callback target')
    p.commit()
    return result


def apply_token_string_lifecycle_callback(pages, *, wrapper_offset,
        argument_block_address, image_base, allocate, free,
        max_payload_bytes=0x100000):
    """Actual +288b4c clone / +288b5c free / +288b68 lifecycle consumers.

    Tail wrappers load the target, destination and optional source from packed
    words. Their results remain in guest objects. Clone/default return the
    accepted owner's X0 value; cleanup has no declared physical return value.
    """
    import vm9_objects as objects
    p=_PageTransaction(pages)
    target=int.from_bytes(_read_span(p,argument_block_address,8),'little')-image_base
    pointer=int.from_bytes(_read_span(p,argument_block_address+8,8),'little')
    pair=(wrapper_offset,target)
    if pair==(0x288B4C,0x2483E0):
        source=int.from_bytes(_read_span(p,argument_block_address+16,8),'little')
        result=objects.clone_string_object(p,object_address=pointer,
            source_object_address=source,image_base=image_base,allocate=allocate,
            max_payload_bytes=max_payload_bytes)
    elif pair==(0x288B68,0x2481AC):
        result=objects.construct_string_object(p,object_address=pointer,source_address=0,
            allocate=allocate,vtable_address=image_base+0x34F5F8,
            empty_descriptor_address=image_base+0x6E168)
    elif pair in ((0x288B68,0x2484B8),(0x288B68,0x2484FC)):
        result=objects.destroy_string_object(p,object_address=pointer,image_base=image_base,
            free=free,delete_object=target==0x2484FC)
    elif pair==(0x288B5C,0x32A264):
        free(p,pointer)
        result=None
    else:
        raise RefillUnsupported('unrecovered token string lifecycle callback')
    p.commit()
    return result


def apply_token_string_transform_callback(pages, *, wrapper_offset,
        argument_block_address, image_base, entry_stack_address,
        allocate, reallocate, free, prepare_format=None, max_bytes=0x100000):
    """+288b74 format, +288b8c sized string, +288ba0 hidden-X8 pair.

    W2 is read as 32 bits. The pair wrapper loads output X8 from packed+8,
    X0 from +16 and X1 from +24, then composes the accepted clone and append
    owners. Physical spill aliases remain outside that composition.
    """
    import vm9_objects as objects
    p=_PageTransaction(pages)
    words=tuple(int.from_bytes(_read_span(p,argument_block_address+i*8,8),'little') for i in range(4))
    target=words[0]-image_base
    pair=(wrapper_offset,target)
    if pair==(0x288B74,0x248908):
        import vm9_configuration_init as configuration
        extra=tuple(int.from_bytes(_read_span(p,argument_block_address+i*8,8),'little') for i in (4,5))
        result=configuration.format_string_object(p,object_address=words[1],format_address=words[2],
            argument_addresses=(words[3]&0xFFFFFFFF,*extra,words[0]),image_base=image_base,
            allocate=allocate,reallocate=reallocate,free=free,prepare_format=prepare_format,max_bytes=max_bytes)
    elif pair==(0x288B8C,0x2481FC):
        result=objects.construct_sized_string_object(p,object_address=words[1],source_address=words[2],
            length=words[3]&0xFFFFFFFF,image_base=image_base,allocate=allocate,max_payload_bytes=max_bytes)
    elif pair==(0x288BA0,0x248780):
        if type(entry_stack_address) is not int or not 0x200<=entry_stack_address<1<<64 or entry_stack_address&15:
            raise RefillUnsupported('token pair stack requires aligned spill space')
        def guard_span(address,width):
            if address<entry_stack_address and address+width>entry_stack_address-0x200:
                raise RefillUnsupported('token string pair aliases unmodeled physical spills')
        for address in words[1:]:guard_span(address,24)
        def guard_payloads(pages):
            for address in words[2:]:
                pointer=int.from_bytes(_read_span(pages,address+16,8),'little')
                length=objects._s32(int.from_bytes(_read_span(pages,address+12,4),'little'))
                if pointer and length>0:guard_span(pointer,length)
        def checked_allocate(pages,size):
            result=allocate(pages,size)
            if result:guard_span(result,size)
            guard_payloads(pages)
            return result
        def checked_reallocate(pages,pointer,size):
            result=reallocate(pages,pointer,size)
            if result:guard_span(result,size)
            guard_payloads(pages)
            return result
        guard_payloads(p)
        objects.clone_string_object(p,object_address=words[1],source_object_address=words[2],
            image_base=image_base,allocate=checked_allocate,max_payload_bytes=max_bytes)
        result=objects.append_string_fields(p,destination_fields=words[1]+8,source_fields=words[3]+8,
            allocate=checked_allocate,reallocate=checked_reallocate,free=free,max_bytes=max_bytes)&0xFFFFFFFF
    else:
        raise RefillUnsupported('unrecovered token string transform callback')
    p.commit()
    return result


def apply_token_digest_callback(pages, *, argument_block_address, image_base,
        entry_stack_address, thread_pointer, allocate, reallocate, free,
        thread_id=None, observer=None, max_source_bytes=0x100000):
    """+288bbc -> +25874c: hidden X8, byte flag and child SP=entrySP-16.

    Reuse the MD5 owner with its actual scoped reference lifecycle. The result
    is the referenced StringObject; the wrapper does not store physical X0.
    """
    import vm9_reference_scopes as references
    if type(entry_stack_address) is not int or not 0x120<=entry_stack_address<1<<64 or entry_stack_address&15:
        raise RefillUnsupported('token MD5 callback requires aligned child stack')
    p=_PageTransaction(pages)
    target=int.from_bytes(_read_span(p,argument_block_address,8),'little')-image_base
    if target!=0x25874C:
        raise RefillUnsupported('unrecovered token digest callback target')
    out=int.from_bytes(_read_span(p,argument_block_address+8,8),'little')
    source=int.from_bytes(_read_span(p,argument_block_address+16,8),'little')
    flag=_read_span(p,argument_block_address+24,1)[0]
    result=references.construct_scoped_digest_reference(p,output_reference_address=out,
        source_object_address=source,entry_stack_address=entry_stack_address-16,
        image_base=image_base,thread_pointer=thread_pointer,allocate=allocate,
        reallocate=reallocate,free=free,thread_id=thread_id,diagnostic_observer=observer,
        flag=flag,max_source_bytes=max_source_bytes)
    p.commit()
    return result


def apply_token_cipher_callback(pages, *, argument_block_address, image_base,
        entry_stack_address, thread_pointer, allocate, reallocate, free, max_bytes=0x100000):
    """+288bdc tail wrapper -> +287580 with three packed StringObject pointers."""
    from vm9_request_token_cipher import encrypt_token_string_object
    p=_PageTransaction(pages)
    words=tuple(int.from_bytes(_read_span(p,argument_block_address+i*8,8),'little') for i in range(4))
    if words[0]-image_base!=0x287580:
        raise RefillUnsupported('unrecovered token StringObject cipher callback')
    encrypt_token_string_object(p,source_object_address=words[1],object_address=words[2],
        key_object_address=words[3],entry_stack_address=entry_stack_address,
        thread_pointer=thread_pointer,image_base=image_base,allocate=allocate,
        reallocate=reallocate,free=free,max_bytes=max_bytes)
    p.commit()
