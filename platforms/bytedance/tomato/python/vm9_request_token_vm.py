"""Bounded +0x287500 nested request VM, with independently generated inputs.

Constants, random, shared readers and diagnostic scopes use recovered owners.
The next StringObject clone is an explicit boundary; no pages are published.
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
        random_services=None, continue_shared_readers=False, diagnostic_services=None, **inputs):
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
