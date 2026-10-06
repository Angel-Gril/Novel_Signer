"""Default six-VM task composed with naturally bootstrapped matching libc."""
from __future__ import annotations
import vm9_startup as startup
from vm9_libc_base import _allocate_staged
from vm9_libc_boot import _u
from vm9_libc_cold import _initialize_default
from vm9_libc_tcache import _public_large


def initialize_default_task(guest_os, *, vm_module, image_base, entry_stack_address,
        return_address, thread_pointer, scratch_address, libc_base, brk, os_call, broadcast):
    """Run +0x280554 with actual default malloc boot and owned large extents.

    Thread/TLS/stack and virtual OS/broadcast services are explicit inputs.
    This composes the task body, not a complete startup worker/root or signer.
    Guest pages, mappings, protection and cursor publish only on full success.
    External provider effects are outside the guest transaction.
    """
    tx=guest_os.begin()
    def allocation_body(inner, *, request_size, libc_base, thread_pointer, os_call):
        if _u(inner.pages,libc_base+0xDB6A0,4)==3:
            status=_initialize_default(inner,scratch_address=scratch_address,libc_base=libc_base,
                thread_pointer=thread_pointer,brk=brk,os_call=os_call)
            if status:return 0
        return _public_large(inner,request_size=request_size,libc_base=libc_base,
            thread_pointer=thread_pointer,os_call=os_call,scratch_address=scratch_address)
    def allocate(staged,size):
        return _allocate_staged(tx,staged,request_size=size,libc_base=libc_base,
            thread_pointer=thread_pointer,os_call=os_call,allocation_body=allocation_body)
    result=startup.run_default_initialization_task(tx.pages,allocate=allocate,
        broadcast=broadcast,vm_module=vm_module,entry_stack_address=entry_stack_address,
        return_address=return_address,thread_pointer=thread_pointer,image_base=image_base)
    tx.commit()
    return result

def initialize_main_startup(guest_os, *, vm_module, image_base, entry_stack_address,
        return_address, thread_pointer, scratch_address, libc_base, brk, os_call,
        create_thread, register_destructor, thread_id, signal_condition):
    """Fresh +0x28040c startup with actual cold/small/large allocation.

    Thread creation is an explicit provider that publishes guest descriptors.
    It does not execute workers or create an OS thread. Guest pages and owned
    mapping state commit only when the complete startup caller returns.
    """
    from vm9_libc_tcache import _public_small
    tx = guest_os.begin()
    def allocation_body(inner, *, request_size, libc_base, thread_pointer, os_call):
        if _u(inner.pages, libc_base + 0xDB6A0, 4) == 3:
            status = _initialize_default(inner, scratch_address=scratch_address,
                libc_base=libc_base, thread_pointer=thread_pointer, brk=brk, os_call=os_call)
            if status:
                return 0
        body = _public_small if request_size <= 0x3800 else _public_large
        return body(inner, request_size=request_size, libc_base=libc_base,
            thread_pointer=thread_pointer, os_call=os_call, scratch_address=scratch_address)
    def allocate(staged, size):
        return _allocate_staged(tx, staged, request_size=size, libc_base=libc_base,
            thread_pointer=thread_pointer, os_call=os_call, allocation_body=allocation_body)
    result = startup.initialize_startup_caller(tx.pages, vm_module=vm_module,
        image_base=image_base, entry_stack_address=entry_stack_address,
        return_address=return_address, thread_pointer=thread_pointer, allocate=allocate,
        create_thread=create_thread, register_destructor=register_destructor,
        thread_id=thread_id, signal_condition=signal_condition)
    tx.commit()
    return result

def run_default_queue_worker(guest_os, *, vm_module, image_base, argument_address,
        entry_stack_address, thread_pointer, thread_id, scratch_address,
        libc_base, brk, os_call, broadcast, clock, futex):
    """Startup-generated default queue through actual allocation and argument free.

    The main startup and fresh worker TLS are independent inputs. Normal return
    leaves support and allocator TSD in TLS; exit destructors are not executed.
    The complete worker publishes pages/mappings/cursor atomically. Explicit OS,
    clock, futex and broadcast provider effects are outside guest rollback.
    """
    import vm9_allocator as allocator
    import vm9_objects as objects
    from vm9_libc_tcache import _public_small, _release_cached_small_pages
    tx = guest_os.begin()
    def allocation_body(inner, *, request_size, libc_base, thread_pointer, os_call):
        if _u(inner.pages, libc_base + 0xDB6A0, 4) == 3:
            status = _initialize_default(inner, scratch_address=scratch_address,
                libc_base=libc_base, thread_pointer=thread_pointer, brk=brk, os_call=os_call)
            if status:
                return 0
        body = _public_small if request_size <= 0x3800 else _public_large
        return body(inner, request_size=request_size, libc_base=libc_base,
            thread_pointer=thread_pointer, os_call=os_call, scratch_address=scratch_address)
    def allocate(staged, size):
        return _allocate_staged(tx, staged, request_size=size, libc_base=libc_base,
            thread_pointer=thread_pointer, os_call=os_call, allocation_body=allocation_body)
    def free(staged, pointer):
        return _release_cached_small_pages(staged, pointer=pointer,
            libc_base=libc_base, thread_pointer=thread_pointer)
    table = libc_base + 0xE0200
    def create_key(staged, address, destructor):
        return allocator.pthread_key_create(staged, key_address=address,
            destructor=destructor, generation_table=table)
    def set_specific(staged, key, value):
        return allocator.pthread_setspecific(staged, key=key, value=value,
            thread_pointer=thread_pointer, generation_table=table)
    def get_specific(staged, key):
        return allocator.pthread_getspecific(staged, key=key,
            thread_pointer=thread_pointer, generation_table=table)
    def reallocate(*args):
        raise allocator.RefillUnsupported('worker emulated-TLS array growth is unrecovered')
    def get_tls(staged, descriptor):
        return objects.get_emulated_tls_address(staged, control_address=descriptor,
            image_base=image_base, allocate=allocate, reallocate=reallocate, free=free,
            get_specific=get_specific, set_specific=set_specific, create_key=create_key)
    result = startup.run_default_queue_worker(tx.pages, argument_address=argument_address,
        image_base=image_base, entry_stack_address=entry_stack_address,
        thread_pointer=thread_pointer, thread_id=thread_id, vm_module=vm_module,
        allocate=allocate, free=free, broadcast=broadcast, create_key=create_key,
        set_specific=set_specific, get_tls=get_tls, clock=clock, futex=futex)
    tx.commit()
    return result
