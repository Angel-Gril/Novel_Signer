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
