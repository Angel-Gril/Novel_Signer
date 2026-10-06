"""Actual matching allocator/GC bridge for the bounded independent root factory.

ELF, TLS, stack, references and OS/property/clock outcomes are explicit inputs.
No native state or native execution is used. Unsupported realloc and large-bin
GC remain closed. Publication is one GuestOS transaction; provider effects
are outside guest rollback.
"""
from __future__ import annotations
import vm9_allocator as a,vm9_root as root,vm9_objects as objects
import vm9_configuration_init as configuration,vm9_registry as registry
import vm9_libc_exit as exit_owner,vm9_libc_release as release_owner
import vm9_libc_region as region
from vm9_libc_boot import _u,_w
from vm9_libc_cold import _initialize_default
from vm9_libc_base import _allocate_staged
from vm9_libc_tcache import _public_small,_public_large


def construct_root_reference(guest_os,*,vm_module,image_base,libc_base,
        output_reference_address,first_reference_address,second_reference_address,
        initializer_reference_address,flag,entry_stack_address,thread_pointer,
        scratch_address,errno_address,brk,os_call,read_property,syscall,mkdir,
        read_clock,once_wake,register_destructor,thread_id,
        allocation_effect=None,free_effect=None):
    """+0x257578 with natural cold malloc, small flush and small-cursor GC.

    Existing root/TLS/registry/configuration owners perform all object work.
    The caller supplies missing-file/logging/no-waiter environment outcomes;
    this is not JNI or a complete Medusa request-signing entry.
    Optional effect observers run after successful allocation/free and must
    obey the caller's provider contract; their effects cannot be rolled back.
    """
    tx=guest_os.begin();generation=libc_base+0xE0200
    def release_extent(p,arena,slab,dirty,force_clean,constants):
        return release_owner.release_empty_small_extent(p,arena,slab,dirty,force_clean,constants,
            libc_base=libc_base,os_call=os_call)
    def collect(p,tsd,cache):
        return exit_owner._collect_small_cache(p,tsd,cache,
            libc_base=libc_base,release_extent=release_extent)
    def allocation_body(inner,*,request_size,libc_base,thread_pointer,os_call):
        if _u(inner.pages,libc_base+0xDB6A0,4)==3:
            if _initialize_default(inner,scratch_address=scratch_address,libc_base=libc_base,
                    thread_pointer=thread_pointer,brk=brk,os_call=os_call):return 0
        operation=_public_small if request_size<=0x3800 else _public_large
        return operation(inner,request_size=request_size,libc_base=libc_base,
            thread_pointer=thread_pointer,os_call=os_call,scratch_address=scratch_address,collect_cache=collect)
    def allocate(p,size):
        pointer=_allocate_staged(tx,p,request_size=size,libc_base=libc_base,
            thread_pointer=thread_pointer,os_call=os_call,allocation_body=allocation_body)
        if allocation_effect:allocation_effect(p,size,pointer)
        return pointer
    def allocate_at_stack(p,size,stack):
        # Only the singleton layout currently supplies this physical caller
        # boundary. +0x7973c saves je_malloc's current cache (X25) during a
        # refill; later +0x268eb0 copies the surviving upper seven bytes.
        if not isinstance(stack,int) or stack&15:
            raise a.RefillUnsupported('actual allocator call stack must be aligned')
        key=_u(p,_u(p,libc_base+0xD8F98),4)
        wrapper=a.pthread_getspecific(p,key=key,thread_pointer=thread_pointer,generation_table=generation)
        if not wrapper:raise a.RefillUnsupported('layout allocation requires current TSD')
        cache=_u(p,wrapper+0x10)
        if not cache or not 0<size<=0x1000:
            raise a.RefillUnsupported('layout allocation requires its small cache')
        index=region._size_index(p,libc_base,size)
        refill=not _u(p,cache+index*32+0x30,4)
        pointer=allocate(p,size)
        if refill:_w(p,stack-0x1B0,cache)
        return pointer
    def prefix_stack_effect(p,stack):
        # malloc +0x1bb0c retains operator-new's FP/LR at these slots.
        # The deeper +0x163ddc reference-counter call supplies the first pair;
        # the final layout allocation supplies the shallower return slot.
        for delta,value in ((-0x150,stack-0x140),(-0x148,image_base+0x32A210),
                (-0xF8,image_base+0x32A210)):
            _w(p,stack+delta,value)
    def free(p,pointer):
        exit_owner._free_in_exit(tx,p,pointer,libc_base=libc_base,thread_pointer=thread_pointer,
            scratch_address=scratch_address,os_call=os_call,release_extent=release_extent,
            flush_small=True,collect_cache=collect)
        if free_effect:free_effect(p,pointer)
    def reallocate(*args):raise a.RefillUnsupported('actual-root realloc is unrecovered')
    def create_key(p,key_address,destructor):
        return a.pthread_key_create(p,key_address=key_address,destructor=destructor,generation_table=generation)
    def get_specific(p,key):
        return a.pthread_getspecific(p,key=key,thread_pointer=thread_pointer,generation_table=generation)
    def set_specific(p,key,value):
        return a.pthread_setspecific(p,key=key,value=value,thread_pointer=thread_pointer,generation_table=generation)
    def get_tls(p,control_address):
        return objects.get_emulated_tls_address(p,control_address=control_address,image_base=image_base,
            allocate=allocate,reallocate=reallocate,get_specific=get_specific,set_specific=set_specific,
            create_key=create_key,once_wake=once_wake)
    def thread_destructor(p,destructor,obj,dso):
        if dso!=image_base+0x34C700:raise a.RefillUnsupported('unexpected actual-root destructor DSO')
        return objects.register_emulated_thread_destructor(p,destructor_address=destructor,
            object_address=obj,image_base=image_base,allocate=allocate,get_tls=get_tls,
            create_key=create_key,set_specific=set_specific,register_atexit=register_destructor,thread_id=thread_id)
    def initialize_registry(p):
        return objects.initialize_scoped_tls_registry(p,image_base=image_base,get_tls=get_tls,register_destructor=thread_destructor)
    def broadcast(p,pointer):
        return objects.broadcast_condition_no_waiters(p,condition_address=pointer,wake=once_wake)
    def singleton(p,sp):
        return registry.get_singleton136_reference(p,entry_stack_address=sp,image_base=image_base,
            allocate=allocate,free=free,read_clock=read_clock,get_tls=get_tls,
            initialize_registry=initialize_registry,broadcast=broadcast,thread_id=thread_id,
            allocate_at_stack=allocate_at_stack).wrapper_address
    def prepare_format(p):
        return configuration.prepare_bionic_format_locale(p,once_address=libc_base+0xDE938,
            key_address=libc_base+0xDE930,generation_table=generation,
            thread_pointer=thread_pointer,wake=once_wake)
    result=root.construct_root_reference(tx.pages,output_reference_address=output_reference_address,
        first_reference_address=first_reference_address,second_reference_address=second_reference_address,
        initializer_reference_address=initializer_reference_address,flag=flag,
        entry_stack_address=entry_stack_address,thread_pointer=thread_pointer,image_base=image_base,
        vm_module=vm_module,allocate=allocate,reallocate=reallocate,free=free,
        get_singleton=singleton,get_tls=get_tls,initialize_registry=initialize_registry,
        broadcast=broadcast,read_property=read_property,syscall=syscall,errno_address=errno_address,
        mkdir=mkdir,register_destructor=register_destructor,thread_id=thread_id,prepare_format=prepare_format,
        prefix_stack_effect=prefix_stack_effect)
    tx.commit();return result
