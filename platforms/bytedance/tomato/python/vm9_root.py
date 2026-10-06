"""Bounded Python root constructor and caller for the observed VM9 path.

All guest pages, allocator, TLS and environment services are explicit inputs.
This module does not execute native code or consume a VM-entry snapshot.
Unsupported callbacks fail closed; this is not a complete Medusa signer.
"""
from __future__ import annotations

from dataclasses import dataclass

import vm9_configuration_init as configuration
import vm9_objects as objects
import vm9_state as state
import vm9_stream_cipher as stream
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from vm9_objects import _PageTransaction


@dataclass(frozen=True)
class RootResult:
    steps: int
    stop_offset: int
    registers: tuple[int, ...]
    modeled_callbacks: list[dict]


class RootCallbacks:
    """Observed root callbacks, composed with recovered constructor services."""
    def __init__(self, *, image_base, native_stack_address, thread_pointer,
            vm_module, allocate, reallocate, free, get_singleton, get_tls,
            initialize_registry, broadcast, read_property, syscall,
            errno_address, mkdir, register_destructor, thread_id=None,
            prepare_format=None):
        self.base=image_base; self.stack=native_stack_address
        self.thread_pointer=thread_pointer; self.vm_module=vm_module
        self.allocate=allocate; self.reallocate=reallocate; self.free=free
        self.get_singleton=get_singleton
        self.environment=dict(reallocate=reallocate,free=free,get_tls=get_tls,
            initialize_registry=initialize_registry,broadcast=broadcast,
            read_property=read_property,syscall=syscall,errno_address=errno_address,
            mkdir=mkdir,register_destructor=register_destructor,
            thread_id=thread_id,prepare_format=prepare_format)
        self.modeled=[]

    def __call__(self, vm, function, argument):
        base=self.base; pages=vm.m.pages
        wrapper=function-base
        words=[vm.m.u64(argument+i*8) for i in range(4)]
        target=words[0]-base
        if (wrapper,target) in ((0x258444,0x26C858),(0x258454,0x26C9D0)):
            pass  # Same explicit diagnostic-scope exclusion as native controls.
        elif (wrapper,target)==(0x2584C4,0x32A1F0):
            vm.m.w64(argument+0x10,self.allocate(pages,words[1]))
        elif (wrapper,target)==(0x258460,0x32A264):
            self.free(pages,words[1])
        elif wrapper==0x25846C and target in (0x2484B8,0x2484FC):
            objects.destroy_string_object(pages,object_address=words[1],image_base=base,
                free=self.free,delete_object=target==0x2484FC)
        elif (wrapper,target)==(0x258478,0x248344):
            objects.construct_string_object(pages,object_address=words[1],
                source_address=words[2],allocate=self.allocate,
                vtable_address=base+0x34F5F8,empty_descriptor_address=base+0x6E168)
        elif wrapper==0x2584B8 and target in (0x32A444,0x32A4FC):
            model=objects.acquire_uncontended_shared_reader if target==0x32A444 else objects.release_uncontended_shared_reader
            model(pages,mutex_address=words[1])
        elif (wrapper,target)==(0x258430,0x167E54):
            objects.decode_masked_bytes(pages,source_address=words[1],
                destination_address=words[2],mask_address=words[3])
        elif (wrapper,target)==(0x2584E0,0x26194C):
            configuration.construct_initialized_configuration(pages,
                object_address=words[1],first_string_address=words[2],second_string_address=words[3],
                identity_object_address=vm.m.u64(argument+0x20),
                entry_stack_address=self.stack-0x180,thread_pointer=self.thread_pointer,
                image_base=base,vm_module=self.vm_module,allocate=self.allocate,
                reallocate=self.reallocate,free=self.free,get_singleton=self.get_singleton)
        elif (wrapper,target)==(0x258500,0x2698F0):
            state.construct_initialized_state_owner(pages,object_address=words[1],
                source_object_address=words[2],flag=words[3]&255,
                entry_stack_address=self.stack-0x180,return_address=base+0x16AA4C,
                thread_pointer=self.thread_pointer,image_base=base,vm_module=self.vm_module,
                allocate=self.allocate,**self.environment)
        else:
            raise RefillUnsupported(f'unrecovered root callback +{wrapper:#x} -> +{target:#x}')
        self.modeled.append(dict(wrapper_offset=hex(wrapper),target_offset=hex(target)))


def _word(pages,address,value):
    if not isinstance(value,int) or not 0<=value<1<<64:
        raise RefillUnsupported('root caller word must fit uint64')
    _write_span(pages,address,value.to_bytes(8,'little'))


def construct_root_caller(pages, *, object_address, source_reference_address,
        entry_stack_address, return_address, thread_pointer, image_base,
        vm_module, allocate, saved_frame_pointer=0, saved_x28=0, saved_x19=0,
        max_steps=100000, **environment):
    """Generate +0x257308's prelude and execute observed VM +0x991c0.

    Unwritten register-backing bytes are preserved from caller input pages.
    The returned registers are all32 virtual slots before the native epilogue.
    """
    if not isinstance(max_steps,int) or not 1<=max_steps<=1000000:
        raise ValueError('invalid root instruction bound')
    if not isinstance(entry_stack_address,int) or entry_stack_address&15:
        raise RefillUnsupported('root caller stack must be aligned')
    if not isinstance(return_address,int) or not 0<=return_address<1<<56:
        raise RefillUnsupported('PAC-tagged root return address is unsupported')
    staged=_PageTransaction(pages);stack=entry_stack_address-0x5A0
    _read_span(staged,stack-0x400,0x9A0)
    _read_span(staged,image_base+0x991C0,4)
    _read_span(staged,object_address,264);_read_span(staged,source_reference_address,16)
    _word(staged,stack,object_address);_word(staged,stack+8,source_reference_address)
    _word(staged,stack+0x10,image_base+0x258520)
    _word(staged,stack+0x18,stack+0x570);_word(staged,stack+0x20,return_address)
    _word(staged,entry_stack_address-0x20,saved_frame_pointer)
    _word(staged,entry_stack_address-0x18,return_address)
    _word(staged,entry_stack_address-0x10,saved_x28)
    _word(staged,entry_stack_address-8,saved_x19)
    _write_span(staged,entry_stack_address-0x28,_read_span(staged,thread_pointer+0x28,8))
    initial=[int.from_bytes(_read_span(staged,stack+0x458+i*8,8),'little') for i in range(32)]
    class StrictMem(vm_module.Mem):
        def __init__(self,pages):self.pages=pages
        def _pg(self,address):
            if address>>12 not in self.pages:raise RefillUnsupported('unmapped root guest page')
            return self.pages[address>>12]
    previous=vm_module.B
    try:
        vm_module.B=image_base
        vm=vm_module.VM(StrictMem(staged),0x991C0,stack,image_base+0x35B6A0,
            image_base+0x35B740,image_base+0x258520,return_address,maxsteps=max_steps)
        vm.R=initial;vm.R[0]=0
        vm.R[4:8]=[stack,image_base+0x35B6A0,image_base+0x35B740,image_base+0x258520]
        vm.R[29]=(stack+0x440)&~15;vm.R[31]=return_address
        callbacks=RootCallbacks(image_base=image_base,native_stack_address=stack,
            thread_pointer=thread_pointer,vm_module=vm_module,allocate=allocate,**environment)
        vm.native_hook=callbacks
        try:vm.run()
        except vm_module.VMExit:pass
        else:raise RefillUnsupported('root caller did not reach explicit VM exit')
        if _read_span(staged,thread_pointer+0x28,8)!=_read_span(staged,entry_stack_address-0x28,8):
            raise RefillUnsupported('root caller TLS canary changed')
        result=RootResult(vm.steps,vm.pc-image_base,tuple(vm.R),callbacks.modeled)
        staged.commit();return result
    finally:vm_module.B=previous


def construct_initialized_root(pages, *, object_address, initial_reference_address,
        first_reference_address, second_reference_address, initializer_reference_address,
        flag, entry_stack_address, thread_pointer, image_base, vm_module,
        allocate, saved_x28=0, prefix_stack_effect=None, **environment):
    """+0x257084 layout, temporary third reference, caller and release.

    This composes the bounded default native path from constructor entry inputs;
    earlier allocator/runtime startup and nondefault environment remain separate.
    """
    if not isinstance(entry_stack_address,int) or entry_stack_address&15:
        raise RefillUnsupported('root constructor stack must be aligned')
    staged=_PageTransaction(pages)
    _read_span(staged,entry_stack_address-0xA20,0xA20)
    layout=objects.construct_root_configuration_layout(staged,object_address=object_address,
        initial_reference_address=initial_reference_address,first_reference_address=first_reference_address,
        second_reference_address=second_reference_address,flag=flag,image_base=image_base,allocate=allocate)
    # Surviving prefix spills from +0x25c324/+0x163ddc and their nested
    # +0x24bca4/operator-new calls. Values derive from this run's allocations,
    # ELF addresses and constructor frame, never a later VM entry snapshot.
    container=layout.container_addresses[1]
    for delta,value in (
            (-0x140,entry_stack_address-0x100),(-0x138,image_base+0x163E1C),
            (-0x130,container),(-0x128,image_base+0x24BCBC),
            (-0x120,entry_stack_address-0x100),(-0x118,image_base+0x24B904),
            (-0x110,container+0x20),(-0x100,entry_stack_address-0xB0),
            (-0xF8,image_base+0x25C380),(-0xF0,entry_stack_address-0xB0),
            (-0xE8,image_base+0x2572CC),(-0xE0,0),
            (-0xD8,object_address+0xC0),(-0xD0,image_base+0x182D6C)):
        _word(staged,entry_stack_address+delta,value)
    # +0x163e00 retains the explicit TLS canary in another otherwise unused
    # VM backing slot, even when the diagnostic allocator bypasses libc.
    _write_span(staged,entry_stack_address-0x108,_read_span(staged,thread_pointer+0x28,8))
    if prefix_stack_effect is not None:
        prefix_stack_effect(staged,entry_stack_address)
    temporary=entry_stack_address-0x78
    objects.copy_reference_wrapper(staged,object_address=temporary,source_address=initializer_reference_address)
    _write_span(staged,entry_stack_address-0x68,_read_span(staged,thread_pointer+0x28,8))
    result=construct_root_caller(staged,object_address=object_address,source_reference_address=temporary,
        entry_stack_address=entry_stack_address-0x80,return_address=image_base+0x257250,
        thread_pointer=thread_pointer,image_base=image_base,vm_module=vm_module,allocate=allocate,
        saved_frame_pointer=entry_stack_address-0x60,saved_x28=saved_x28,saved_x19=object_address,**environment)
    stream.release_string_reference(staged,reference_address=temporary,image_base=image_base,free=environment['free'])
    if _read_span(staged,thread_pointer+0x28,8)!=_read_span(staged,entry_stack_address-0x68,8):
        raise RefillUnsupported('root constructor TLS canary changed')
    staged.commit();return result


@dataclass(frozen=True)
class RootFactoryResult:
    object_address: int
    reference_count_address: int
    vm_result: RootResult


def construct_root_reference(pages, *, output_reference_address,
        first_reference_address, second_reference_address, initializer_reference_address,
        flag, entry_stack_address, thread_pointer, image_base, vm_module,
        allocate, **environment):
    """Observed +0x257578 factory from function input pages through cleanup.

    Native code is not used. TLS, ELF globals, allocator and OS effects are
    provided explicitly; this is not complete process/arena bootstrapping.
    """
    if not isinstance(entry_stack_address,int) or entry_stack_address&15:
        raise RefillUnsupported('root factory stack must be aligned')
    if not isinstance(flag,int) or not 0<=flag<=0xFFFFFFFF:
        raise RefillUnsupported('root factory flag must fit uint32')
    staged=_PageTransaction(pages)
    stack=entry_stack_address-0xA0
    _read_span(staged,stack-0xA20,0xAC0)
    _read_span(staged,output_reference_address,16)
    canary=_read_span(staged,thread_pointer+0x28,8)
    _write_span(staged,stack+0x48,canary)
    root=objects._allocate(staged,allocate,264)
    empty=objects._allocate(staged,allocate,24)
    objects.construct_string_object(staged,object_address=empty,
        source_address=image_base+0x6FE64,allocate=allocate,vtable_address=image_base+0x34F5F8)
    objects.construct_reference_wrapper(staged,object_address=stack+0x38,
        referenced_address=empty,allocate=allocate)
    for destination,source in ((stack+0x28,first_reference_address),
            (stack+0x18,second_reference_address),(stack+8,initializer_reference_address)):
        objects.copy_reference_wrapper(staged,object_address=destination,source_address=source)
    result=construct_initialized_root(staged,object_address=root,
        initial_reference_address=stack+0x38,first_reference_address=stack+0x28,
        second_reference_address=stack+0x18,initializer_reference_address=stack+8,
        flag=flag,entry_stack_address=stack,thread_pointer=thread_pointer,image_base=image_base,
        vm_module=vm_module,allocate=allocate,**environment)
    counter=objects.construct_reference_wrapper(staged,object_address=output_reference_address,
        referenced_address=root,allocate=allocate)
    for reference in (stack+8,stack+0x18,stack+0x28,stack+0x38):
        stream.release_string_reference(staged,reference_address=reference,
            image_base=image_base,free=environment['free'])
    if _read_span(staged,thread_pointer+0x28,8)!=canary:
        raise RefillUnsupported('root factory TLS canary changed')
    staged.commit();return RootFactoryResult(root,counter,result)
