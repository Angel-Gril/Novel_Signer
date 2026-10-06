"""Observed state VM/caller from guest inputs and explicit environment effects.

Default shared reference, %s/%% formatting, unavailable log/file/socket profile
and one-entry scoped writer tree are bounded component models. No native or
captured VM prelude is required by construct_state_caller. Unsupported branches
reject page writes; external effects are outside transactional rollback.
"""
from __future__ import annotations
from dataclasses import dataclass
import vm9_objects as objects
import vm9_configuration_init as configuration
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported


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
            thread_id=None, prepare_format=None, logger_observer=None):
        self.base,self.stack=image_base,native_stack_address
        self.allocate,self.reallocate,self.free=allocate,reallocate,free
        self.get_tls,self.initialize_registry,self.broadcast=get_tls,initialize_registry,broadcast
        self.read_property,self.syscall,self.errno,self.mkdir=read_property,syscall,errno_address,mkdir
        self.register,self.thread_id,self.prepare_format=register_destructor,thread_id,prepare_format
        self.logger_observer=logger_observer
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
            configuration.construct_environment_reference(p,output_reference_address=words[1],
                entry_stack_address=self.stack-0x190,image_base=b,allocate=allocate,reallocate=reallocate,
                free=free,read_property=self.read_property,syscall=self.syscall,errno_address=self.errno,
                mkdir=self.mkdir,thread_id=self.thread_id,register_destructor=self.register,
                prepare_format=self.prepare_format,logger_observer=self.logger_observer)
        elif wrapper==0x26A500 and target in (0x2481AC,0x2484B8,0x2484FC):
            if target==0x2481AC:
                objects.construct_string_object(p,object_address=words[1],source_address=0,allocate=allocate,
                    vtable_address=b+0x34F5F8,empty_descriptor_address=b+0x6E168)
            else:objects.destroy_string_object(p,object_address=words[1],image_base=b,free=free,delete_object=target==0x2484FC)
        elif (wrapper,target)==(0x26A50C,0x258780):
            objects.construct_digest_reference(p,object_address=words[1],source_object_address=words[2],
                algorithm='sha1',flag=words[3]&255,image_base=b,allocate=allocate,reallocate=reallocate,free=free)
        elif (wrapper,target)==(0x26A52C,0x248908):
            configuration.format_string_object(p,object_address=words[1],format_address=words[2],
                argument_addresses=(words[3],vm.m.u64(argument+32),vm.m.u64(argument+40)),image_base=b,
                allocate=allocate,reallocate=reallocate,free=free,prepare_format=self.prepare_format)
        elif wrapper in (0x26A544,0x26A560) and target in (0x26C858,0x26C9D0):
            pass  # Explicit diagnostic-scope exclusion shared with native oracle.
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
        register_destructor, thread_id=None, prepare_format=None, max_steps=100000, logger_observer=None):
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
            thread_id=thread_id,prepare_format=prepare_format,logger_observer=logger_observer)
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
    objects.construct_mutex_backed_string_owner_prefix(staged,object_address=object_address,
        source_object_address=source_object_address,flag=flag,image_base=image_base,allocate=allocate)
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
