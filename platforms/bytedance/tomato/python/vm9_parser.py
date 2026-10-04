"""Configuration parser VM with a Python-generated +0x262608 caller prelude.

The caller supplies guest pages, a matching VM instruction interpreter and
explicit allocator/singleton environment services. All observed parser native
callbacks below are Python component models. Diagnostic scope calls are an
explicit exclusion; unsupported callback/bytecode/schema state fails closed.
"""
from __future__ import annotations
from dataclasses import dataclass

import vm9_objects as objects
import vm9_cipher_callback as cipher_callback
import vm9_stream_cipher as stream_cipher
import vm9_protobuf as protobuf
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span


@dataclass
class ParserResult:
    steps: int
    stop_offset: int
    registers: tuple[int, ...]
    modeled_callbacks: list[dict]
    unpack_results: list[dict]


class ParserCallbacks:
    def __init__(self, *, image_base, native_stack_address, allocate, reallocate, free, get_singleton):
        self.base, self.stack = image_base, native_stack_address
        self.allocate, self.reallocate, self.free, self.get_singleton = allocate, reallocate, free, get_singleton
        self.modeled, self.unpacks = [], []

    def __call__(self, vm, function, argument):
        base, pages = self.base, vm.m.pages
        wrapper = function - base
        words = [vm.m.u64(argument + i * 8) for i in range(4)]
        target = words[0] - base
        allocate, reallocate, free = self.allocate, self.reallocate, self.free
        if (wrapper, target) in ((0x26346C, 0x26C858), (0x263498, 0x26C9D0)):
            pass  # Explicit diagnostic-scope exclusion, shared with native oracle.
        elif (wrapper, target) == (0x26347C, 0x32A1F0):
            vm.m.w64(argument + 0x10, allocate(pages, words[1]))
        elif (wrapper, target) == (0x2634C4, 0x2481AC):
            objects.construct_string_object(pages, object_address=words[1], source_address=0,
                allocate=allocate, vtable_address=base + 0x34F5F8, empty_descriptor_address=base + 0x6E168)
        elif (wrapper, target) == (0x2634A4, 0x258E7C):
            objects.construct_decoded_configuration_reference(pages, object_address=words[1],
                source_object_address=words[2], image_base=base, allocate=allocate, free=free)
        elif (wrapper, target) == (0x2634D0, 0x248684):
            returned = objects.append_string_object(pages, object_address=words[1],
                source_object_address=words[2], allocate=allocate, reallocate=reallocate, free=free)
            vm.m.w64(argument + 24, returned)
        elif (wrapper, target) == (0x2634F0, 0x2481FC):
            objects.construct_sized_string_object(pages, object_address=words[1],
                source_address=words[2], length=words[3] & 0xFFFFFFFF, image_base=base, allocate=allocate)
        elif wrapper == 0x2634C4 and target in (0x2484B8, 0x2484FC):
            objects.destroy_string_object(pages, object_address=words[1], image_base=base,
                free=free, delete_object=target == 0x2484FC)
        elif wrapper == 0x263504 and target in (0x25874C, 0x258780):
            objects.construct_digest_reference(pages, object_address=words[1], source_object_address=words[2],
                algorithm='md5' if target == 0x25874C else 'sha1', flag=words[3] & 255,
                image_base=base, allocate=allocate, reallocate=reallocate, free=free)
        elif (wrapper, target) == (0x263524, 0x248344):
            objects.construct_string_object(pages, object_address=words[1], source_address=words[2],
                allocate=allocate, vtable_address=base + 0x34F5F8, empty_descriptor_address=base + 0x6E168)
        elif (wrapper, target) == (0x263534, 0x259DBC):
            cipher_callback.decrypt_configuration_reference(pages, output_reference_address=words[1],
                data_object_address=words[2], key_object_address=words[3],
                iv_object_address=vm.m.u64(argument + 32), mode_address=vm.m.u64(argument + 40),
                entry_stack_address=self.stack - 0x190, image_base=base, allocate=allocate, free=free,
                get_singleton=self.get_singleton)
        elif (wrapper, target) == (0x263554, 0x2483E0):
            objects.clone_string_object(pages, object_address=words[1], source_object_address=words[2],
                image_base=base, allocate=allocate)
        elif (wrapper, target) == (0x263564, 0x276B9C):
            returned = cipher_callback.checked_forward_copy(pages, output_address=words[1],
                source_address=words[2], length=words[3], entry_stack_address=self.stack - 0x190,
                get_singleton=self.get_singleton)
            vm.m.w64(argument + 32, returned)
        elif (wrapper, target) == (0x263584, 0x2592B8):
            stream_cipher.transform_configuration_reference(pages, output_reference_address=words[1],
                data_object_address=words[2], key_object_address=words[3],
                entry_stack_address=self.stack - 0x190, image_base=base, allocate=allocate, free=free)
        elif (wrapper, target) == (0x2635A0, 0x32A264):
            free(pages, words[1])
        elif (wrapper, target) == (0x2635AC, 0x248DD8):
            objects.fill_string_object(pages, object_address=words[1], length=vm.m.u32(argument + 0x10),
                fill=vm.m.rd(argument + 0x14, 1)[0], allocate=allocate, reallocate=reallocate, free=free)
        elif (wrapper, target) == (0x2635C0, 0x256088):
            returned = protobuf.unpack_configuration_message(pages, allocator_address=words[1],
                length=words[2], data_address=words[3], image_base=base, allocate=allocate, free=free)
            vm.m.w64(argument + 32, returned)
            self.unpacks.append({'input_length':words[2], 'returned_null':returned == 0})
        else:
            raise RefillUnsupported(f'unsupported parser callback +{wrapper:#x} -> +{target:#x}')
        self.modeled.append({'wrapper_offset':hex(wrapper),'target_offset':hex(target)})


def parse_configuration_caller(pages, *, first_argument: int, second_argument: int,
        third_argument: int, output_address: int, entry_stack_address: int,
        return_address: int, thread_pointer: int, image_base: int, vm_module,
        allocate, reallocate, free, get_singleton, max_steps: int = 100000) -> ParserResult:
    """Model +0x262608 prelude and the observed +0x9a6f0 parser VM path.

    +0x262608 is void: semantic output is guest memory, not physical native X0.
    Unused VM slots retain caller workspace bytes. Explicit environment effects
    are not rolled back when an unsupported state rejects the page transaction.
    No captured/native VM-entry prelude page is required by this API.
    """
    if not isinstance(max_steps, int) or not 1 <= max_steps <= 1000000:
        raise ValueError('invalid parser instruction bound')
    if entry_stack_address & 15:
        raise RefillUnsupported('parser caller stack must be 16-byte aligned')
    if not 0 <= return_address < 1 << 56:
        raise RefillUnsupported('PAC-tagged parser return addresses are unsupported')
    staged = _PageTransaction(pages)
    stack = entry_stack_address - 0x810
    _read_span(staged, stack - 0x400, 0xC20)
    def word(address, value):
        if not isinstance(value,int) or not 0 <= value < 1 << 64:
            raise RefillUnsupported('parser caller word must fit u64')
        _write_span(staged,address,value.to_bytes(8,'little'))
    word(stack,output_address);word(stack+8,first_argument)
    word(stack+16,second_argument);word(stack+24,third_argument)
    word(stack+32,image_base+0x263638);word(stack+40,stack+0x7E0)
    word(stack+48,return_address)
    _write_span(staged,entry_stack_address-0x28,_read_span(staged,thread_pointer+0x28,8))
    backing = stack + 0x6C8
    initial = [int.from_bytes(_read_span(staged,backing+i*8,8),'little') for i in range(32)]
    class StrictMem(vm_module.Mem):
        def __init__(self, pages):self.pages=pages
        def _pg(self,address):
            if address >> 12 not in self.pages:
                raise RefillUnsupported('unmapped parser guest page')
            return self.pages[address >> 12]
    previous_base=vm_module.B
    try:
        vm_module.B=image_base
        vm=vm_module.VM(StrictMem(staged),0x9A6F0,stack,image_base+0x35BAB0,
            image_base+0x35BAD0,image_base+0x263638,return_address,maxsteps=max_steps)
        vm.R=initial;vm.R[0]=0
        vm.R[4:8]=[stack,image_base+0x35BAB0,image_base+0x35BAD0,image_base+0x263638]
        vm.R[29]=(stack+0x6B0)&~15;vm.R[31]=return_address
        callbacks=ParserCallbacks(image_base=image_base,native_stack_address=stack,
            allocate=allocate,reallocate=reallocate,free=free,get_singleton=get_singleton)
        vm.native_hook=callbacks
        try:vm.run()
        except vm_module.VMExit:pass
        else:raise RefillUnsupported('parser did not reach an explicit VM exit')
        result=ParserResult(vm.steps,vm.pc-image_base,tuple(vm.R),callbacks.modeled,callbacks.unpacks)
        staged.commit()
        return result
    finally:
        vm_module.B=previous_base
