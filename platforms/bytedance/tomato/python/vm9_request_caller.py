"""Fresh +0x2830c4 caller inputs and +0x168324 VM prelude.

Arguments remain explicit native ABI words. This module does not convert a
URL/JNI header array into native request objects or generate a signature.
"""
from __future__ import annotations

from dataclasses import dataclass
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span


@dataclass(frozen=True)
class RequestCallerFrame:
    bytecode_offset: int
    native_stack_address: int
    packed_arguments_address: int
    descriptor_address: int
    register_backing_address: int
    registers: tuple[int, ...]
    vm_call_registers: tuple[int, ...]


def prepare_request_caller(pages, *, entry_stack_address, return_address,
        thread_pointer, image_base, argument_x0, argument_x1, argument_x2,
        argument_x3, output_x8, saved_frame_pointer=0, saved_x28=0,
        saved_x19=0) -> RequestCallerFrame:
    """Generate caller spills and defined virtual registers from fresh inputs.

    STR W2 preserves the upper four bytes of its eight-byte slot. All virtual
    register slots not written by the actual prelude retain caller memory.
    No input or register word is imported from a native runtime snapshot.
    """
    values = (entry_stack_address, return_address, thread_pointer, image_base,
        argument_x0, argument_x1, argument_x2, argument_x3, output_x8,
        saved_frame_pointer, saved_x28, saved_x19)
    if any(not isinstance(value, int) or not 0 <= value < 1 << 64 for value in values):
        raise RefillUnsupported("request caller inputs must fit uint64")
    if entry_stack_address & 15:
        raise RefillUnsupported("request caller stack must be aligned")
    if return_address >= 1 << 56:
        raise RefillUnsupported("PAC-tagged request return address is unsupported")
    staged = _PageTransaction(pages)
    stack = entry_stack_address - 0x1740
    _read_span(staged, stack, 0x1740)
    _read_span(staged, image_base + 0xF7720, 4)
    canary = _read_span(staged, thread_pointer + 0x28, 8)

    def word(address, value):
        _write_span(staged, address, value.to_bytes(8, "little"))

    for address, value in (
        (entry_stack_address - 0x20, saved_frame_pointer),
        (entry_stack_address - 0x18, return_address),
        (entry_stack_address - 0x10, saved_x28),
        (entry_stack_address - 8, saved_x19),
        (stack + 8, output_x8), (stack + 0x10, argument_x0),
        (stack + 0x18, argument_x1), (stack + 0x28, argument_x3),
        (stack + 0x30, image_base + 0x28587C),
        (stack + 0x38, stack + 0x1710), (stack + 0x40, return_address),
    ):
        word(address, value)
    _write_span(staged, entry_stack_address - 0x28, canary)
    _write_span(staged, stack + 0x20, (argument_x2 & 0xFFFFFFFF).to_bytes(4, "little"))
    top = stack + 0x1710
    backing = top - 0x118
    # Defined stores in +0x1683f0..+0x1684f0. Scratch native frame bytes
    # below the caller stack are not claimed by this model.
    word(top - 0x120, image_base + 0xF7720)
    for slot, value in ((0, 0), (4, stack + 8),
        (5, image_base + 0x35E230), (6, image_base + 0x35E690),
        (7, image_base + 0x28587C), (29, (top - 0x130) & ~15),
        (31, return_address)):
        word(backing + slot * 8, value)
    registers = tuple(int.from_bytes(_read_span(staged, backing + i * 8, 8), "little")
                      for i in range(32))
    vm_arguments = (image_base + 0xF7720, stack + 8,
        image_base + 0x35E230, image_base + 0x35E690, stack + 0x30)
    staged.commit()
    return RequestCallerFrame(0xF7720, stack, stack + 8, stack + 0x30,
                              backing, registers, vm_arguments)


@dataclass(frozen=True)
class RequestVmCallerFrame:
    native_stack_address: int
    bytecode_offset: int
    packed_arguments_address: int
    descriptor_address: int
    register_backing_address: int
    registers: tuple[int, ...]
    vm_call_registers: tuple[int, ...]


def prepare_request_vm_caller(pages, *, entry_stack_address, return_address,
        thread_pointer, image_base, object_address, preserved_x8,
        saved_frame_pointer=0, saved_x28=0, saved_x19=0) -> RequestVmCallerFrame:
    """Generate +0x256ed4's caller and defined +0x168324 prelude slots.

    Incoming x8 is saved in [sp], x0 in [sp+8]. Descriptor+8 points to
    sp+0x380: ADD #0x28 then ADD #0x358, not just sp+0x28. Undefined VM
    backing words retain the caller's memory. No native frame is copied.
    """
    values = (entry_stack_address, return_address, thread_pointer, image_base,
              object_address, preserved_x8, saved_frame_pointer, saved_x28, saved_x19)
    if any(not isinstance(v, int) or not 0 <= v < 1 << 64 for v in values):
        raise RefillUnsupported("request VM caller inputs must fit uint64")
    if entry_stack_address & 15:
        raise RefillUnsupported("request VM caller stack must be aligned")
    if return_address >= 1 << 56:
        raise RefillUnsupported("PAC-tagged request VM caller return is unsupported")
    tx = _PageTransaction(pages)
    local = entry_stack_address - 0x3B0
    _read_span(tx, local, 0x3B0)
    _read_span(tx, image_base + 0x99020, 4)
    def word(address, value):
        _write_span(tx, address, value.to_bytes(8, "little"))
    for address, value in (
        (entry_stack_address - 0x20, saved_frame_pointer),
        (entry_stack_address - 0x18, return_address),
        (entry_stack_address - 0x10, saved_x28),
        (entry_stack_address - 8, saved_x19),
        (local, preserved_x8), (local + 8, object_address),
        (local + 0x10, image_base + 0x257050),
        (local + 0x18, local + 0x380), (local + 0x20, return_address),
    ):
        word(address, value)
    _write_span(tx, entry_stack_address - 0x28, _read_span(tx, thread_pointer + 0x28, 8))
    top = local + 0x380
    backing = top - 0x118
    word(top - 0x120, image_base + 0x99020)
    for slot, value in ((0, 0), (4, local), (5, image_base + 0x35B650),
        (6, image_base + 0x35B660), (7, image_base + 0x257050),
        (29, (top - 0x130) & ~15), (31, return_address)):
        word(backing + slot * 8, value)
    registers = tuple(int.from_bytes(_read_span(tx, backing + i * 8, 8), "little")
                      for i in range(32))
    vm_arguments = (image_base + 0x99020, local, image_base + 0x35B650,
                    image_base + 0x35B660, local + 0x10)
    tx.commit()
    return RequestVmCallerFrame(local, 0x99020, local, local + 0x10,
        backing, registers, vm_arguments)


def validate_request_vm_exit(pages, *, image_base, pc, registers, return_address):
    """Validate the observed +0xffb78 return branch of native +0x16a974.

    op17/sub30 is not an unconditional native return. The selected virtual
    slot must equal the caller's saved sentinel. Native x0 return ABI and the
    caller's stack-canary/physical epilogue are outside this helper contract.
    """
    if pc != image_base+0xFFB78 or len(registers) != 32:
        raise RefillUnsupported('request VM exit is outside the recovered return branch')
    word=int.from_bytes(_read_span(pages,pc,4),'little')
    if word != 0x07C00791:
        raise RefillUnsupported('request VM exit word does not match the sample')
    slot=(word>>22)&31
    if registers[slot] != return_address:
        raise RefillUnsupported('request VM exit target does not match its caller sentinel')
    return dict(bytecode_offset=hex(pc-image_base),instruction_word=hex(word),
        opcode=word&63,subopcode=(word>>6)&63,selected_slot=slot,
        selected_target=return_address,caller_sentinel_matches=True,
        native_handler_offset='0x16a974',native_epilogue_offset='0x172440',
        physical_native_caller_epilogue_modeled=False,native_return_x0_abi_compared=False)
