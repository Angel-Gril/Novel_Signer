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
