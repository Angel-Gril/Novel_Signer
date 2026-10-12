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


def prepare_request_token_vm_caller(pages, *, entry_stack_address, return_address,
        thread_pointer, image_base, object_address, saved_frame_pointer=0,
        saved_x28=0, saved_x19=0) -> RequestVmCallerFrame:
    """Generate +0x287500's caller and the defined generic VM prelude slots.

    Descriptor top is local SP+0x650. Undefined virtual words and packed
    padding retain live caller memory. TLS is read after the native spills,
    including when its canary address aliases the saved caller registers.
    """
    values = (entry_stack_address, return_address, thread_pointer, image_base,
        object_address, saved_frame_pointer, saved_x28, saved_x19)
    if any(type(v) is not int or not 0 <= v < 1 << 64 for v in values):
        raise RefillUnsupported('request token VM caller inputs must fit uint64')
    if entry_stack_address < 0x680 or entry_stack_address & 15:
        raise RefillUnsupported('request token VM caller stack must be aligned')
    if return_address >= 1 << 56:
        raise RefillUnsupported('PAC-tagged request token VM return is unsupported')
    tx = _PageTransaction(pages)
    local = entry_stack_address - 0x680
    def word(address, value):
        _write_span(tx, address, value.to_bytes(8, 'little'))
    try:
        _read_span(tx, local, 0x680)
        _read_span(tx, image_base + 0x118570, 4)
        for address, value in (
            (entry_stack_address - 0x20, saved_frame_pointer),
            (entry_stack_address - 0x18, return_address),
            (entry_stack_address - 0x10, saved_x28),
            (entry_stack_address - 8, saved_x19),
        ):
            word(address, value)
        _write_span(tx, entry_stack_address - 0x28,
            _read_span(tx, thread_pointer + 0x28, 8))
        for address, value in ((local + 8, object_address),
            (local + 0x10, image_base + 0x2884AC),
            (local + 0x18, local + 0x650), (local + 0x20, return_address)):
            word(address, value)
        top = local + 0x650
        backing = top - 0x118
        word(top - 0x120, image_base + 0x118570)
        for slot, value in ((0, 0), (4, local + 8),
            (5, image_base + 0x35F5E0), (6, image_base + 0x35F650),
            (7, image_base + 0x2884AC), (29, (top - 0x130) & ~15),
            (31, return_address)):
            word(backing + slot * 8, value)
        registers = tuple(int.from_bytes(_read_span(tx, backing + i * 8, 8), 'little')
            for i in range(32))
    except ValueError as exc:
        raise RefillUnsupported('request token VM caller memory is unmapped') from exc
    vm_arguments = (image_base + 0x118570, local + 8, image_base + 0x35F5E0,
        image_base + 0x35F650, local + 0x10)
    tx.commit()
    return RequestVmCallerFrame(local, 0x118570, local + 8, local + 0x10,
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


@dataclass(frozen=True)
class RequestCallerReturn:
    pc: int
    sp: int
    x0: int
    x19: int
    x28: int
    x29: int
    x30: int


def finish_request_caller(pages, *, image_base, entry_stack_address,
        thread_pointer, callback_sentinel) -> RequestCallerReturn:
    """+0x283134: check canary, restore saved registers and return to caller.

    Native +0x1683f0 loads descriptor[0] into physical X0. Its callback
    trampoline +0x16aa30 saves/restores X0, and +0x172440 preserves it.
    This owner covers the supported VM return branch; it consumes explicit
    callback ABI state and never substitutes virtual R0 for physical X0.
    """
    values = (image_base, entry_stack_address, thread_pointer, callback_sentinel)
    if any(type(v) is not int or not 0 <= v < 1 << 64 for v in values):
        raise RefillUnsupported('request caller return inputs must fit uint64')
    if entry_stack_address < 0x1740 or entry_stack_address & 15:
        raise RefillUnsupported('request caller return stack must be aligned')
    if callback_sentinel != image_base + 0x28587C:
        raise RefillUnsupported('request caller callback sentinel does not match this entry')
    try:
        saved = _read_span(pages, entry_stack_address - 0x28, 0x28)
        canary = _read_span(pages, thread_pointer + 0x28, 8)
    except ValueError as exc:
        raise RefillUnsupported('request caller return frame or TLS is unmapped') from exc
    if saved[:8] != canary:
        raise RefillUnsupported('request caller stack canary mismatch')
    def word(a):return int.from_bytes(saved[a - (entry_stack_address - 0x28):
        a - (entry_stack_address - 0x28) + 8],'little')
    x29 = word(entry_stack_address - 0x20)
    x30 = word(entry_stack_address - 0x18)
    if x30 >= 1 << 56:
        raise RefillUnsupported('PAC-tagged request caller return is unsupported')
    return RequestCallerReturn(x30,entry_stack_address,callback_sentinel,
        word(entry_stack_address - 8),word(entry_stack_address - 0x10),x29,x30)
