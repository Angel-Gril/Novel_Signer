"""Fresh +0x2830c4 caller inputs and +0x168324 VM prelude.

Arguments remain explicit native ABI words. This module does not convert a
URL/JNI header array into native request objects or generate a signature.
"""
from __future__ import annotations

from dataclasses import dataclass
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
from vm9_effects import require_effect_journal


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


def validate_request_token_vm_exit(pages, *, image_base, pc, registers, return_address):
    """Validate +118f44's selected-slot return through the generic VM owner.

    Native +16a974 compares the selected virtual word with the saved caller
    sentinel before choosing +172440. Other sub30 targets remain unsupported.
    """
    if pc!=image_base+0x118F44 or len(registers)!=32:
        raise RefillUnsupported('token VM exit is outside its recovered return branch')
    word=int.from_bytes(_read_span(pages,pc,4),'little')
    if word!=0x07C00791:
        raise RefillUnsupported('token VM exit word does not match the sample')
    slot=(word>>22)&31
    if type(registers[slot]) is not int or registers[slot]!=return_address:
        raise RefillUnsupported('token VM exit target does not match its caller sentinel')
    return dict(bytecode_offset=hex(pc-image_base),instruction_word=hex(word),
        selected_slot=slot,selected_target=return_address,caller_sentinel_matches=True,
        native_handler_offset='0x16a974',native_epilogue_offset='0x172440')


def finish_request_token_vm_caller(pages, *, image_base, entry_stack_address,
        thread_pointer, callback_sentinel) -> RequestCallerReturn:
    """+28755c: canary check, saved caller restore and physical sentinel X0.

    +1683f0 loads descriptor[0] into physical X0. Callback +16aa30 and VM
    epilogue +172440 preserve it. Virtual R0 is not the physical return value.
    This function reads the live caller spills and leaves all pages unchanged.
    """
    values=(image_base,entry_stack_address,thread_pointer,callback_sentinel)
    if any(type(v) is not int or not 0<=v<1<<64 for v in values):
        raise RefillUnsupported('token caller return inputs must fit uint64')
    if entry_stack_address<0x680 or entry_stack_address&15:
        raise RefillUnsupported('token caller return stack must be aligned')
    if callback_sentinel!=image_base+0x2884AC:
        raise RefillUnsupported('token caller callback sentinel does not match this entry')
    try:
        saved=_read_span(pages,entry_stack_address-0x28,0x28)
        canary=_read_span(pages,thread_pointer+0x28,8)
    except ValueError as exc:
        raise RefillUnsupported('token caller return frame or TLS is unmapped') from exc
    if saved[:8]!=canary:
        raise RefillUnsupported('token caller stack canary mismatch')
    canary_word,x29,x30,x28,x19=(int.from_bytes(saved[i:i+8],'little') for i in range(0,40,8))
    if x30>=1<<56:
        raise RefillUnsupported('PAC-tagged token caller return is unsupported')
    return RequestCallerReturn(x30,entry_stack_address,callback_sentinel,x19,x28,x29,x30)


def validate_request_287474_vm_exit(pages, *, image_base,pc,registers,return_address):
    """Validate +112434's selected-slot return to the second caller sentinel."""
    if (any(type(v) is not int or not 0<=v<1<<64 for v in (image_base,pc,return_address))
            or pc!=image_base+0x112434 or len(registers)!=32):
        raise RefillUnsupported('second VM exit is outside its recovered return branch')
    try:word=int.from_bytes(_read_span(pages,pc,4),'little')
    except ValueError as exc:raise RefillUnsupported('second VM return word is unmapped') from exc
    if word!=0x07C00791 or type(registers[31]) is not int or registers[31]!=return_address:
        raise RefillUnsupported('second VM exit does not reach its caller sentinel')
    return dict(bytecode_offset='0x112434',instruction_word=hex(word),selected_slot=31,
        selected_target=return_address,caller_sentinel_matches=True,
        native_handler_offset='0x16a974',native_epilogue_offset='0x172440')


def finish_request_287474_vm_caller(pages, *, image_base,entry_stack_address,
        thread_pointer,callback_sentinel) -> RequestCallerReturn:
    """+2874D8: live canary/restore after the +285F38 tail call.

    This entry shares the token caller's saved-word layout and descriptor X0.
    The native wrapper saves no extra frame. Reuse that return owner with
    the second caller's larger stack bound; virtual R0 is not physical X0.
    """
    if type(entry_stack_address) is not int or entry_stack_address<0x1A00:
        raise RefillUnsupported('second caller return requires its full stack frame')
    return finish_request_token_vm_caller(pages,image_base=image_base,
        entry_stack_address=entry_stack_address,thread_pointer=thread_pointer,
        callback_sentinel=callback_sentinel)


def prepare_request_287474_vm_caller(pages, *, entry_stack_address, return_address,
        thread_pointer, image_base, object_address, saved_frame_pointer=0,
        saved_x28=0, saved_x19=0) -> RequestVmCallerFrame:
    """Generate +0x287474's caller and the defined generic VM prelude slots.

    Descriptor top is local SP+0x19D0. Undefined virtual words and packed
    padding retain live caller memory. TLS is read after the native spills,
    including when its canary address aliases the saved caller registers.
    """
    values = (entry_stack_address, return_address, thread_pointer, image_base,
        object_address, saved_frame_pointer, saved_x28, saved_x19)
    if any(type(v) is not int or not 0 <= v < 1 << 64 for v in values):
        raise RefillUnsupported('request second VM caller inputs must fit uint64')
    if entry_stack_address < 0x1A00 or entry_stack_address & 15:
        raise RefillUnsupported('request second VM caller stack must be aligned')
    if return_address >= 1 << 56:
        raise RefillUnsupported('PAC-tagged request second VM return is unsupported')
    tx = _PageTransaction(pages)
    local = entry_stack_address - 0x1A00
    def word(address, value):
        _write_span(tx, address, value.to_bytes(8, 'little'))
    try:
        _read_span(tx, local, 0x1A00)
        _read_span(tx, image_base + 0x102BB0, 4)
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
            (local + 0x18, local + 0x19D0), (local + 0x20, return_address)):
            word(address, value)
        top = local + 0x19D0
        backing = top - 0x118
        word(top - 0x120, image_base + 0x102BB0)
        for slot, value in ((0, 0), (4, local + 8),
            (5, image_base + 0x35EDF0), (6, image_base + 0x35F3D0),
            (7, image_base + 0x2884AC), (29, (top - 0x130) & ~15),
            (31, return_address)):
            word(backing + slot * 8, value)
        registers = tuple(int.from_bytes(_read_span(tx, backing + i * 8, 8), 'little')
            for i in range(32))
    except ValueError as exc:
        raise RefillUnsupported('request second VM caller memory is unmapped') from exc
    vm_arguments = (image_base + 0x102BB0, local + 8, image_base + 0x35EDF0,
        image_base + 0x35F3D0, local + 0x10)
    tx.commit()
    return RequestVmCallerFrame(local, 0x102BB0, local + 8, local + 0x10,
        backing, registers, vm_arguments)


def prepare_request_28048c_vm_caller(pages, *, entry_stack_address, return_address,
        thread_pointer, image_base, output_x8, argument_x0, argument_x1,
        argument_x2, saved_frame_pointer=0, saved_x28=0, saved_x19=0):
    """+28048c caller: hidden X8, X0, low W1 and X2; top=local+ef0.

    The W1 spill preserves its four padding bytes. The descriptor begins at
    local+20, after packed X2. Undefined backing slots retain caller memory.
    """
    values=(entry_stack_address,return_address,thread_pointer,image_base,
        output_x8,argument_x0,argument_x1,argument_x2,saved_frame_pointer,saved_x28,saved_x19)
    if any(type(v) is not int or not 0<=v<1<<64 for v in values):
        raise RefillUnsupported('request child VM caller inputs must fit uint64')
    if entry_stack_address<0xF20 or entry_stack_address&15:
        raise RefillUnsupported('request child VM caller stack must be aligned')
    if return_address>=1<<56:
        raise RefillUnsupported('PAC-tagged request child VM return is unsupported')
    p=_PageTransaction(pages);local=entry_stack_address-0xF20
    def word(address,value):_write_span(p,address,value.to_bytes(8,'little'))
    try:
        _read_span(p,local,0xF20);_read_span(p,image_base+0xA71D0,4)
        for address,value in ((entry_stack_address-0x20,saved_frame_pointer),
                (entry_stack_address-0x18,return_address),(entry_stack_address-0x10,saved_x28),
                (entry_stack_address-8,saved_x19)):
            word(address,value)
        _write_span(p,entry_stack_address-0x28,_read_span(p,thread_pointer+0x28,8))
        word(local,output_x8);word(local+8,argument_x0)
        _write_span(p,local+0x10,(argument_x1&0xFFFFFFFF).to_bytes(4,'little'))
        for address,value in ((local+0x18,argument_x2),(local+0x20,image_base+0x281414),
                (local+0x28,local+0xEF0),(local+0x30,return_address)):
            word(address,value)
        top=local+0xEF0;backing=top-0x118
        word(top-0x120,image_base+0xA71D0)
        for slot,value in ((0,0),(4,local),(5,image_base+0x35D6B0),
                (6,image_base+0x35D970),(7,image_base+0x281414),
                (29,(top-0x130)&~15),(31,return_address)):
            word(backing+slot*8,value)
        registers=tuple(int.from_bytes(_read_span(p,backing+i*8,8),'little') for i in range(32))
    except ValueError as exc:
        raise RefillUnsupported('request child VM caller memory is unmapped') from exc
    arguments=(image_base+0xA71D0,local,image_base+0x35D6B0,image_base+0x35D970,local+0x20)
    p.commit()
    return RequestVmCallerFrame(local,0xA71D0,local,local+0x20,backing,registers,arguments)


def validate_request_28048c_vm_exit(pages, *, image_base,pc,registers):
    """Validate the child return word and its selected caller sentinel."""
    if pc!=image_base+0xED3DC or len(registers)!=32:
        raise RefillUnsupported('child VM exit is outside the recovered return branch')
    word=int.from_bytes(_read_span(pages,pc,4),'little')
    if word!=0x07C00791 or registers[31]!=image_base+0x2885C8:
        raise RefillUnsupported('child VM exit does not reach its wrapper sentinel')
    return dict(bytecode_offset='0xed3dc',instruction_word=hex(word),selected_slot=31,
        selected_target=registers[31],caller_sentinel_matches=True,
        native_handler_offset='0x16a974',native_epilogue_offset='0x172440')


def finish_request_28048c_wrapper_caller(pages, *, entry_stack_address,
        thread_pointer,image_base,callback_sentinel) -> RequestCallerReturn:
    """+2804f0 canary/restore and +2885c8 wrapper LR/SP return.

    Generic +1683f0 loads the descriptor callback into physical X0; the VM
    epilogue and both return sequences preserve it. Read live saved words,
    including TLS aliases, without treating virtual R0 as a physical result.
    The generic handler's scratch words and full PAC ABI are outside scope.
    """
    values=(entry_stack_address,thread_pointer,image_base,callback_sentinel)
    if any(type(v) is not int or not 0<=v<1<<64 for v in values):
        raise RefillUnsupported('child caller return inputs must fit uint64')
    if entry_stack_address<0xF30 or entry_stack_address&15:
        raise RefillUnsupported('child caller return stack must be aligned')
    if callback_sentinel!=image_base+0x281414:
        raise RefillUnsupported('child caller descriptor callback does not match this entry')
    entry=entry_stack_address-16
    try:
        canary=_read_span(pages,thread_pointer+0x28,8)
        saved=_read_span(pages,entry-0x28,0x28)
        if canary!=saved[:8]:raise RefillUnsupported('child caller stack canary mismatch')
        _,x29,child_lr,x28,x19=(int.from_bytes(saved[i:i+8],'little') for i in range(0,40,8))
        if child_lr!=image_base+0x2885C8:
            raise RefillUnsupported('child caller LR does not reach its wrapper')
        x30=int.from_bytes(_read_span(pages,entry_stack_address-16,8),'little')
    except ValueError as exc:raise RefillUnsupported('child caller return memory is unmapped') from exc
    if x30>=1<<56:raise RefillUnsupported('PAC-tagged child wrapper return is unsupported')
    return RequestCallerReturn(x30,entry_stack_address,callback_sentinel,x19,x28,x29,x30)


def prepare_request_environment_vm_caller(pages, *, helper_offset,
        entry_stack_address,return_address,thread_pointer,image_base,
        saved_frame_pointer=0,saved_x28=0,saved_x19=0):
    """Actual +204e50/+204ed4 zero-argument caller and generic prelude.

    Both callers reserve a packed W result at local+8 without initializing it.
    Descriptor local+10 uses +2050e4; undefined words preserve caller memory.
    TLS is read after saving FP/LR/X28/X19, including spill aliases.
    """
    values=(helper_offset,entry_stack_address,return_address,thread_pointer,
        image_base,saved_frame_pointer,saved_x28,saved_x19)
    if any(type(v) is not int or not 0<=v<1<<64 for v in values):
        raise RefillUnsupported('request environment VM inputs must fit uint64')
    spec={0x204E50:(0x500,0x4D0,0x8A040,0x34F170,0x34F210),
        0x204ED4:(0x3D0,0x3A0,0x8A4F0,0x34F250,0x34F290)}
    if helper_offset not in spec:raise RefillUnsupported('unrecovered request environment VM helper')
    size,top_offset,code,table_one,table_two=spec[helper_offset]
    if entry_stack_address<size or entry_stack_address&15:
        raise RefillUnsupported('request environment VM stack must be aligned')
    if return_address>=1<<56:raise RefillUnsupported('PAC-tagged request environment VM return is unsupported')
    p=_PageTransaction(pages);local=entry_stack_address-size
    def word(address,value):_write_span(p,address,value.to_bytes(8,'little'))
    try:
        _read_span(p,local,size);_read_span(p,image_base+code,4)
        for address,value in ((entry_stack_address-0x20,saved_frame_pointer),
                (entry_stack_address-0x18,return_address),(entry_stack_address-0x10,saved_x28),
                (entry_stack_address-8,saved_x19)):
            word(address,value)
        _write_span(p,entry_stack_address-0x28,_read_span(p,thread_pointer+0x28,8))
        top=local+top_offset;backing=top-0x118;callback=image_base+0x2050E4
        for address,value in ((local+0x10,callback),(local+0x18,top),
                (local+0x20,return_address),(top-0x120,image_base+code)):
            word(address,value)
        for slot,value in ((0,0),(4,local+8),(5,image_base+table_one),
                (6,image_base+table_two),(7,callback),(29,(top-0x130)&~15),(31,return_address)):
            word(backing+slot*8,value)
        registers=tuple(int.from_bytes(_read_span(p,backing+i*8,8),'little') for i in range(32))
    except ValueError as exc:raise RefillUnsupported('request environment VM caller memory is unmapped') from exc
    arguments=(image_base+code,local+8,image_base+table_one,image_base+table_two,local+0x10)
    p.commit();return RequestVmCallerFrame(local,code,local+8,local+0x10,backing,registers,arguments)


def request_environment_wrapper_return_offset(wrapper_offset):
    """Only the two observed W-result wrappers may select a helper sentinel."""
    if type(wrapper_offset) is not int or wrapper_offset not in (0x2814C8,0x28863C):
        raise RefillUnsupported('unrecovered request environment wrapper')
    return {0x2814C8:0x2814D8,0x28863C:0x28864C}[wrapper_offset]


def finish_request_environment_wrapper_caller(pages, *, helper_offset,
        entry_stack_address,thread_pointer,image_base,wrapper_offset=0x2814C8) -> RequestCallerReturn:
    """+204eac/+204f30 canary/restore followed by actual +2814d8 wrapper.

    Read the helper's packed W result first. Restore helper registers before
    the wrapper stores that W through restored X19; only then read wrapper
    LR/X19. Live result aliases into saved words preserve this native order.
    Tagged return addresses and unexpected helper return targets are rejected.
    """
    sentinel=request_environment_wrapper_return_offset(wrapper_offset)
    values=(helper_offset,entry_stack_address,thread_pointer,image_base)
    if any(type(v) is not int or not 0<=v<1<<64 for v in values):
        raise RefillUnsupported('request environment return inputs must fit uint64')
    sizes={0x204E50:0x500,0x204ED4:0x3D0}
    if helper_offset not in sizes:raise RefillUnsupported('unrecovered environment helper return')
    size=sizes[helper_offset]
    if entry_stack_address<size+16 or entry_stack_address&15:
        raise RefillUnsupported('request environment return stack must be aligned')
    p=_PageTransaction(pages);entry=entry_stack_address-16;local=entry-size
    try:
        result=int.from_bytes(_read_span(p,local+8,4),'little')
        canary=_read_span(p,thread_pointer+0x28,8)
        if canary!=_read_span(p,entry-0x28,8):
            raise RefillUnsupported('request environment return stack canary mismatch')
        x28=int.from_bytes(_read_span(p,entry-0x10,8),'little')
        packed=int.from_bytes(_read_span(p,entry-8,8),'little')
        x29=int.from_bytes(_read_span(p,entry-0x20,8),'little')
        helper_lr=int.from_bytes(_read_span(p,entry-0x18,8),'little')
        if helper_lr!=image_base+sentinel:
            raise RefillUnsupported('request environment helper LR does not reach its wrapper')
        if packed>(1<<64)-12:raise RefillUnsupported('request environment result address wraps uint64')
        _write_span(p,packed+8,result.to_bytes(4,'little'))
        x30=int.from_bytes(_read_span(p,entry_stack_address-16,8),'little')
        x19=int.from_bytes(_read_span(p,entry_stack_address-8,8),'little')
    except ValueError as exc:raise RefillUnsupported('request environment return memory is unmapped') from exc
    if x30>=1<<56:raise RefillUnsupported('PAC-tagged environment wrapper return is unsupported')
    state=RequestCallerReturn(x30,entry_stack_address,result,x19,x28,x29,x30)
    p.commit();return state


def validate_request_environment_vm_exit(pages, *, helper_offset,image_base,pc,registers,
        wrapper_offset=0x2814C8):
    """Validate the observed +204e50 helper VM return instruction and target."""
    sentinel=request_environment_wrapper_return_offset(wrapper_offset)
    if helper_offset!=0x204E50 or pc!=image_base+0x8A4E8 or len(registers)!=32:
        raise RefillUnsupported('environment helper VM exit is outside the recovered branch')
    word=int.from_bytes(_read_span(pages,pc,4),'little')
    if word!=0x07C00791 or registers[31]!=image_base+sentinel:
        raise RefillUnsupported('environment helper VM exit does not reach its wrapper sentinel')
    return dict(bytecode_offset='0x8a4e8',instruction_word=hex(word),selected_slot=31,
        selected_target=registers[31],caller_sentinel_matches=True,
        native_handler_offset='0x16a974',native_epilogue_offset='0x172440')


@dataclass(frozen=True)
class RequestJniAvailabilityReturn(RequestCallerReturn):
    x20: int
    x21: int
    x22: int
    availability: object


def _execute_request_jni_availability_wrapper_impl(pages, *, image_base,
        entry_stack_address,argument_block_address,return_address,thread_pointer,
        acquire_environment,invoke_jni,saved_frame_pointer=0,saved_x19=0,
        saved_x20=0,saved_x21=0,saved_x22=0,saved_x28=0):
    """Actual +2814c8 -> +204b80 prologue, shared body and ordered return.

    Only saved registers, canary and the acquired output pair are declared
    stack state. Obfuscation temporaries and deeper acquisition spills are
    outside this wrapper's physical-stack contract. Guest pages publish
    atomically; JavaVM/JNI providers own external effects.
    """
    from vm9_jni_environment import check_cached_static_method_availability
    values=(image_base,entry_stack_address,argument_block_address,return_address,
        thread_pointer,saved_frame_pointer,saved_x19,saved_x20,saved_x21,saved_x22,saved_x28)
    if any(type(v) is not int or not 0<=v<1<<64 for v in values):
        raise RefillUnsupported('JNI availability wrapper inputs must fit uint64')
    if entry_stack_address<0x150 or entry_stack_address&15:
        raise RefillUnsupported('JNI availability wrapper stack must be aligned')
    if return_address>=1<<56:
        raise RefillUnsupported('PAC-tagged JNI availability wrapper return is unsupported')
    p=_PageTransaction(pages);W=entry_stack_address;E=W-16
    def read(address,width=8):return int.from_bytes(_read_span(p,address,width),'little')
    def write(address,value,width=8):_write_span(p,address,value.to_bytes(width,'little'))
    try:
        write(W-16,return_address);write(W-8,saved_x19)
        if read(argument_block_address)!=image_base+0x204B80:
            raise RefillUnsupported('unrecovered JNI availability wrapper target')
        for address,value in ((E-0x30,saved_frame_pointer),(E-0x28,image_base+0x2814D8),
                (E-0x20,saved_x22),(E-0x18,saved_x21),(E-0x10,saved_x20),(E-8,argument_block_address)):
            write(address,value)
        _write_span(p,E-0x38,_read_span(p,thread_pointer+0x28,8))
        availability=check_cached_static_method_availability(p,image_base=image_base,
            entry_stack_address=E-0x60,acquire_environment=acquire_environment,invoke_jni=invoke_jni)
        result=availability.availability
        if _read_span(p,thread_pointer+0x28,8)!=_read_span(p,E-0x38,8):
            raise RefillUnsupported('JNI availability wrapper stack canary mismatch')
        x20=read(E-0x10);packed=read(E-8)
        x22=read(E-0x20);x21=read(E-0x18);x29=read(E-0x30);helper_lr=read(E-0x28)
        if helper_lr!=image_base+0x2814D8:
            raise RefillUnsupported('JNI availability helper LR does not reach its wrapper')
        if packed>(1<<64)-12:
            raise RefillUnsupported('JNI availability result address wraps uint64')
        write(packed+8,result,4)
        x30=read(W-16);x19=read(W-8)
        if x30>=1<<56:
            raise RefillUnsupported('PAC-tagged JNI availability wrapper return is unsupported')
    except ValueError as exc:raise RefillUnsupported('JNI availability wrapper memory is unmapped') from exc
    state=RequestJniAvailabilityReturn(x30,W,result,x19,saved_x28,x29,x30,x20,x21,x22,availability)
    p.commit();return state


def execute_request_jni_availability_wrapper(pages, *, image_base,
        entry_stack_address,argument_block_address,return_address,thread_pointer,
        acquire_environment,invoke_jni,saved_frame_pointer=0,saved_x19=0,
        saved_x20=0,saved_x21=0,saved_x22=0,saved_x28=0,effect_journal=None):
    """Run the availability wrapper with an optional provider-effect boundary.

    The historical default remains page-only.  When an owner supplies an
    ``EffectJournal``, acquisition/JNI provider undo records are scoped to this
    callback and remain available to an enclosing request transaction after a
    successful return.
    """
    effect_journal=require_effect_journal(effect_journal)
    kwargs=dict(image_base=image_base,entry_stack_address=entry_stack_address,
        argument_block_address=argument_block_address,return_address=return_address,
        thread_pointer=thread_pointer,acquire_environment=acquire_environment,
        invoke_jni=invoke_jni,saved_frame_pointer=saved_frame_pointer,
        saved_x19=saved_x19,saved_x20=saved_x20,saved_x21=saved_x21,
        saved_x22=saved_x22,saved_x28=saved_x28)
    if effect_journal is None:
        return _execute_request_jni_availability_wrapper_impl(pages,**kwargs)
    with effect_journal.transaction():
        return _execute_request_jni_availability_wrapper_impl(pages,**kwargs)
