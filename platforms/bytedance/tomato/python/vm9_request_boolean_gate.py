"""Fresh +0x28bb5c boolean gate orchestration with explicit leaf boundaries.

Recover lazy encoded globals, stack locals, clock/scope descriptor and the
counter%74 condition. The evaluator and elapsed logger bodies remain explicit
callbacks; an absent callback stops at its real target, never at a fake result.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable
import vm9_callbacks as callbacks
import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span

MASK64 = (1 << 64) - 1


def _u(pages, address, width=8):
    return int.from_bytes(_read_span(pages, address, width), 'little')


def _word(pages, address, value):
    _write_span(pages, address, (value & MASK64).to_bytes(8, 'little'))


def _encoded_delta(image_base):
    entry = image_base + 0x28BB5C
    folded = (((0x00A060400A021040 | (~entry & MASK64)) & 0x00A061440A061440)
        + (entry & 0x0000010400040400)) & MASK64
    return (folded | 0x01010104) ^ 0xFF5F9EBBF4585F1C


def resolve_boolean_gate_addresses(pages, *, image_base):
    delta = _encoded_delta(image_base)
    roles = dict(first_name=0x383980, second_name=0x383988, counter=0x383990,
        first_flag=0x383998, first_source=0x3839A0, first_mask=0x3839A8,
        second_flag=0x3839B0, second_source=0x3839B8, second_mask=0x3839C0,
        scope_constructor=0x383840, evaluator=0x383848, scope_destructor=0x383850)
    resolved = {role: (_u(pages, image_base + offset) + delta) & MASK64 for role, offset in roles.items()}
    for role, offset in (('scope_constructor', 0x28C088), ('evaluator', 0x28B05C), ('scope_destructor', 0x28C09C)):
        if resolved[role] != image_base + offset:
            raise RefillUnsupported('boolean gate indirect target layout does not match this sample: ' + role)
    return resolved


@dataclass(frozen=True)
class BooleanGateResult:
    returned_boolean: bool
    evaluator_called: bool
    counter_value: int
    original_cached_byte: int
    scope_address: int
    start_address: int
    evaluator_argument_address: int
    second_name_address: int


def execute_boolean_gate(pages, *, object_address: int, image_base: int,
        entry_stack_address: int, read_clock: Callable, evaluate=None,
        leave_scope=None, observer=None):
    """+0x28bb5c orchestration, preserving leaf call and guest store order.

    evaluate(pages, descriptor_address, 2, name_address) supplies +0x28b05c;
    leave_scope(pages, scope_address) supplies +0x28c09c. These are explicit
    component services, not default runtime implementations. Observers can
    record the fresh prelude even when a missing leaf raises a boundary.
    Guest changes publish only on success. A boundary observer may inspect
    the transaction, but must not inject native output into it.
    """
    if not callable(read_clock):
        raise RefillUnsupported('boolean gate requires an explicit clock provider')
    for value in (object_address, image_base, entry_stack_address):
        if not isinstance(value, int) or not 0 < value <= MASK64:
            raise RefillUnsupported('boolean gate pointers must be positive uint64')
    if entry_stack_address & 15 or entry_stack_address < 0x100:
        raise RefillUnsupported('boolean gate stack must be aligned with scratch space')
    p = _PageTransaction(pages)
    _read_span(p, object_address, 2)
    _read_span(p, entry_stack_address - 0x100, 0x60)
    addresses = resolve_boolean_gate_addresses(p, image_base=image_base)
    globals_ledger = []
    for label in ('first', 'second'):
        flag = addresses[label + '_flag']
        initial = _u(p, flag, 4)
        length = None
        if initial == 0:
            length = objects.decode_masked_bytes(p, source_address=addresses[label + '_source'],
                destination_address=addresses[label + '_name'], mask_address=addresses[label + '_mask'])
            _write_span(p, flag, (1).to_bytes(4, 'little'))
        globals_ledger.append(dict(name=label, flag_address=flag, flag_before=initial,
            decode_performed=initial == 0, decoded_length=length))
    start, scope, scope_source = (entry_stack_address - n for n in (0xB0, 0xC0, 0xD0))
    name_argument = entry_stack_address - 0xE0
    duplicated_first = entry_stack_address - 0xF0
    boolean_slot = entry_stack_address - 0x100
    clock_word = callbacks.store_monotonic_start(p, object_address=start, read_clock=read_clock)
    # The native +0x28c088 borrows a start pointer from its input word,
    # then writes flag at destination+8 before destination+0.
    _word(p, scope_source, start)
    _write_span(p, scope + 8, b'\1')
    _word(p, scope, _u(p, scope_source))
    _write_span(p, boolean_slot, b'\0')
    _word(p, name_argument, addresses['second_name'])
    _word(p, duplicated_first, addresses['first_name'])
    _word(p, duplicated_first + 8, addresses['first_name'])
    counter = _u(p, addresses['counter'])
    original = _u(p, object_address + 1, 1)
    needed = counter % 74 == 0 or original != 0
    context = dict(addresses=addresses, globals=globals_ledger, clock_word=clock_word,
        start_address=start, scope_address=scope, scope_source_address=scope_source,
        evaluator_argument_address=duplicated_first, second_name_slot_address=name_argument, boolean_slot=boolean_slot,
        duplicated_first_address=duplicated_first, counter_value=counter,
        original_cached_byte=original, evaluator_needed=needed)
    if observer:
        observer(p, phase='before_evaluator' if needed else 'evaluator_skipped', **context)
    if needed:
        if evaluate is None:
            raise RefillUnsupported('request boolean evaluator +0x28b05c is not recovered')
        raw = evaluate(p, duplicated_first, 2, _u(p, name_argument))
        if not isinstance(raw, int) or not 0 <= raw <= MASK64:
            raise RefillUnsupported('boolean evaluator result must be a uint64 ABI word')
        _write_span(p, boolean_slot, bytes([raw & 1]))
    result = _u(p, boolean_slot, 1)
    _write_span(p, object_address + 1, bytes([result]))
    if observer:
        observer(p, phase='before_scope_cleanup', result=result, **context)
    if leave_scope is None:
        raise RefillUnsupported('request boolean scope destructor +0x28c09c is not recovered')
    leave_scope(p, scope)
    p.commit()
    return BooleanGateResult(bool(result), needed, counter, original, scope, start,
        duplicated_first, addresses['second_name'])
