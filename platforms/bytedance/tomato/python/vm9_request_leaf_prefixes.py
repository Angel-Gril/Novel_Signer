"""Recovered request leaf prefixes; missing real JNI/format bodies refuse.

+0x28b05c is a Java stack-trace evaluator, not the signature algorithm.
+0x28ddd0 samples a diagnostic event by its fourth uint64 argument.
No callback result, JNI environment or native snapshot is synthesized here.
The mode body can run with explicit owning allocator/free services.
"""
from __future__ import annotations
import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span

MASK64 = (1 << 64) - 1
EVALUATOR_GLOBAL_OFFSETS = (
    (0x3E1520, 0x3E1534, 0x11E8F0, 0x11EB00),
    (0x3E1538, 0x3E1548, 0x11E904, 0x11EAE8),
    (0x3E1550, 0x3E1568, 0x11E920, 0x11EAD0),
    (0x3E156C, 0x3E157C, 0x11E938, 0x11EAB4),
    (0x3E1580, 0x3E15A4, 0x11E950, 0x11EA90),
    (0x3E15B0, 0x3E15CC, 0x11E980, 0x11EA70),
    (0x3E15D0, 0x3E15E0, 0x11E99C, 0x11EA58),
    (0x3E15F0, 0x3E1608, 0x11E9B0, 0x11EA40),
    (0x3E160C, 0x3E161C, 0x11E9C8, 0x11EA28),
)


def _uint(value, bits, label):
    if not isinstance(value, int) or not 0 <= value < 1 << bits:
        raise RefillUnsupported(label + ' must fit uint' + str(bits))


def _stack(value, scratch):
    _uint(value, 64, 'entry stack')
    if value < scratch or value & 15:
        raise RefillUnsupported('request leaf stack must be aligned with scratch space')


def _u(pages, address, width=8):
    return int.from_bytes(_read_span(pages, address, width), 'little')


def _w(pages, address, value, width=8):
    _write_span(pages, address, value.to_bytes(width, 'little'))


def _lazy(pages, *, image_base, name, flag, source, mask):
    before = _u(pages, image_base + flag, 4)
    length = None
    if before == 0:
        length = objects.decode_masked_bytes(pages, source_address=image_base + source,
            destination_address=image_base + name, mask_address=image_base + mask)
        _w(pages, image_base + flag, 1, 4)
    return dict(name_address=image_base + name, flag_address=image_base + flag,
        flag_before=before, decode_performed=before == 0, decoded_length=length)


def resolve_stack_evaluator_globals(pages, *, image_base):
    """Resolve original ELF table +0x383860 using this function's address."""
    entry = image_base + 0x28B05C
    folded = (((0x00A060400A021040 | (~entry & MASK64)) & 0x00A061440A061440)
        + (entry & 0x0000010400040400)) & MASK64
    delta = (folded | 0x01010104) ^ 0xFF5F9EBBF4585F1C
    resolved = []
    for index, expected in enumerate(EVALUATOR_GLOBAL_OFFSETS):
        slots = (index * 8, 0x48 + index * 24, 0x50 + index * 24, 0x58 + index * 24)
        words = [_u(pages, image_base + 0x383860 + slot) for slot in slots]
        values = tuple((word + delta) & MASK64 for word in words)
        if values != tuple(image_base + offset for offset in expected):
            raise RefillUnsupported('stack evaluator encoded global table does not match sample')
        resolved.append(dict(name=values[0], flag=values[1], source=values[2], mask=values[3],
            encoded_name=words[0]))
    return resolved


def execute_stack_evaluator_prefix(pages, *, image_base, entry_stack_address,
        descriptor_address, descriptor_count, method_name_address, observer=None,
        acquire_environment=None):
    """+0x28b05c through actual +0x26edc4 acquisition call; no fake env.

    Native saves encoded pointers and input slots, then initializes nine lazy
    names in order. The environment output pair is still untouched at this
    call boundary. With an explicit acquisition provider, continue through
    environment storage to the original FindClass callsite +0x28b71c.
    Observer sees staged pages only; this incomplete body never commits.
    """
    _stack(entry_stack_address, 0xF0)
    _uint(image_base, 64, 'image base')
    _uint(descriptor_address, 64, 'descriptor address')
    _uint(descriptor_count, 32, 'descriptor count')
    _uint(method_name_address, 64, 'method name address')
    p = _PageTransaction(pages)
    frame = entry_stack_address - 0x60
    _w(p, frame - 0x30, method_name_address)
    _w(p, frame - 0x50, descriptor_count, 4)
    addresses = resolve_stack_evaluator_globals(p, image_base=image_base)
    _w(p, frame - 0x18, addresses[4]['encoded_name'])
    _w(p, frame - 0x10, addresses[3]['encoded_name'])
    _w(p, frame - 0x28, descriptor_address)
    _w(p, frame - 0x20, addresses[5]['encoded_name'])
    _w(p, frame - 0x38, addresses[6]['encoded_name'])
    _w(p, frame - 0x48, addresses[8]['encoded_name'])
    _w(p, frame - 0x40, addresses[7]['encoded_name'])
    ledger = [_lazy(p, image_base=image_base, name=n, flag=f, source=s, mask=m)
        for n, f, s, m in EVALUATOR_GLOBAL_OFFSETS]
    environment_pair = entry_stack_address - 0xE0
    if observer:
        observer(p, phase='before_jni_acquisition', globals=ledger, addresses=addresses,
            descriptor_address=descriptor_address, descriptor_count=descriptor_count,
            method_name_address=method_name_address,
            environment_pair_address=environment_pair,
            environment_slot_address=entry_stack_address - 0xF0,
            unresolved_leaf_target_offset='0x26edc4', body_transaction_committed=False)
    if acquire_environment is None:
        raise RefillUnsupported('request JNI acquisition +0x26edc4 is not recovered')
    acquire_environment(p,entry_stack_address=entry_stack_address-0xF0,
        output_pair_address=environment_pair)
    environment = _u(p,environment_pair)
    if not environment:
        raise RefillUnsupported('request JNI null-environment continuation +0x28b7c8 is not recovered')
    _w(p,entry_stack_address-0xF0,environment)
    table = _u(p,environment)
    if not table:
        raise RefillUnsupported('request JNI environment table is missing')
    target = _u(p,table+0x30)
    if not target:
        raise RefillUnsupported('request JNI FindClass function is missing')
    if observer:
        observer(p,phase='before_jni_find_class',globals=ledger,addresses=addresses,
            environment_pair_address=environment_pair,environment_slot_address=entry_stack_address-0xF0,
            environment=environment,jni_vtable_slot=0x30,jni_call_target=target,
            jni_call_arguments=(environment,addresses[0]['name']),
            native_callsite_offset='0x28b71c',body_transaction_committed=False)
    raise RefillUnsupported('request JNI FindClass +0x28b71c is not recovered')


def execute_event_mode_prefix(pages, *, image_base, entry_stack_address,
        output_object_address, mode, observer=None, allocate=None, free=None):
    """Prepare mode prefix; allocator/free services enable the bounded body."""
    _stack(entry_stack_address, 0x140)
    _uint(mode, 32, 'event mode')
    _uint(output_object_address, 64, 'mode output address')
    p = _PageTransaction(pages)
    ledger = _lazy(p, image_base=image_base, name=0x3E1AD0,
        flag=0x3E1ADC, source=0x11F1CC, mask=0x11F1D8)
    argument = entry_stack_address - 0x60
    _w(p, argument, mode, 4)
    if observer:
        observer(p, phase='before_mode_format_builder', globals=[ledger],
            output_object_address=output_object_address,
            format_address=image_base + 0x3E1AD0,
            argument_address=argument, mode=mode,
            format_object_address=entry_stack_address - 0xB0,
            conversion_object_address=entry_stack_address - 0x140,
            unresolved_leaf_target_offset='0x28f0f4', body_transaction_committed=False)
    if allocate is None or free is None:
        raise RefillUnsupported('request mode construction +0x28f0f4 requires allocator/free services')
    import vm9_request_format_objects as formatting
    result = formatting.execute_event_mode(p, image_base=image_base,
        entry_stack_address=entry_stack_address, output_object_address=output_object_address,
        mode=mode, allocate=allocate, free=free, observer=observer)
    p.commit()
    return result


def execute_event_formatter_prefix(pages, *, image_base, entry_stack_address,
        event_object_address, argument_words, mode, observer=None, allocate=None, free=None):
    """+0x28ddd0 sampling and locals; selected branch enters real mode prefix.

    AArch64 UDIV by zero produces zero, so the remainder is the sequence word.
    The fourth uint64 word (X4) is sampled; it is not a clock value here.
    Return indicates only whether this bounded path selected formatting;
    it does not represent the native function's unspecified X0 return ABI.
    """
    _stack(entry_stack_address, 0x1B0)
    _uint(event_object_address, 64, 'event object address')
    if len(argument_words) != 4:
        raise RefillUnsupported('request formatter requires four uint64 words')
    for value in argument_words:
        _uint(value, 64, 'formatter argument')
    _uint(mode, 32, 'formatter mode')
    p = _PageTransaction(pages)
    local = entry_stack_address - 0x1B0
    first, second, third, sequence = argument_words
    _w(p, local + 0x48, second)
    _w(p, local + 0x50, first)
    _w(p, local + 0x38, sequence)
    _w(p, local + 0x40, third)
    _w(p, local + 0x34, mode, 4)
    divisor = _u(p, image_base + 0x3839E8)
    quotient = sequence // divisor if divisor else 0
    remainder = sequence - quotient * divisor
    selected = remainder == 0
    if observer:
        observer(p, phase='sampling_decision', divisor=divisor, sequence=sequence,
            remainder=remainder, selected=selected,
            argument_words=list(argument_words), mode=mode,
            argument_slots_address=local + 0x34,
            mode_output_address=local + 0x18,
            unresolved_leaf_target_offset='0x28e788' if selected else None,
            body_transaction_committed=False)
    if selected:
        execute_event_mode_prefix(p, image_base=image_base,
            entry_stack_address=local, output_object_address=local + 0x18,
            mode=mode, observer=observer, allocate=allocate, free=free)
        if observer:
            observer(p, phase='before_event_arguments_formatter',
                format_address=image_base+0x6FF77,
                format_object_address=local+0x58,
                mode_output_address=local+0x18,
                mode_cpp_object_hex=_read_span(p,local+0x18,24).hex(),
                argument_addresses=[local+n for n in (0x50,0x48,0x40,0x38,0x34)],
                call_target_offset='0x28e86c', unresolved_leaf_target_offset=None, body_transaction_committed=False)
        import vm9_request_format_objects as formatting
        from vm9_cpp_strings import construct_cpp_string
        formatting.execute_event_arguments(p,image_base=image_base,
            format_object_address=local+0x58,conversion_object_address=local+0xE8,
            output_object_address=local,format_address=image_base+0x6FF77,
            argument_addresses=tuple(local+n for n in (0x50,0x48,0x40,0x38,0x34)),
            allocate=allocate,free=free,observer=observer)
        construct_cpp_string(p,object_address=local+0x58,
            source_address=image_base+0x6E844,allocate=allocate)
        if observer:
            observer(p,phase='before_event_emission',event_object_address=event_object_address,
                mode_output_address=local+0x18,arguments_output_address=local,
                auxiliary_output_address=local+0x58,
                mode_cpp_object_hex=_read_span(p,local+0x18,24).hex(),
                arguments_cpp_object_hex=_read_span(p,local,24).hex(),
                auxiliary_cpp_object_hex=_read_span(p,local+0x58,24).hex(),
                unresolved_leaf_target_offset='0x28ff44',body_transaction_committed=False)
        import vm9_request_event as events
        from vm9_cpp_strings import destroy_cpp_string
        events.execute_event_emission(p,image_base=image_base,entry_stack_address=local,
            input_object_addresses=(event_object_address,local+0x18,local,local+0x58),
            allocate=allocate,free=free,observer=observer)
        for address in (local+0x58,local,local+0x18):
            destroy_cpp_string(p,object_address=address,free=free)
        if observer:
            observer(p,phase='event_formatter_completed',bounded_event_formatter_completed=True,
                whole_request_callback_completed=False,body_transaction_committed=True)
        p.commit()
        return True
    p.commit()
    return False
