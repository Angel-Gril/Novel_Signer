"""Recovered request leaves with explicit JNI and owning component services.

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
        acquire_environment=None, invoke_jni=None, get_singleton=None,
        max_frames=4096, max_string_bytes=0x100000):
    """Actual +0x28b05c acquisition, stack inspection and local cleanup.

    JNI results and the +0x161068 singleton getter are explicit services.
    No-argument object calls preserve both logical va_list structures; their
    unconsumed GP/SIMD saves and physical spills remain outside this API.
    The original compares the first UTF pointer against both expected names,
    with prefix lengths, and still acquires/releases the second UTF pointer.
    Nonzero checked-comparison environment branches refuse transactionally.
    """
    _stack(entry_stack_address, 0x210)
    _uint(image_base, 64, 'image base')
    _uint(descriptor_address, 64, 'descriptor address')
    _uint(descriptor_count, 32, 'descriptor count')
    _uint(method_name_address, 64, 'method name address')
    if type(max_frames) is not int or not 1 <= max_frames <= 0x100000:
        raise RefillUnsupported('stack evaluator frame bound is invalid')
    objects._string_bound(max_string_bytes)
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
        if observer:
            observer(p, phase='stack_evaluator_completed', returned_boolean=False,
                inspected_frames=0, body_transaction_committed=True,
                whole_request_callback_completed=False)
        p.commit()
        return 0
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
    if invoke_jni is None:
        raise RefillUnsupported('request JNI FindClass +0x28b71c is not recovered')
    import vm9_jni_environment as jni
    call_sp = entry_stack_address - 0xF0
    def call(slot, *args):
        return jni._invoke_jni(p, environment, slot, args, invoke_jni)
    def check():
        return jni.check_and_clear_java_exception(p,
            environment_pointer=environment, invoke_jni=invoke_jni)
    def remove(ref):
        call(0xB8, ref)
    def object_call(slot, ref, method):
        original, copied = call_sp - 0x48, call_sp - 0x70
        raw = b''.join(v.to_bytes(8, 'little') for v in
            (call_sp, copied, call_sp - 0xA0))
        raw += (-40).to_bytes(4, 'little', signed=True)
        raw += (-128).to_bytes(4, 'little', signed=True)
        _write_span(p, original, raw)
        _write_span(p, copied, _read_span(p, original, 32))
        return call(slot, ref, method, copied)
    def length(address):
        # +0x27617c returns zero for NULL; do not dereference that pointer.
        return len(objects._cstring(p, address, max_string_bytes)) - 1 if address else 0
    def compare(first, second, width):
        # +0x276298 has no singleton effects when its initial length is zero.
        result = 0
        if not width:
            return result
        for i in range(width):
            left, right = _u(p, first + i, 1), _u(p, second + i, 1)
            result = left - right
            if result or not left:
                break
        else:
            return 0
        if not callable(get_singleton):
            raise RefillUnsupported('stack evaluator comparison requires a singleton getter')
        reference = get_singleton(p, call_sp - 0x30)
        _uint(reference, 64, 'comparison singleton reference')
        first_field = _u(p, _u(p, reference) + 0x10)
        reference = get_singleton(p, call_sp - 0x30)
        _uint(reference, 64, 'comparison singleton reference')
        if first_field and _u(p, _u(p, reference) + 0x18):
            raise RefillUnsupported('stack evaluator checked-comparison environment branch is unrecovered')
        return result
    class _StopInspection(Exception):
        pass
    cleanup = []
    result = 0
    inspected = 0
    first_class = call(0x30, addresses[0]['name'])
    if first_class and not check():
        cleanup.append(first_class)
        try:
            static_method = call(0x388, first_class, addresses[1]['name'], addresses[2]['name'])
            if not static_method:
                raise _StopInspection
            thread = object_call(0x398, first_class, static_method)
            if not thread or check():
                raise _StopInspection
            cleanup.append(thread)
            trace_method = call(0x108, first_class, addresses[3]['name'], addresses[4]['name'])
            if not trace_method:
                raise _StopInspection
            trace = object_call(0x118, thread, trace_method)
            if not trace or check():
                raise _StopInspection
            cleanup.append(trace)
            count = objects._s32(call(0x558, trace) & 0xFFFFFFFF)
            if count < 3:
                raise _StopInspection
            element_class = call(0x30, addresses[5]['name'])
            if not element_class or check():
                raise _StopInspection
            cleanup.append(element_class)
            first_method = call(0x108, element_class, addresses[6]['name'], addresses[7]['name'])
            _w(p, frame - 0x38, first_method)
            if not first_method:
                raise _StopInspection
            second_method = call(0x108, element_class, addresses[8]['name'], addresses[7]['name'])
            _w(p, frame - 0x40, second_method)
            if not second_method:
                raise _StopInspection
            _w(p, frame - 0x70, element_class)
            _w(p, frame - 0x68, thread)
            _w(p, frame - 0x60, trace)
            limit = min(count, objects._s32((descriptor_count + 2) & 0xFFFFFFFF))
            _w(p, frame - 0x20, limit & 0xFFFFFFFF, 4)
            if max(0, limit - 2) > max_frames:
                raise RefillUnsupported('stack evaluator frame bound exceeded')
            descriptor_index = 0
            for index in range(2, limit):
                inspected += 1
                element = call(0x568, trace, index)
                if not element:
                    continue
                first_string = object_call(0x118, element, first_method)
                _w(p, frame - 0x18, first_string)
                _w(p, frame - 0x10, descriptor_index)
                first_failed = check() if first_string else True
                second_string = object_call(0x118, element, second_method)
                second_failed = check() if second_string else True
                if not first_failed and not second_failed:
                    first_utf = call(0x548, first_string, 0)
                    second_utf = call(0x548, second_string, 0)
                    _w(p, frame - 0x48, second_utf)
                    if first_utf and second_utf:
                        _w(p, frame - 0x50, first_utf)
                        first_length = length(first_utf)
                        expected = _u(p, descriptor_address + descriptor_index * 8)
                        expected_length = length(expected)
                        _w(p, frame - 0x58, expected_length)
                        method_length = length(method_name_address)
                        if compare(first_utf, method_name_address, min(first_length, method_length)):
                            if compare(first_utf, expected, min(first_length, expected_length)):
                                result = 1
                        descriptor_index += 1
                        _w(p, frame - 0x10, descriptor_index)
                    if first_utf:
                        call(0x550, first_string, first_utf)
                    if second_utf:
                        call(0x550, second_string, second_utf)
                if first_string:
                    remove(first_string)
                if second_string:
                    remove(second_string)
                remove(element)
        except _StopInspection:
            pass
        for ref in reversed(cleanup):
            remove(ref)
    # The final check only clears; it does not call ExceptionOccurred/delete.
    jni.clear_java_exception(p, environment_pointer=environment, invoke_jni=invoke_jni)
    if observer:
        observer(p, phase='stack_evaluator_completed', returned_boolean=bool(result),
            inspected_frames=inspected, body_transaction_committed=True,
            whole_request_callback_completed=False)
    p.commit()
    return result


def execute_elapsed_event(pages, *, image_base, entry_stack_address,
        elapsed_word, sequence_word, mode=0, allocate, free, observer=None):
    """+0x28e204 names, sampled two-cell formatter, emission and cleanup."""
    _stack(entry_stack_address,0x400)
    _uint(elapsed_word,64,'elapsed word');_uint(sequence_word,64,'elapsed sequence')
    _uint(mode,32,'elapsed mode')
    if not callable(allocate) or not callable(free):
        raise RefillUnsupported('elapsed event requires allocator/free services')
    from vm9_cpp_strings import construct_cpp_string, clone_cpp_string, destroy_cpp_string
    import vm9_request_format_objects as formatting
    import vm9_request_event as events
    p = _PageTransaction(pages)
    for n,f,s,m in ((0x3E1A10,0x3E1A30,0x11F140,0x11F260),
                    (0x3E1A40,0x3E1A60,0x11F160,0x11F240)):
        _lazy(p,image_base=image_base,name=n,flag=f,source=s,mask=m)
    first,second,first_copy,second_copy=(entry_stack_address-n for n in (0x80,0xA0,0xC0,0xE0))
    construct_cpp_string(p,object_address=first,source_address=image_base+0x3E1A10,allocate=allocate)
    construct_cpp_string(p,object_address=second,source_address=image_base+0x3E1A40,allocate=allocate)
    emitted=0
    def format_event(obj):
        nonlocal emitted
        # Both call sites use the same original SP, including the second copy.
        local=entry_stack_address-0xE0-0x170
        _w(p,local+0x38,sequence_word);_w(p,local+0x40,elapsed_word)
        divisor=_u(p,image_base+0x3839E8)
        remainder=sequence_word % divisor if divisor else sequence_word
        if remainder:
            return
        formatting.execute_event_mode(p,image_base=image_base,entry_stack_address=local,
            output_object_address=local+0x20,mode=mode,allocate=allocate,free=free)
        formatting.execute_elapsed_arguments(p,image_base=image_base,
            format_object_address=local+0x48,conversion_object_address=local+0xA8,
            output_object_address=local+8,format_address=image_base+0x6E9C7,
            argument_addresses=(local+0x40,local+0x38),allocate=allocate,free=free)
        construct_cpp_string(p,object_address=local+0xA8,source_address=image_base+0x6E844,allocate=allocate)
        events.execute_event_emission(p,image_base=image_base,entry_stack_address=local,
            input_object_addresses=(obj,local+0x20,local+8,local+0xA8),allocate=allocate,free=free)
        for address in (local+0xA8,local+8,local+0x20):
            destroy_cpp_string(p,object_address=address,free=free)
        emitted+=1
    clone_cpp_string(p,object_address=first_copy,source_object_address=first,allocate=allocate)
    format_event(first_copy)
    destroy_cpp_string(p,object_address=first_copy,free=free)
    if mode:
        clone_cpp_string(p,object_address=second_copy,source_object_address=second,allocate=allocate)
        format_event(second_copy)
        destroy_cpp_string(p,object_address=second_copy,free=free)
    destroy_cpp_string(p,object_address=second,free=free)
    destroy_cpp_string(p,object_address=first,free=free)
    if observer:
        observer(p,phase='elapsed_event_completed',emission_calls=emitted,
            whole_request_callback_completed=False,body_transaction_committed=True)
    p.commit()
    return emitted


def leave_boolean_scope(pages, *, image_base, entry_stack_address,
        scope_address, read_clock, allocate, free, observer=None):
    """Actual +0x28c09c: elapsed clock, uint64 fetch-add and tail event call.

    The serialized fetch-add returns the old counter and wraps its stored
    increment; host concurrency and architecture-specific atomicity are not
    claimed. The counter still advances when sampling skips event emission.
    """
    _stack(entry_stack_address,0x400)
    _uint(scope_address,64,'boolean scope address')
    p = _PageTransaction(pages)
    if not _u(p,scope_address+8,1):
        p.commit()
        return 0
    import vm9_callbacks as callbacks
    if not callable(read_clock):
        raise RefillUnsupported('boolean scope cleanup requires a clock provider')
    elapsed=callbacks.elapsed_monotonic_microseconds(p,object_address=_u(p,scope_address),read_clock=read_clock)
    counter_address=image_base+0x3E1620
    sequence=_u(p,counter_address)
    _w(p,counter_address,(sequence+1)&MASK64)
    emitted=execute_elapsed_event(p,image_base=image_base,entry_stack_address=entry_stack_address,
        elapsed_word=elapsed&MASK64,sequence_word=sequence,allocate=allocate,free=free,observer=observer)
    if observer:
        observer(p,phase='boolean_scope_completed',elapsed_microseconds=elapsed,
            counter_before=sequence,counter_after=(sequence+1)&MASK64,emission_calls=emitted,
            whole_request_callback_completed=False,body_transaction_committed=True)
    p.commit()
    return emitted


def execute_request_byte_gate(pages, *, image_base, object_address, observer=None):
    """+0x28c0ec decodes its name and invokes this ELF's zero-return leaf.

    Encoded +0x383858 resolves to +0x28bb54 (MOV W0,0; RET). It does not
    resolve to the distinct Java publisher +0x28c268. A changed target refuses.
    """
    _uint(image_base,64,'image base');_uint(object_address,64,'request byte gate')
    p = _PageTransaction(pages)
    entry=image_base+0x28C0EC
    folded=(((0x00A060400A021040|(~entry&MASK64))&0x00A061440A061440)
        +(entry&0x0000010400040400))&MASK64
    delta=((folded|0x01010104)^0xFF5F9EBBF4585F1C)&MASK64
    def resolve(offset):return (_u(p,image_base+offset)+delta)&MASK64
    name,flag,source,mask=(resolve(off) for off in (0x3839C8,0x3839D0,0x3839D8,0x3839E0))
    if (name,flag,source,mask)!=tuple(image_base+off for off in (0x3E1648,0x3E1658,0x11E9F0,0x11EA00)):
        raise RefillUnsupported('request byte gate encoded globals do not match sample')
    before=_u(p,flag,4)
    if not before:
        objects.decode_masked_bytes(p,source_address=source,destination_address=name,mask_address=mask)
        _w(p,flag,1,4)
    target=resolve(0x383858)
    if target!=image_base+0x28BB54 or _read_span(p,target,8)!=bytes.fromhex('e0031f2ac0035fd6'):
        raise RefillUnsupported('request byte gate zero-return target is unrecovered')
    _w(p,object_address,0,1)
    if observer:
        observer(p,phase='request_byte_gate_completed',flag_before=before,
            actual_target_offset='0x28bb54',returned_byte=0,
            body_transaction_committed=True,whole_request_callback_completed=False)
    p.commit()
    return 0


def publish_request_handle(pages, *, image_base, entry_stack_address, root_address,
        acquire_environment, invoke_jni, observer=None):
    """Actual +0x28c268: acquire, dispatch both tags, then clean both refs.

    +0x28c308 tail-adapts each tag to (tag,0,root,0,0) for +0x26e70c.
    Cleanup uses the first acquired environment after both dispatches, even
    when later acquisitions return different environments. Return tests the
    first dispatch reference for NULL; it never reads a Java Boolean value.
    """
    _stack(entry_stack_address,0x1E0)
    _uint(image_base,64,'image base');_uint(root_address,64,'published root')
    if not callable(acquire_environment):
        raise RefillUnsupported('request publication requires environment acquisition')
    import vm9_jni_environment as jni
    p = _PageTransaction(pages);stack=entry_stack_address-0x50;pair=stack+8
    acquire_environment(p,entry_stack_address=stack,output_pair_address=pair)
    environment=_u(p,pair)
    references=[]
    for tag in (0x2000001,0x2000002):
        result=jni.invoke_java_dispatch(p,image_base=image_base,entry_stack_address=stack,
            argument_words=(tag,0,root_address,0,0),acquire_environment=acquire_environment,
            invoke_jni=invoke_jni)
        references.append(result.returned_reference)
    for ref in references:
        jni.release_java_reference(p,environment_pointer=environment,reference=ref,invoke_jni=invoke_jni)
    returned=int(bool(references[0]))
    if observer:
        observer(p,phase='request_publication_completed',first_environment=environment,
            first_reference=references[0],second_reference=references[1],returned_boolean=bool(returned),
            body_transaction_committed=True,whole_request_callback_completed=False)
    p.commit()
    return returned


def construct_request_object(pages, *, image_base, entry_stack_address,
        object_address, kind, source_string_address, reference_address, mode, flag,
        thread_pointer, allocate, read_clock, thread_id=None, diagnostic_observer=None,
        observer=None, max_payload_bytes=0x100000):
    """Actual +0x25ce68 object, cloned string, shared reference and realtime.

    Kind/mode use W registers, flag uses its low byte. Padding is preserved.
    The reference copy reuses the recovered diagnostic scope and count owner.
    Return the signed realtime millisecond value left by +0x26cc60.
    """
    _stack(entry_stack_address, 0x80)
    for value, label in ((kind, 'request kind'), (mode, 'request mode'), (flag, 'request flag')):
        _uint(value, 32, label)
    for value, label in ((image_base, 'image base'), (object_address, 'request object'),
            (source_string_address, 'source string'), (reference_address, 'request reference')):
        _uint(value, 64, label)
    if not callable(allocate):
        raise RefillUnsupported('request object requires allocation')
    import vm9_reference_scopes as references
    import vm9_callbacks as callbacks
    p = _PageTransaction(pages)
    _w(p, object_address + 8, kind, 4)
    _w(p, object_address, image_base + 0x35B868)
    objects.clone_string_object(p, object_address=object_address + 0x10,
        source_object_address=source_string_address, allocate=allocate,
        image_base=image_base, max_payload_bytes=max_payload_bytes)
    references.copy_scoped_string_reference(p, destination_address=object_address + 0x28,
        source_address=reference_address, entry_stack_address=entry_stack_address - 0x30,
        image_base=image_base, thread_pointer=thread_pointer, allocate=allocate,
        thread_id=thread_id, diagnostic_observer=diagnostic_observer)
    timestamp = callbacks.read_realtime_milliseconds(p, read_clock=read_clock)
    _w(p, object_address + 0x40, 0, 1)
    _w(p, object_address + 0x44, mode, 4)
    _w(p, object_address + 0x38, timestamp & MASK64)
    _w(p, object_address + 0x48, flag & 255, 1)
    if observer:
        observer(p, phase='request_object_constructed', object_address=object_address,
            kind=kind, mode=mode, flag=flag & 255, realtime_milliseconds=timestamp,
            body_transaction_committed=True, whole_request_callback_completed=False)
    p.commit()
    return timestamp


def construct_request_object_with_null_reference(pages, *, image_base, entry_stack_address,
        object_address, kind, source_string_address, mode, flag, thread_pointer,
        allocate, free, read_clock, thread_id=None, diagnostic_observer=None,
        observer=None, max_payload_bytes=0x100000):
    """+0x25cdd4: construct a NULL reference, copy it, then release the temporary.

    The generated count survives with one owner in object+0x28. This models
    constructor effects; the wrapper's incidental X0 return is unspecified.
    """
    _stack(entry_stack_address, 0xE0)
    if not callable(allocate) or not callable(free):
        raise RefillUnsupported('request object lifecycle requires allocator/free services')
    import vm9_reference_scopes as references
    p = _PageTransaction(pages)
    stack = entry_stack_address - 0x60
    temporary = stack + 8
    keywords = dict(entry_stack_address=stack, image_base=image_base,
        thread_pointer=thread_pointer, allocate=allocate, thread_id=thread_id,
        diagnostic_observer=diagnostic_observer)
    references.construct_scoped_string_reference(p, reference_address=temporary,
        string_address=0, **keywords)
    construct_request_object(p, object_address=object_address, kind=kind,
        source_string_address=source_string_address, reference_address=temporary,
        mode=mode, flag=flag, read_clock=read_clock, max_payload_bytes=max_payload_bytes,
        observer=observer, **keywords)
    references.release_scoped_string_reference(p, reference_address=temporary,
        free=free, **keywords)
    if observer:
        observer(p, phase='request_object_lifecycle_completed', object_address=object_address,
            temporary_reference_address=temporary, body_transaction_committed=True,
            whole_request_callback_completed=False)
    p.commit()


def destroy_request_object(pages, *, image_base, entry_stack_address,
        object_address, thread_pointer, allocate, free, thread_id=None,
        diagnostic_observer=None, observer=None):
    """+0x25cf98: restore vtable, release the scoped reference, destroy string.

    The event path +0x25cfe4 is still unrecovered. Inactive events or a prior
    nonzero emission byte follow the actual cleanup branch. +0x162714 and
    +0x15e1a8 have the same scope and reference-release instructions; reuse
    the verified owner for NULL, retained and supported string references.
    Other virtual deleting-destructor targets retain its explicit rejection.
    """
    _stack(entry_stack_address, 0x60)
    for value,label in ((image_base,'image base'),(object_address,'request object'),
                       (thread_pointer,'request thread pointer')):
        _uint(value,64,label)
    if not callable(allocate) or not callable(free):
        raise RefillUnsupported('request destructor requires allocator/free services')
    import vm9_reference_scopes as references
    p = _PageTransaction(pages)
    flag = _u(p,object_address + 0x48,1)
    _w(p,object_address,image_base + 0x35B868)
    if flag and not _u(p,object_address + 0x40,1):
        raise RefillUnsupported('request destructor event emission +0x25cfe4 is not recovered')
    references.release_scoped_string_reference(p,reference_address=object_address + 0x28,
        entry_stack_address=entry_stack_address - 0x20,image_base=image_base,
        thread_pointer=thread_pointer,thread_id=thread_id,allocate=allocate,free=free,
        diagnostic_observer=diagnostic_observer)
    objects.destroy_string_object(p,object_address=object_address + 0x10,
        image_base=image_base,free=free)
    if observer:
        observer(p,phase='request_object_destroyed',object_address=object_address,
            event_emission_branch_taken=False,body_transaction_committed=True,
            whole_request_callback_completed=False)
    p.commit()


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
