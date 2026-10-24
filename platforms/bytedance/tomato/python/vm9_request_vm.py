"""Owning request VM execution and explicit services for the recovered sample.

Execution can return a staged prefix for diagnostic consumers. The strict
adapters below require a completed VM/caller return before publishing pages.
The interpreter and JNI/OS services are supplied by the caller; execution is
serial because the interpreter module base is temporarily changed.
"""
from __future__ import annotations

import hashlib
from elftools.elf.elffile import ELFFile
import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
from vm9_request_caller import prepare_request_caller
from vm9_effects import require_effect_journal


class PrefixBoundary(Exception):
    pass


class RequestContinuationBoundary(Exception):
    def __init__(self, *, staged, frame, vm, ledger, decoded, cause):
        super().__init__(str(cause))
        self.staged, self.frame, self.vm = staged, frame, vm
        self.ledger, self.decoded, self.cause = ledger, decoded, cause


def resolve_request_memory_imports(pages, library, image):
    """Resolve matching ELF memory/exit imports to explicit PLT services.

    Derive PLT entries from this file's jump relocations, then bind matching
    ABS64/GLOB_DAT/JUMP_SLOT sites. This is loader input, not native output.
    The VM callback hooks implement the declared PLT services separately.
    """
    targets, relocations = {}, []
    with library.open('rb') as stream:
        elf = ELFFile(stream)
        plt = elf.get_section_by_name('.plt')
        jumps = elf.get_section_by_name('.rela.plt')
        if plt is None or jumps is None:
            raise RefillUnsupported('request ELF lacks the expected PLT relocations')
        symbols = elf.get_section(jumps['sh_link'])
        for index, relocation in enumerate(jumps.iter_relocations()):
            name = symbols.get_symbol(relocation['r_info_sym']).name
            if name in ('memset', 'memcpy', '__cxa_atexit'):
                targets[name] = image + plt['sh_addr'] + 32 + index * 16
        if targets != {'memset': image + 0x347F20, 'memcpy': image + 0x347F60,
                       '__cxa_atexit': image + 0x347EA0}:
            raise RefillUnsupported('request ELF memory import layout does not match this sample')
        for section in elf.iter_sections():
            if section['sh_type'] != 'SHT_RELA':
                continue
            symbols = elf.get_section(section['sh_link'])
            for relocation in section.iter_relocations():
                name = symbols.get_symbol(relocation['r_info_sym']).name
                if relocation['r_info_type'] in (257, 1025, 1026) and name in targets:
                    relocations.append((name, relocation['r_offset'],
                        targets[name] + relocation['r_addend'], relocation['r_info_type']))
    staged = _PageTransaction(pages)
    for name, offset, target, kind in relocations:
        _write_span(staged, image + offset, target.to_bytes(8, 'little'))
    staged.commit()
    return [dict(symbol=name, relocation_offset=hex(offset),
        target_offset=hex(target-image), relocation_kind=kind) for name, offset, target, kind in relocations]


def apply_request_configuration_set_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,thread_pointer,allocate,free,get_tls,
        initialize_registry,broadcast,max_nodes=4096,max_bytes=0x100000):
    """+285EF0/+2568C8: scoped u32 write; packed W0 at +28.

    The wrapper saves 16 bytes before entering the existing registry writer.
    Retain its defined canary and live key reads around provider effects.
    Known input/allocation/spill aliases reject; page rollback does not undo
    an external provider ledger or guest mapping effects.
    """
    import vm9_registry as registry
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('configuration setter requires an aligned guest stack')
    if type(max_nodes) is not int or not 1<=max_nodes<=4096:
        raise RefillUnsupported('configuration setter requires a bounded tree')
    if type(max_bytes) is not int or not 1<=max_bytes<=0x100000:
        raise RefillUnsupported('configuration setter requires a bounded key')
    if any(not callable(f) for f in (allocate,free,get_tls,initialize_registry,broadcast)):
        raise RefillUnsupported('configuration setter requires explicit writer services')
    def span(a,n):
        if type(a) is not int or not 0<a<=(1<<64)-n:
            raise RefillUnsupported('configuration setter address wraps uint64')
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('configuration setter aliases native spills')
    span(argument_block_address,32)
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,32)
    target,receiver,key=(int.from_bytes(packed[i:i+8],'little') for i in (0,8,16))
    if target!=image_base+0x2568C8:raise RefillUnsupported('unexpected configuration setter target')
    span(thread_pointer,0x30)
    fixed=((argument_block_address,32),(receiver,320),(key,24),(thread_pointer+0x28,8))
    for a,n in fixed:span(a,n);_read_span(p,a,n)
    if any(a<b+m and b<a+n for i,(a,n) in enumerate(fixed) for b,m in fixed[i+1:]):
        raise RefillUnsupported('configuration setter fixed inputs alias')
    live=[]
    def check_inputs(tx):
        if _read_span(tx,argument_block_address,32)!=packed:
            raise RefillUnsupported('configuration setter provider changed packed input')
        length=int.from_bytes(_read_span(tx,key+12,4),'little')
        if length>max_bytes:raise RefillUnsupported('configuration setter key exceeds byte bound')
        pointer=int.from_bytes(_read_span(tx,key+16,8),'little')
        if length:
            span(pointer,length);_read_span(tx,pointer,length)
            if any(pointer<a+n and a<pointer+length for a,n in fixed+tuple(live)):
                raise RefillUnsupported('configuration setter key aliases active storage')
        return ((pointer,length),) if length else ()
    check_inputs(p)
    def checked_allocate(tx,n):
        if type(n) is not int or not 1<=n<=0x100000:
            raise RefillUnsupported('configuration setter allocation exceeds byte bound')
        result=allocate(tx,n);payload=check_inputs(tx)
        if type(result) is not int or not 0<=result<=(1<<64)-n:
            raise RefillUnsupported('configuration setter allocator returned invalid address')
        if result:
            span(result,n);_read_span(tx,result,n)
            if any(result<a+m and a<result+n for a,m in fixed+tuple(live)+payload):
                raise RefillUnsupported('configuration setter allocation aliases active storage')
            live.append((result,n))
        return result
    def checked_free(tx,a):
        free(tx,a);live[:]=[(b,n) for b,n in live if b!=a];check_inputs(tx)
    canary=entry_stack_address-0x58
    _write_span(p,canary,_read_span(p,thread_pointer+0x28,8))
    result=registry.set_configuration_u32(p,registry_address=receiver,key_address=key,
        value=int.from_bytes(packed[24:28],'little'),entry_stack_address=entry_stack_address-16,
        image_base=image_base,allocate=checked_allocate,free=checked_free,get_tls=get_tls,
        initialize_registry=initialize_registry,broadcast=broadcast,max_nodes=max_nodes,max_bytes=max_bytes)
    check_inputs(p)
    if _read_span(p,canary,8)!=_read_span(p,thread_pointer+0x28,8):
        raise RefillUnsupported('configuration setter stack canary changed')
    _write_span(p,argument_block_address+28,result.to_bytes(4,'little'))
    p.commit();return result


def _execute_request_vm_impl(pages, inputs, vm_module, seconds, nanoseconds, *, allocate=None,
                   diagnostic_scope=None, reallocate=None, free=None, prepare_format=None,
                   read_clock=None, acquire_environment=None, invoke_jni=None,
                   get_singleton=None, get_tls=None, initialize_registry=None, broadcast=None,
                   register_exit=None, get_state_service=None, parse_decimal=None,
                   random_services=None, logger_services=None, jni_availability_services=None,
                   calloc=None, process_services=None, identifier_file_services=None,
                   mutex_import_bindings=None, format_number=None,
                   effect_journal=None):
    if format_number is not None and not callable(format_number):
        raise RefillUnsupported('request number formatter must be callable')
    if identifier_file_services is not None and (
            not isinstance(identifier_file_services,dict)
            or set(identifier_file_services)!={'fopen','fread','fclose'}
            or any(not callable(f) for f in identifier_file_services.values())):
        raise RefillUnsupported('request identifier requires explicit fopen/fread/fclose services')
    if mutex_import_bindings is not None and (
            not isinstance(mutex_import_bindings,dict)
            or set(mutex_import_bindings)!={'pthread_mutex_lock','pthread_mutex_unlock'}
            or any(type(a) is not int or not 0<a<1<<64 or a&3 for a in mutex_import_bindings.values())):
        raise RefillUnsupported('request mutex imports require explicit aligned lock/unlock bindings')
    if jni_availability_services is not None and (not isinstance(jni_availability_services,dict) or
            not callable(jni_availability_services.get('invoke_jni'))):
        raise RefillUnsupported('request JNI availability requires an explicit JNI service')
    staged = _PageTransaction(pages)
    frame = prepare_request_caller(staged, **inputs)
    image = inputs['image_base']
    ledger, decoded = [], []
    class StrictMem(vm_module.Mem):
        def __init__(self):
            self.pages = staged
        def _pg(self, address):
            if address >> 12 not in self.pages:
                raise RefillUnsupported(f'unmapped request prefix page {address:#x}')
            return self.pages[address >> 12]
    previous = vm_module.B
    try:
        vm_module.B = image
        vm = vm_module.VM(StrictMem(), frame.bytecode_offset,
            frame.packed_arguments_address, image + 0x35E230,
            image + 0x35E690, image + 0x28587C,
            inputs['return_address'], maxsteps=8000)
        vm.R = list(frame.registers)
        def callback(vm, function, argument):
            words = [vm.m.u64(argument + i * 8) for i in range(4)]
            wrapper, target = function - image, words[0] - image
            ledger.append((wrapper, target, argument, tuple(words)))
            if (wrapper, target) == (0x285888, 0x167E54):
                length = objects.decode_masked_bytes(vm.m.pages,
                    source_address=words[1], destination_address=words[2], mask_address=words[3])
                decoded.append((words[2], length))
            elif (wrapper, target) == (0x28589C, 0x291440):
                import vm9_callbacks
                provider = read_clock
                if provider is None:
                    provider = lambda _p, clock_id: (0, seconds, nanoseconds)
                value = vm9_callbacks.store_monotonic_start(vm.m.pages,
                    object_address=words[1], read_clock=provider)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('clock_stores', []).append(dict(
                        object_address=words[1], clock_id=1, stored_nanoseconds=value,
                        owning_clock_provider_used=read_clock is not None))
            elif allocate is not None and (wrapper, target) == (0x285FB4, 0x28DC38):
                if diagnostic_scope is None or free is None:
                    raise PrefixBoundary()
                import vm9_request_event
                import vm9_request_leaf_prefixes as leaf
                def event_observer(p, *, phase, **context):
                    diagnostic_scope.setdefault('request_event_prefixes', []).append(dict(
                        phase=phase, **context,
                        first_object_hex=_read_span(p, context['first_object_address'], 24).hex(),
                        second_object_hex=_read_span(p, context['second_object_address'], 24).hex(),
                        first_copy_hex=_read_span(p, context['first_copy_address'], 24).hex(),
                        formatter_target_offset='0x28ddd0',
                        supported_prefix_staged=True, body_transaction_committed=False,
                        native_input_snapshot_used=False))
                def event_leaf_observer(p, **context):
                    diagnostic_scope.setdefault('request_event_leaf_prefixes', []).append(dict(
                        **context, native_input_snapshot_used=False,
                        whole_callback_transaction_committed=False))
                def format_event(p, obj, x1, x2, x3, x4, mode):
                    return leaf.execute_event_formatter_prefix(p, image_base=image,
                        entry_stack_address=frame.native_stack_address - 0x270,
                        event_object_address=obj, argument_words=(x1, x2, x3, x4),
                        mode=mode, observer=event_leaf_observer, allocate=allocate, free=free)
                event_result = vm9_request_event.execute_request_event(vm.m.pages, image_base=image,
                    entry_stack_address=frame.native_stack_address - 0x180,
                    argument_words=(words[1], words[2], words[3], vm.m.u64(argument + 32)),
                    allocate=allocate, free=free, format_event=format_event, observer=event_observer)
                diagnostic_scope.setdefault('request_event_completed', []).append(dict(
                    wrapper_offset=hex(wrapper),target_offset=hex(target),
                    formatter_calls=event_result.formatter_calls,
                    emit_error_event=event_result.emit_error_event,
                    bounded_request_event_returned=True,callback_transaction_committed_to_request_stage=True))
            elif allocate is not None and (wrapper, target) == (0x285A80, 0x28BB5C):
                if diagnostic_scope is None or read_clock is None:
                    raise PrefixBoundary()
                import vm9_request_boolean_gate
                import vm9_request_leaf_prefixes as leaf
                def gate_observer(p, *, phase, **context):
                    diagnostic_scope.setdefault('request_boolean_prefixes', []).append(dict(
                        phase=phase, **context,
                        scope_hex=_read_span(p, context['scope_address'], 16).hex(),
                        evaluator_descriptor_hex=_read_span(p, context['evaluator_argument_address'], 16).hex(),
                        unresolved_leaf_target_offset='0x28b05c' if context['evaluator_needed'] else '0x28c09c',
                        supported_prefix_staged=True, body_transaction_committed=False,
                        native_input_snapshot_used=False))
                def evaluator_observer(p, **context):
                    diagnostic_scope.setdefault('request_evaluator_prefixes', []).append(dict(
                        **context, native_input_snapshot_used=False))
                def evaluate(p, descriptor, count, name):
                    return leaf.execute_stack_evaluator_prefix(p, image_base=image,
                        entry_stack_address=frame.native_stack_address - 0x290,
                        descriptor_address=descriptor, descriptor_count=count,
                        method_name_address=name, observer=evaluator_observer,
                        acquire_environment=acquire_environment,invoke_jni=invoke_jni,
                        get_singleton=get_singleton)
                def leave_boolean_scope(p, scope):
                    return leaf.leave_boolean_scope(p,image_base=image,
                        entry_stack_address=frame.native_stack_address-0x290,
                        scope_address=scope,read_clock=read_clock,allocate=allocate,free=free,
                        observer=lambda _p,**context:diagnostic_scope.setdefault('request_boolean_scopes',[]).append(context))
                vm9_request_boolean_gate.execute_boolean_gate(vm.m.pages,
                    object_address=words[1], image_base=image,
                    entry_stack_address=frame.native_stack_address - 0x190,
                    read_clock=read_clock, evaluate=evaluate, leave_scope=leave_boolean_scope,
                    observer=gate_observer)
            elif allocate is not None and (wrapper, target) == (0x285A80, 0x28C0EC):
                import vm9_request_leaf_prefixes as leaf
                leaf.execute_request_byte_gate(vm.m.pages, image_base=image,
                    object_address=words[1], observer=None if diagnostic_scope is None else
                    lambda _p, **context: diagnostic_scope.setdefault('request_byte_gates', []).append(context))
            elif allocate is not None and (wrapper, target) == (0x285AA0, 0x25CDD4):
                if diagnostic_scope is None or free is None or read_clock is None:
                    raise PrefixBoundary()
                import vm9_request_leaf_prefixes as leaf
                leaf.construct_request_object_with_null_reference(vm.m.pages, image_base=image,
                    entry_stack_address=frame.native_stack_address - 0x180,
                    object_address=words[1], kind=vm.m.u32(argument + 0x10),
                    source_string_address=words[3], mode=vm.m.u32(argument + 0x20),
                    flag=_read_span(vm.m.pages, argument + 0x24, 1)[0], thread_pointer=inputs['thread_pointer'],
                    thread_id=diagnostic_scope.get('thread_id'), allocate=allocate, free=free,
                    read_clock=read_clock, diagnostic_observer=lambda *event:
                    diagnostic_scope.setdefault('events', []).append(list(event)),
                    observer=lambda _p, **context: diagnostic_scope.setdefault('request_objects', []).append(context))
            elif allocate is not None and (wrapper, target) == (0x285ABC, 0x256AB0):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                import vm9_registry as registry
                previous_count = registry.increment_configuration_counter(vm.m.pages,
                    registry_address=words[1], key_address=words[2], image_base=image,
                    entry_stack_address=frame.native_stack_address - 0x190,
                    allocate=allocate, free=free, get_tls=get_tls,
                    initialize_registry=initialize_registry, broadcast=broadcast,
                    observer=lambda _p, **context: diagnostic_scope.setdefault('request_counters', []).append(context))
                _write_span(vm.m.pages, argument + 0x18, previous_count.to_bytes(4, 'little'))
            elif allocate is not None and (wrapper, target) == (0x285ADC, 0x25BF14):
                import vm9_registry as registry
                controller = registry.construct_configuration_tree(vm.m.pages,
                    container_address=words[1], descriptor_address=words[2],
                    image_base=image, allocate=allocate)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_trees', []).append(dict(
                        phase='request_tree_constructed', container_address=words[1],
                        controller_address=controller, body_transaction_committed=True))
            elif wrapper == 0x285AEC and target in (0x25C180, 0x25C188):
                import vm9_registry as registry
                pair = registry.configuration_tree_iterator(vm.m.pages,
                    container_address=words[1], image_base=image,
                    position='begin' if target == 0x25C180 else 'end')
                _write_span(vm.m.pages, argument + 0x10, b''.join(v.to_bytes(8, 'little') for v in pair))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_tree_iterators', []).append(dict(
                        position='begin' if target == 0x25C180 else 'end', packed_pair_written=True))
            elif (wrapper, target) == (0x285B08, 0x24C600):
                import vm9_registry as registry
                equal = registry.configuration_tree_iterators_equal(vm.m.pages,
                    first_address=words[1], second_address=words[2])
                _write_span(vm.m.pages, argument + 0x18, int(equal).to_bytes(4, 'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_iterator_comparisons', []).append(dict(equal=equal))
            elif (wrapper, target) == (0x285B7C, 0x347EA0):
                import vm9_callbacks as callbacks
                status = callbacks.register_process_destructor(vm.m.pages,
                    destructor_address=words[1], object_address=words[2],
                    dso_address=words[3], register_exit=register_exit)
                _write_span(vm.m.pages, argument + 0x20, status.to_bytes(4, 'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_process_registrations', []).append(dict(
                        status_u32=status, owning_exit_service_used=True))
            elif allocate is not None and (wrapper, target) == (0x285B9C, 0x248274):
                fill = _read_span(vm.m.pages, argument + 0x10, 1)[0]
                length = int.from_bytes(_read_span(vm.m.pages, argument + 0x14, 4), 'little')
                objects.construct_filled_string_object(vm.m.pages, object_address=words[1],
                    fill=fill, length=length, image_base=image, allocate=allocate)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_fill_strings', []).append(dict(
                        length_u32=length, fill_byte=fill))
            elif (wrapper, target) == (0x285BB0, 0x25C168):
                import vm9_registry as registry
                pointer = registry.lookup_configuration_value(vm.m.pages,
                    container_address=words[1], key_address=words[2], image_base=image)
                _write_span(vm.m.pages, argument + 0x18, pointer.to_bytes(8, 'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_tree_lookups', []).append(dict(
                        found=bool(pointer)))
            elif (wrapper, target) == (0x285C00, 0x27617C):
                import vm9_logger as logger
                length = len(logger.cstring(vm.m.pages, words[1]))
                _write_span(vm.m.pages, argument + 0x10, length.to_bytes(8, 'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_cstring_lengths', []).append(length)
            elif (wrapper, target) == (0x285C1C, 0x2765C4):
                result = objects.compare_folded_cstrings(vm.m.pages,
                    first_address=words[1], second_address=words[2], length=words[3],
                    entry_stack_address=frame.native_stack_address - 0x190,
                    image_base=image, get_singleton=get_singleton)
                _write_span(vm.m.pages, argument + 0x20, (result & 0xFFFFFFFF).to_bytes(4, 'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_folded_comparisons', []).append(result)
            elif (wrapper, target) == (0x285F44, 0x25C150):
                import vm9_registry as registry
                size = registry.configuration_tree_size(vm.m.pages, container_address=words[1])
                _write_span(vm.m.pages, argument + 0x10, size.to_bytes(8, 'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_tree_sizes', []).append(size)
            elif (wrapper, target) == (0x285B28, 0x24C59C):
                import vm9_registry as registry
                pair = registry.configuration_tree_iterator_pair(vm.m.pages, iterator_address=words[1])
                _write_span(vm.m.pages, argument + 0x10, pair.to_bytes(8, 'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_iterator_pairs', []).append(dict(nonzero=bool(pair)))
            elif allocate is not None and (wrapper, target) == (0x285B44, 0x2483E0):
                objects.clone_string_object(vm.m.pages, object_address=words[1],
                    source_object_address=words[2], image_base=image, allocate=allocate)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_iterator_string_clones', []).append(dict(
                        source_length_u32=vm.m.u32(words[2] + 12)))
            elif (wrapper, target) == (0x285B54, 0x24C5B8):
                import vm9_registry as registry
                pair = registry.advance_configuration_tree_iterator(vm.m.pages, iterator_address=words[1])
                _write_span(vm.m.pages, argument + 0x10, b''.join(v.to_bytes(8, 'little') for v in pair))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_iterator_advances', []).append(dict(returned_pair_written=True))
            elif (wrapper, target) == (0x285B70, 0x25C01C):
                import vm9_registry as registry
                if diagnostic_scope is not None:
                    diagnostic_scope['request_tree_cleanup_started'] = True
                registry.destroy_configuration_tree(vm.m.pages, container_address=words[1],
                    entry_stack_address=frame.native_stack_address - 0x180,
                    image_base=image, free=free)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_tree_cleanups', []).append(dict(completed=True))
            elif (wrapper, target) == (0x285B70, 0x25C12C):
                import vm9_registry as registry
                if diagnostic_scope is not None:
                    diagnostic_scope['request_tree_delete_started'] = True
                    diagnostic_scope['request_tree_delete_container_address'] = words[1]
                registry.delete_configuration_tree(vm.m.pages,container_address=words[1],
                    entry_stack_address=frame.native_stack_address - 0x180,image_base=image,free=free)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_tree_deletes', []).append(dict(completed=True))
            elif wrapper == 0x285910 and target in (0x32A264,0x347FA0):
                if not callable(free):
                    raise RefillUnsupported('request final free requires a free service')
                if diagnostic_scope is not None:
                    diagnostic_scope['request_final_free_started'] = True
                free(vm.m.pages,words[1])
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_final_frees', []).append(dict(completed=True))
            elif (wrapper, target) == (0x285F9C, 0x25CF98):
                import vm9_request_leaf_prefixes as leaf
                if diagnostic_scope is not None:
                    diagnostic_scope['request_object_cleanup_started'] = True
                leaf.destroy_request_object(vm.m.pages,object_address=words[1],image_base=image,
                    entry_stack_address=frame.native_stack_address - 0x180,
                    thread_pointer=inputs['thread_pointer'],allocate=allocate,free=free,
                    thread_id=None if diagnostic_scope is None else diagnostic_scope.get('thread_id'),
                    diagnostic_observer=None if diagnostic_scope is None else lambda *event:
                    diagnostic_scope.setdefault('events', []).append(list(event)),
                    observer=None if diagnostic_scope is None else lambda _p, **context:
                    diagnostic_scope.setdefault('request_object_cleanups', []).append(context))
            elif allocate is not None and (wrapper, target) == (0x285F60, 0x2914D0):
                if diagnostic_scope is None or read_clock is None:
                    raise PrefixBoundary()
                import vm9_callbacks
                value = vm9_callbacks.elapsed_monotonic_microseconds(vm.m.pages,
                    object_address=words[1], read_clock=read_clock)
                _write_span(vm.m.pages, argument + 16, (value & ((1 << 64) - 1)).to_bytes(8, 'little'))
                diagnostic_scope.setdefault('elapsed_clocks', []).append(dict(
                    object_address=words[1], clock_id=1, elapsed_microseconds=value,
                    owning_clock_provider_used=True))
            elif allocate is not None and (wrapper, target) == (0x2859EC, 0x172CA4):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                readers = vm.m.u32(words[1] + 0x88)
                pointer = objects.read_shared_state_pointer(vm.m.pages, object_address=words[1])
                _write_span(vm.m.pages, argument + 16, pointer.to_bytes(8, 'little'))
                diagnostic_scope.setdefault('shared_state_pointers', []).append(dict(
                    object_address=words[1], pointer=pointer, readers_before=readers,
                    readers_after=vm.m.u32(words[1] + 0x88),
                    pointer_field_offset='0x90', pointed_value_dereferenced=False))
            elif allocate is not None and (wrapper, target) == (0x2859E0, 0x32A330):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                objects.initialize_mutex_storage(vm.m.pages, storage_address=words[1])
                diagnostic_scope.setdefault('raw_mutex_states', []).append(dict(
                    storage_address=words[1], cleared_bytes=140,
                    outer_vtable_and_flag_written=False))
            elif (wrapper, target) == (0x2858A8, 0x347F60):
                _write_span(vm.m.pages, words[1], _read_span(vm.m.pages, words[2], words[3]))
            elif (wrapper, target) == (0x2858BC, 0x25C324):
                if allocate is None:
                    raise PrefixBoundary()
                import vm9_registry as registry
                if diagnostic_scope is not None:
                    diagnostic_scope['request_scoped_tree_started'] = True
                registry.construct_scoped_configuration_tree_reference(vm.m.pages,
                    output_reference_address=words[1],image_base=image,allocate=allocate,
                    entry_stack_address=frame.native_stack_address - 0x190,
                    thread_pointer=inputs['thread_pointer'],
                    thread_id=None if diagnostic_scope is None else diagnostic_scope.get('thread_id'),
                    diagnostic_observer=None if diagnostic_scope is None else lambda *event:
                    diagnostic_scope.setdefault('events', []).append(list(event)))
            elif allocate is not None and (wrapper, target) == (0x2858D0, 0x26C858):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                import vm9_diagnostics
                scope = vm9_diagnostics.enter_diagnostic_scope(vm.m.pages,
                    object_address=words[1], input_word=words[2], image_base=image,
                    thread_pointer=inputs['thread_pointer'],
                    thread_id=diagnostic_scope.get('thread_id'), allocate=allocate,
                    observer=lambda *event: diagnostic_scope.setdefault('events', []).append(list(event)))
                diagnostic_scope.setdefault('scopes', []).append(scope)
            elif allocate is not None and (wrapper, target) == (0x2858E0, 0x26C9D0):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                import vm9_diagnostics
                result = vm9_diagnostics.leave_diagnostic_scope(vm.m.pages,
                    object_address=words[1], image_base=image,
                    thread_pointer=inputs['thread_pointer'],
                    observer=lambda *event: diagnostic_scope.setdefault('events', []).append(list(event)))
                diagnostic_scope.setdefault('leaves', []).append(result)
            elif allocate is not None and (wrapper, target) == (0x285928, 0x32A1F0):
                pointer = allocate(vm.m.pages, words[1])
                _write_span(vm.m.pages, argument + 0x10, pointer.to_bytes(8, 'little'))
                diagnostic_scope.setdefault('allocation_callbacks', []).append([words[1], pointer])
            elif (wrapper,target) == (0x285B44,0x248EB4):
                result=objects.trim_string_object_left_set(vm.m.pages,
                    object_address=words[1],set_object_address=words[2],
                    entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,thread_pointer=inputs['thread_pointer'])
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_left_set_trims',[]).append(dict(
                        object_address=words[1],erase_status=result))
            elif (wrapper,target) == (0x285B44,0x248EF8):
                result=objects.trim_string_object_right_set(vm.m.pages,
                    object_address=words[1],set_object_address=words[2],
                    entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,thread_pointer=inputs['thread_pointer'])
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_right_set_trims',[]).append(dict(
                        object_address=words[1],last_remaining_index=result))
            elif (wrapper,target) == (0x285E98,0x2482EC):
                pointer=objects.construct_character_string_object(vm.m.pages,
                    object_address=words[1],value_u32=_read_span(vm.m.pages,argument+16,1)[0],
                    image_base=image,allocate=allocate)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_character_strings',[]).append(dict(
                        object_address=words[1],allocated_pointer=pointer))
            elif (wrapper,target) == (0x285C94,0x258D6C):
                result=objects.encode_string_object_base64(vm.m.pages,
                    source_object_address=words[1],object_address=words[2],
                    entry_stack_address=frame.native_stack_address-0x190,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    allocate=allocate,reallocate=reallocate,free=free)
                _write_span(vm.m.pages,argument+0x18,bytes([int(result)]))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_base64_encoded',[]).append(dict(
                        source_object_address=words[1],object_address=words[2],query_nonempty=result))
            elif (wrapper,target) == (0x285EF0,0x2568C8):
                value=apply_request_configuration_set_callback(vm.m.pages,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,thread_pointer=inputs['thread_pointer'],allocate=allocate,free=free,
                    get_tls=get_tls,initialize_registry=initialize_registry,broadcast=broadcast)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_configuration_sets',[]).append((argument,value))
            elif (wrapper,target) == (0x285F38,0x287474):
                import vm9_request_287474_vm
                nested=vm9_request_287474_vm.execute_request_287474_vm_prefix(vm.m.pages,
                    continue_caller_return=True,
                    vm_module=vm_module,consumer_services=dict(allocate=allocate,reallocate=reallocate,free=free,prepare_format=prepare_format,format_number=format_number,random_services=random_services,
                        process_services=process_services,identifier_file_services=identifier_file_services,
                        mutex_import_bindings=mutex_import_bindings,
                        get_singleton=get_singleton,
                        get_tls=get_tls,
                        read_clock=read_clock,
                        acquire_environment=acquire_environment,logger_services=logger_services,
                        jni_availability_services=jni_availability_services,invoke_jni=invoke_jni,
                        register_exit=register_exit,calloc=calloc,
                        thread_id=None if diagnostic_scope is None else diagnostic_scope.get('thread_id'),
                        diagnostic_observer=None if diagnostic_scope is None else lambda *event:
                            diagnostic_scope.setdefault('events',[]).append(event)),
                    maxsteps=500000,entry_stack_address=frame.native_stack_address-0x180,
                    return_address=image+0x16AA4C,thread_pointer=inputs['thread_pointer'],
                    image_base=image,object_address=words[1],effect_journal=effect_journal,
                    saved_frame_pointer=frame.native_stack_address-0x60,
                    saved_x28=frame.register_backing_address,saved_x19=frame.register_backing_address-8)
                if getattr(nested,'caller_return',None) is not None:
                    if diagnostic_scope is not None:
                        diagnostic_scope['request_287474_vm_boundary_state']=nested
                        diagnostic_scope.setdefault('request_287474_vm_returns',[]).append(dict(
                            nested_steps=nested.steps,nested_bytecode_offset=hex(nested.pc-image),
                            callback_count=len(nested.callbacks),caller_return=vars(nested.caller_return),
                            exit_state=nested.exit_state,whole_second_native_differential_verified=False))
                    return
                if diagnostic_scope is not None:
                    diagnostic_scope['request_287474_vm_boundary_state']=nested
                    diagnostic_scope.setdefault('request_287474_vm_prefixes',[]).append(dict(
                        nested_steps=nested.steps,nested_bytecode_offset=hex(nested.pc-image),
                        next_wrapper=hex(nested.callbacks[-1][0]),next_target=hex(nested.callbacks[-1][1]),
                        complete_second_VM_return_verified=False))
                raise RefillUnsupported('second request VM boundary +287474: '
                    f'+{nested.callbacks[-1][0]:#x} -> +{nested.callbacks[-1][1]:#x}')
            elif (wrapper,target) == (0x285F14,0x2828D4):
                from vm9_request_transform import apply_request_url_condition_callback
                result=apply_request_url_condition_callback(vm.m.pages,
                    argument_block_address=argument,image_base=image,
                    entry_stack_address=frame.native_stack_address-0x180)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_URL_conditions',[]).append(result)
            elif (wrapper,target) == (0x285EA8,0x287500):
                if random_services is None:
                    raise RefillUnsupported('nested request VM requires explicit random/time services')
                import vm9_request_token_vm
                nested=vm9_request_token_vm.execute_request_token_vm_prefix(vm.m.pages,
                    vm_module=vm_module,random_services=random_services,
                    continue_shared_readers=random_services.get('continue_shared_readers',False),
                    diagnostic_services=random_services.get('diagnostic_services'),
                    string_services=random_services.get('string_services'),
                    continue_caller_return=random_services.get('continue_token_return',False),
                    effect_journal=effect_journal,
                    entry_stack_address=frame.native_stack_address-0x180,
                    return_address=image+0x16AA4C,thread_pointer=inputs['thread_pointer'],
                    image_base=image,object_address=words[1],
                    saved_frame_pointer=frame.native_stack_address-0x60,
                    saved_x28=frame.register_backing_address,
                    saved_x19=frame.register_backing_address-8)
                if isinstance(nested,vm9_request_token_vm.RequestTokenVmReturn):
                    if diagnostic_scope is not None:
                        diagnostic_scope['request_nested_vm_return_state']=nested
                        diagnostic_scope.setdefault('request_nested_vm_returns',[]).append(dict(
                            nested_steps=nested.steps,nested_bytecode_offset=hex(nested.pc-image),
                            callback_count=len(nested.callbacks),caller_return=dict(vars(nested.caller_return)),
                            exit_state=nested.exit_state,whole_nested_native_differential_verified=False))
                else:
                    if diagnostic_scope is not None:
                        diagnostic_scope['request_nested_vm_boundary_state']=nested
                        diagnostic_scope.setdefault('request_nested_vm_prefixes',[]).append(dict(
                            nested_steps=nested.steps,nested_bytecode_offset=hex(nested.pc-image),
                            next_wrapper=hex(nested.callbacks[-1][0]),next_target=hex(nested.callbacks[-1][1]),
                            complete_nested_caller_return_verified=False))
                    raise RefillUnsupported('nested request VM boundary +287500: '
                        f'+{nested.callbacks[-1][0]:#x} -> +{nested.callbacks[-1][1]:#x}')
            elif (wrapper,target) == (0x285E8C,0x287168):
                import vm9_request_transform
                result=vm9_request_transform.construct_request_metadata(vm.m.pages,
                    object_address=words[1],image_base=image,allocate=allocate)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_metadata',[]).append(dict(
                        object_address=words[1],second_printf_uint32_return=result,
                        metadata_helper_returned=True))
            elif (wrapper,target) == (0x285E80,0x2869F0):
                if (allocate is None or reallocate is None or free is None
                        or get_singleton is None or parse_decimal is None):
                    raise RefillUnsupported('request suffix requires its ownership and atoi services')
                import vm9_request_transform
                outputs=vm9_request_transform.construct_request_suffix(vm.m.pages,
                    object_address=words[1],entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,thread_pointer=inputs['thread_pointer'],allocate=allocate,
                    reallocate=reallocate,free=free,
                    get_singleton=lambda p:get_singleton(p,frame.native_stack_address-0x570),
                    parse_decimal=parse_decimal,
                    thread_id=None if diagnostic_scope is None else diagnostic_scope.get('thread_id'),
                    diagnostic_observer=None if diagnostic_scope is None else lambda *event:
                        diagnostic_scope.setdefault('events',[]).append(list(event)))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_suffixes',[]).append(dict(
                        object_address=words[1],output_pointer_addresses=list(outputs),
                        outer_suffix_returned=True))
            elif (wrapper,target) == (0x285E70,0x27ED70):
                if get_tls is None:
                    raise RefillUnsupported('request TLS word setter requires its owning TLS service')
                pointer=get_tls(vm.m.pages,image+0x382920)
                value=words[2]&0xFFFFFFFF
                _write_span(vm.m.pages,pointer,value.to_bytes(4,'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_TLS_stores',[]).append(value)
            elif (wrapper,target) == (0x285E54,0x2850A8):
                if get_tls is None:
                    raise RefillUnsupported('request TLS word getter requires its owning TLS service')
                pointer=get_tls(vm.m.pages,image+0x382920)
                value=int.from_bytes(_read_span(vm.m.pages,pointer,4),'little')
                _write_span(vm.m.pages,argument+0x10,value.to_bytes(4,'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_TLS_words',[]).append(value)
            elif (wrapper,target) == (0x285E38,0x258BE0):
                value=objects.hash_string_object64(vm.m.pages,
                    object_address=words[1],image_base=image)
                _write_span(vm.m.pages,argument+0x10,value.to_bytes(8,'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_string_hash64',[]).append(value)
            elif (wrapper,target) == (0x285E14,0x2633A4):
                if allocate is None:
                    raise RefillUnsupported('request contained reference copy requires its diagnostic allocator')
                import vm9_reference_scopes
                vm9_reference_scopes.copy_scoped_string_reference(vm.m.pages,
                    destination_address=words[1],source_address=words[2]+0x18,
                    entry_stack_address=frame.native_stack_address-0x190,image_base=image,
                    thread_pointer=inputs['thread_pointer'],allocate=allocate,
                    thread_id=None if diagnostic_scope is None else diagnostic_scope.get('thread_id'),
                    diagnostic_observer=None if diagnostic_scope is None else lambda *event:
                        diagnostic_scope.setdefault('events',[]).append(list(event)))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('contained_reference_copies',[]).append(dict(
                        destination_address=words[1],source_address=words[2]+0x18))
            elif (wrapper,target) == (0x285D80,0x26BF90):
                if read_clock is None:
                    raise RefillUnsupported('request elapsed getter requires an explicit clock provider')
                import vm9_state
                value=vm9_state.read_request_elapsed_seconds(vm.m.pages,
                    object_address=words[1],read_clock=read_clock)
                _write_span(vm.m.pages,argument+0x10,value.to_bytes(8,'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_elapsed_seconds',[]).append(value)
            elif (wrapper,target) == (0x285D74,0x26BDFC):
                if (diagnostic_scope is None or get_state_service is None or allocate is None
                        or free is None or get_tls is None or initialize_registry is None or broadcast is None):
                    raise RefillUnsupported('request state constructor requires its explicit state service and ownership providers')
                import vm9_state
                value=vm9_state.construct_request_clock_state(vm.m.pages,object_address=words[1],
                    entry_stack_address=frame.native_stack_address-0x180,image_base=image,
                    get_state_service=get_state_service,allocate=allocate,free=free,get_tls=get_tls,
                    initialize_registry=initialize_registry,broadcast=broadcast)
                diagnostic_scope.setdefault('request_clock_states',[]).append(dict(object_address=words[1],signed_state_word=value))
            elif allocate is not None and (wrapper, target) == (0x28591C, 0x2481AC):
                import vm9_objects
                vm9_objects.construct_string_object(vm.m.pages, object_address=words[1],
                    source_address=0, allocate=allocate,
                    vtable_address=image + 0x34F5F8,
                    empty_descriptor_address=image + 0x6E168)
                diagnostic_scope.setdefault('string_callbacks', []).append(words[1])
            elif allocate is not None and (wrapper, target) == (0x2859CC, 0x347F20):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                fill, size = words[2] & 255, words[3]
                if size > 0x100000:
                    raise RefillUnsupported('request memset exceeds the explicit bound')
                _write_span(vm.m.pages, words[1], bytes([fill]) * size)
                diagnostic_scope.setdefault('memory_fills', []).append(dict(
                    destination_address=words[1], value=fill, length=size))
            elif allocate is not None and (wrapper, target) == (0x2859B8, 0x25BF3C):
                if diagnostic_scope is None or free is None:
                    raise PrefixBoundary()
                import vm9_registry
                pair = vm9_registry.insert_configuration_pair(vm.m.pages,
                    container_address=words[1], key_address=words[2], value_address=words[3],
                    image_base=image, allocate=allocate, free=free)
                diagnostic_scope.setdefault('configuration_insertions', []).append(dict(
                    container_address=words[1], key_address=words[2],
                    value_address=words[3], pair_address=pair))
            elif allocate is not None and (wrapper, target) == (0x2859A8, 0x248344):
                objects.construct_string_object(vm.m.pages, object_address=words[1],
                    source_address=words[2], allocate=allocate,
                    vtable_address=image + 0x34F5F8,
                    empty_descriptor_address=image + 0x6E168)
                diagnostic_scope.setdefault('cstring_constructors', []).append(dict(
                    object_address=words[1], source_address=words[2],
                    declared_length=vm.m.u32(words[1] + 12), native_input_snapshot_used=False))
            elif allocate is not None and (wrapper, target) == (0x285CB8, 0x248D3C):
                start = int.from_bytes(_read_span(vm.m.pages, argument + 24, 4), 'little')
                count = int.from_bytes(_read_span(vm.m.pages, argument + 28, 4), 'little')
                objects.construct_substring_string_object(vm.m.pages,
                    object_address=words[1], source_object_address=words[2],
                    start_u32=start, count_u32=count, image_base=image,
                    entry_stack_address=frame.native_stack_address - 0x190,
                    thread_pointer=inputs['thread_pointer'], allocate=allocate)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_substrings', []).append(dict(
                        start_u32=start, count_u32=count, output_object_address=words[1]))
            elif allocate is not None and (wrapper, target) == (0x285CD8, 0x248F5C):
                if reallocate is None or free is None:
                    raise PrefixBoundary()
                status = objects.construct_cstring_string_object(vm.m.pages,
                    object_address=words[1], first_cstring_address=words[2],
                    second_object_address=words[3], image_base=image,
                    entry_stack_address=frame.native_stack_address - 0x190,
                    thread_pointer=inputs['thread_pointer'], allocate=allocate,
                    reallocate=reallocate, free=free)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_string_combinations', []).append(dict(
                        output_object_address=words[1], append_status=status))
            elif allocate is not None and (wrapper, target) == (0x285CF4, 0x2487B4):
                if reallocate is None or free is None:
                    raise PrefixBoundary()
                objects.construct_string_object_cstring(vm.m.pages,
                    object_address=words[1], first_object_address=words[2],
                    second_cstring_address=words[3], image_base=image,
                    entry_stack_address=frame.native_stack_address - 0x190,
                    allocate=allocate, reallocate=reallocate, free=free)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_object_cstrings', []).append(dict(
                        output_object_address=words[1]))
            elif (wrapper, target) == (0x285D10, 0x248C54):
                start = int.from_bytes(_read_span(vm.m.pages, argument + 24, 4), 'little')
                value = objects.find_string_object_ascii_case_insensitive(vm.m.pages,
                    object_address=words[1], pattern_object_address=words[2], start_u32=start,
                    entry_stack_address=frame.native_stack_address - 0x190)
                _write_span(vm.m.pages, argument + 28, value.to_bytes(4, 'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_casefold_searches', []).append(dict(
                        start_u32=start, result_u32=value))
            elif (wrapper, target) == (0x285D34, 0x248B24):
                start = int.from_bytes(_read_span(vm.m.pages, argument + 24, 4), 'little')
                value = objects.find_string_object_cstring(vm.m.pages,
                    object_address=words[1], pattern_address=words[2], start_u32=start,
                    entry_stack_address=frame.native_stack_address - 0x190)
                _write_span(vm.m.pages, argument + 28, value.to_bytes(4, 'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_cstring_searches', []).append(dict(
                        start_u32=start, result_u32=value))
            elif (wrapper, target) == (0x285C94, 0x2487E8):
                import vm9_configuration_init as configuration
                if any(not v or v > (1 << 64) - 24 for v in words[1:3]):
                    raise RefillUnsupported('binary equality request objects require mapped uint64 fields')
                equal = configuration.strings_equal(vm.m.pages,
                    first_object=words[1], second_object=words[2])
                _write_span(vm.m.pages, argument + 24, bytes([int(equal)]))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_binary_equalities', []).append(dict(equal=equal))
            elif allocate is not None and (wrapper, target) == (0x285C80, 0x2481FC):
                length = int.from_bytes(_read_span(vm.m.pages, argument + 24, 4), 'little')
                pointer = objects.construct_sized_string_object(vm.m.pages,
                    object_address=words[1], source_address=words[2], length=length,
                    image_base=image, allocate=allocate)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_sized_strings', []).append(dict(
                        object_address=words[1], length_u32=length, buffer_address=pointer))
            elif (wrapper, target) == (0x285C5C, 0x248C1C):
                value = objects.find_string_object_byte(vm.m.pages,
                    object_address=words[1], target_byte=_read_span(vm.m.pages, argument + 16, 1)[0],
                    start_u32=int.from_bytes(_read_span(vm.m.pages, argument + 20, 4), 'little'))
                _write_span(vm.m.pages, argument + 24, value.to_bytes(4, 'little'))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_byte_searches', []).append(dict(
                        object_address=words[1], result_u32=value, declared_length_used=True))
            elif (wrapper, target) == (0x285C3C, 0x282A68):
                value = objects.read_signer_request_flag(vm.m.pages, object_address=words[1])
                _write_span(vm.m.pages, argument + 16, bytes([value & 1]))
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('request_flag_reads', []).append(dict(
                        object_address=words[1], returned_byte=value, packed_boolean=value & 1))
            elif (wrapper, target) in ((0x28591C, 0x248F4C), (0x28591C, 0x248F54)):
                value = objects.transform_string_fields_ascii_case(vm.m.pages,
                    fields_address=(words[1] + 8) & ((1 << 64) - 1),
                    uppercase=target == 0x248F4C)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('ascii_string_conversions', []).append(dict(
                        object_address=words[1], uppercase=target == 0x248F4C,
                        returned_u32=value, declared_length_used=True))
            elif allocate is not None and (wrapper, target) == (0x28591C, 0x2484B8):
                if free is None or diagnostic_scope is None:
                    raise PrefixBoundary()
                pointer = vm.m.u64(words[1] + 16)
                objects.destroy_string_object(vm.m.pages, object_address=words[1],
                    image_base=image, free=free)
                diagnostic_scope.setdefault('string_cleanups', []).append(dict(
                    object_address=words[1], released_payload=pointer))
            elif allocate is not None and (wrapper, target) == (0x28596C, 0x32D4F8):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                import vm9_startup
                before = _read_span(vm.m.pages, words[1], 8)
                vm9_startup.release_serial_guard(vm.m.pages,
                    guard_address=words[1], image_base=image)
                diagnostic_scope.setdefault('guard_releases', []).append(dict(
                    guard_address=words[1], guard_before_hex=before.hex(),
                    guard_after_hex=_read_span(vm.m.pages, words[1], 8).hex(),
                    broadcast_executed=False))
            elif allocate is not None and (wrapper, target) == (0x285944, 0x32D3A0):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                import vm9_startup
                before = _read_span(vm.m.pages, words[1], 8)
                acquired = vm9_startup.acquire_serial_guard(vm.m.pages,
                    guard_address=words[1], image_base=image,
                    thread_id=diagnostic_scope.get('thread_id'))
                _write_span(vm.m.pages, argument + 16, int(acquired).to_bytes(4, 'little'))
                diagnostic_scope.setdefault('guard_acquires', []).append(dict(
                    guard_address=words[1], acquired=acquired,
                    guard_before_hex=before.hex(),
                    guard_after_hex=_read_span(vm.m.pages, words[1], 8).hex()))
            elif allocate is not None and (wrapper, target) == (0x2858EC, 0x24880C):
                import vm9_configuration_init
                equal = vm9_configuration_init.string_equals_cstring(vm.m.pages,
                    object_address=words[1], cstring_address=words[2])
                # +0x285900 AND W8,W0,#1 and STRB at argument+0x18.
                _write_span(vm.m.pages, argument + 0x18, bytes([int(equal)]))
                diagnostic_scope.setdefault('string_comparisons', []).append(dict(
                    object_address=words[1], cstring_address=words[2], equal=equal,
                    argument_address=argument))
            elif allocate is not None and (wrapper, target) == (0x285990, 0x248908):
                if diagnostic_scope is None or reallocate is None or free is None:
                    raise PrefixBoundary()
                import vm9_configuration_init
                string_word = vm.m.u64(argument + 0x20)
                result = vm9_configuration_init.format_string_object(vm.m.pages,
                    object_address=words[1], format_address=words[2],
                    argument_addresses=(words[3] & 0xFFFFFFFF, string_word, words[0]),
                    image_base=image, allocate=allocate, reallocate=reallocate,
                    free=free, prepare_format=prepare_format)
                length = vm.m.u32(result + 12)
                pointer = vm.m.u64(result + 16)
                payload = _read_span(vm.m.pages, pointer, length) if pointer else b''
                diagnostic_scope.setdefault('formatted_strings', []).append(dict(
                    object_address=result, format_address=words[2],
                    signed_int32=objects._s32(words[3] & 0xFFFFFFFF),
                    string_argument_address=string_word, declared_length=length,
                    payload_sha256=hashlib.sha256(payload).hexdigest(),
                    format_bytes_hex=objects._cstring(vm.m.pages, words[2], 4096)[:-1].hex(),
                    native_input_snapshot_used=False))
            elif allocate is not None and (wrapper, target) == (0x285978, 0x256ED4):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                from vm9_request_nested_callbacks import (execute_nested_string_getter,
                    nested_getter_inputs_from_request)
                nested_inputs = nested_getter_inputs_from_request(vm.m.pages,
                    request_frame=frame, callback_argument_address=argument,
                    thread_pointer=inputs['thread_pointer'], image_base=image)
                result = execute_nested_string_getter(vm.m.pages, nested_inputs,
                    vm_module, allocate=allocate)
                output = result['output_address']
                source_length = result['declared_length']
                output_pointer = int.from_bytes(_read_span(vm.m.pages, output + 16, 8), 'little')
                source_pointer = int.from_bytes(_read_span(vm.m.pages, result['source_address'] + 16, 8), 'little')
                if source_length < 0x80000000 and output_pointer:
                    source_bytes = _read_span(vm.m.pages, source_pointer, source_length)
                    output_bytes = _read_span(vm.m.pages, output_pointer, source_length)
                    if source_bytes != output_bytes or _read_span(vm.m.pages, output_pointer + source_length, 1) != b'\0':
                        raise RefillUnsupported('nested getter output does not match its owning receiver')
                    payload_digest = hashlib.sha256(output_bytes).hexdigest()
                else:
                    payload_digest = None
                diagnostic_scope.setdefault('nested_getters', []).append(dict(
                    caller_inputs=nested_inputs,
                    source_address=result['source_address'], output_address=output,
                    declared_length=result['declared_length'], vm_steps=result['vm_steps'],
                    vm_exit_pc=result['vm_exit_pc'],
                    callbacks=[dict(kind=c['kind'], wrapper=c['wrapper_offset'],
                        target=c['target_offset'], words=list(c['words'])) for c in result['callbacks']],
                    output_bytes=list(_read_span(vm.m.pages, output, 24)),
                    payload_sha256=payload_digest, output_matches_receiver=payload_digest is not None,
                    acquire_reader_count=result['callbacks'][0]['reader_count'],
                    released_reader_count=result['callbacks'][2]['reader_count'],
                    source_state_injected=False, native_input_snapshot_used=False,
                    python_full_native_caller_abi_modeled=False))
            else:
                if not words[0]:
                    raise RefillUnsupported(f'NULL request callback target at wrapper +{wrapper:#x}')
                raise RefillUnsupported(f'unknown request callback +{wrapper:#x} -> +{target:#x}')
        vm.native_hook = callback
        try:
            vm.run()
        except PrefixBoundary:
            return staged, frame, vm, ledger, decoded
        except vm_module.VMExit:
            from vm9_request_caller import validate_request_vm_exit
            if diagnostic_scope is None:
                raise RefillUnsupported('request VM completion requires its owning diagnostic context')
            result = validate_request_vm_exit(staged,image_base=image,pc=vm.pc,
                registers=tuple(vm.R),return_address=inputs['return_address'])
            from vm9_request_caller import finish_request_caller
            try:
                caller_return = finish_request_caller(staged,image_base=image,
                    entry_stack_address=inputs['entry_stack_address'],
                    thread_pointer=inputs['thread_pointer'],callback_sentinel=vm.cb)
            except RefillUnsupported as exc:
                raise RequestContinuationBoundary(staged=staged,frame=frame,vm=vm,
                    ledger=ledger,decoded=decoded,cause=exc) from exc
            result['physical_native_caller_epilogue_modeled'] = True
            result['caller_native_return'] = dict(vars(caller_return))
            result.update(vm_steps=vm.steps,callback_count=len(ledger),
                all_dispatched_callback_models_returned=True,
                whole_native_request_equivalence_verified=False,
                request_transaction_committed_to_supplied_pages=True)
            staged.commit()
            diagnostic_scope['request_vm_return'] = result
            return staged, frame, vm, ledger, decoded
        except Exception as exc:
            if diagnostic_scope is not None:
                raise RequestContinuationBoundary(staged=staged, frame=frame, vm=vm,
                    ledger=ledger, decoded=decoded, cause=exc) from exc
            print("prefix failed at",vm.steps,hex(vm.pc-image),flush=True)
            raise
        raise AssertionError('request prefix did not reach the allocation boundary')
    finally:
        vm_module.B = previous


def execute_request_vm(pages, inputs, vm_module, seconds, nanoseconds, *,
        effect_journal=None, **services):
    """Run the request VM with optional provider-side failure rollback.

    Guest pages are always staged by ``_PageTransaction``.  When an explicit
    effect journal is supplied, providers may register inverse allocator, OS
    or JNI operations; an exception rolls those effects back to this request
    checkpoint.  Successful prefixes and completed returns keep their effects
    inside an enclosing ``journal.transaction()``; without that outer scope a
    direct call commits and discards its local undo records.
    """
    effect_journal = require_effect_journal(effect_journal)
    if effect_journal is None:
        return _execute_request_vm_impl(pages, inputs, vm_module, seconds,
            nanoseconds, effect_journal=effect_journal, **services)
    with effect_journal.transaction():
        return _execute_request_vm_impl(pages, inputs, vm_module, seconds,
            nanoseconds, effect_journal=effect_journal, **services)


def invoke_request_vm_callback(pages, target, *, image_base, thread_pointer,
        return_address, vm_module, seconds, nanoseconds, entry_stack_address,
        url_reference_address, header_reference_address, mode, context_address,
        output_reference_address, diagnostic_scope=None, allocate=None,
        free=None, effect_journal=None, **services):
    """Dispatch callback +2830c4 using URL/header/W-mode/context/X8 ABI.

    A diagnostic prefix is insufficient for an owning request. Only a fresh
    VM exit and validated caller return publish the staged pages. External
    service effects are outside the historical page rollback unless an
    explicit ``effect_journal`` is supplied.
    """
    words = (target, image_base, thread_pointer, return_address,
        entry_stack_address, url_reference_address, header_reference_address,
        mode, context_address, output_reference_address)
    if any(type(v) is not int or not 0 <= v < 1 << 64 for v in words):
        raise RefillUnsupported('request VM callback ABI words must fit uint64')
    if target != image_base + 0x2830C4:
        raise RefillUnsupported('unrecovered request VM callback target')
    if not isinstance(diagnostic_scope, dict) or not callable(allocate) or not callable(free):
        raise RefillUnsupported('owning request VM requires diagnostics and allocation/free services')
    p = _PageTransaction(pages)
    try:
        _read_span(p, output_reference_address, 16)
    except ValueError as exc:
        raise RefillUnsupported('owning request VM requires a mapped output reference') from exc
    diagnostic = dict(diagnostic_scope)
    diagnostic.pop('request_vm_return', None)
    inputs = dict(image_base=image_base, thread_pointer=thread_pointer,
        return_address=return_address, entry_stack_address=entry_stack_address,
        argument_x0=url_reference_address, argument_x1=header_reference_address,
        argument_x2=mode & 0xFFFFFFFF, argument_x3=context_address,
        output_x8=output_reference_address)
    result = execute_request_vm(p, inputs, vm_module, seconds, nanoseconds,
        allocate=allocate, free=free, diagnostic_scope=diagnostic,
        effect_journal=effect_journal, **services)
    completed = diagnostic.get('request_vm_return', {})
    if not all(completed.get(key) is True for key in (
            'caller_sentinel_matches', 'physical_native_caller_epilogue_modeled',
            'all_dispatched_callback_models_returned',
            'request_transaction_committed_to_supplied_pages')):
        raise RefillUnsupported('owning request VM stopped before a completed caller return')
    _read_span(p, output_reference_address, 16)
    p.commit()
    diagnostic_scope.update(diagnostic)
    return result


def invoke_java_request_service(pages, target, *, image_base, thread_pointer,
        thread_id, return_address, vm_module, seconds, nanoseconds,
        receiver_address, url_reference_address, header_reference_address,
        mode, output_reference_address, entry_stack_address, allocate=None,
        free=None, diagnostic_scope=None, diagnostic_observer=None,
        effect_journal=None,
        max_callbacks=4096, max_nodes=4096, **services):
    """Normal Java facade provider: child +27dd04 -> owning callback VM.

    Bind image/thread/interpreter/clock and explicit VM services with partial,
    then pass the result as invoke_request to invoke_java_request_facade.
    The handler's virtual+20 (+284f98) is a different, unsupported entry.
    """
    if (type(image_base) is not int or not 0 <= image_base < 1 << 64
            or type(target) is not int or target != image_base + 0x27DD04):
        raise RefillUnsupported('Java request service requires child dispatcher +27dd04')
    if not isinstance(diagnostic_scope, dict) or not callable(allocate) or not callable(free):
        raise RefillUnsupported('Java request service requires diagnostics and allocation/free services')
    import vm9_request_dispatch as dispatch

    def callback(p, callback_target, **abi):
        return invoke_request_vm_callback(p, callback_target, image_base=image_base,
            thread_pointer=thread_pointer, return_address=return_address,
            vm_module=vm_module, seconds=seconds, nanoseconds=nanoseconds,
            allocate=allocate, free=free, diagnostic_scope=diagnostic_scope,
            effect_journal=effect_journal, **abi, **services)

    return dispatch.invoke_signer_child_request(pages, image_base=image_base,
        thread_pointer=thread_pointer, thread_id=thread_id,
        receiver_address=receiver_address, url_reference_address=url_reference_address,
        header_reference_address=header_reference_address, mode=mode,
        output_reference_address=output_reference_address,
        entry_stack_address=entry_stack_address, allocate=allocate, free=free,
        invoke_callback=callback, diagnostic_observer=diagnostic_observer,
        max_callbacks=max_callbacks, max_nodes=max_nodes,
        effect_journal=effect_journal)


def invoke_java_request_facade_service(pages, target, *, image_base,
        entry_stack_address, thread_pointer, thread_id, environment_pointer,
        facade_address, url_reference, header_array_reference, return_address,
        vm_module, seconds, nanoseconds, allocate=None, calloc=None, free=None,
        invoke_jni=None, diagnostic_scope=None, diagnostic_observer=None,
        acquire_environment=None, wake_condition=None, lock_mutex=None,
        unlock_mutex=None, effect_journal=None, max_pairs=4096,
        max_bytes=0x100000, max_callbacks=4096, max_nodes=4096, **services):
    """Bind the normal Java facade (+17b8f8) to the owning request service.

    This is the production composition boundary for a Java request.  The
    facade owns JNI URL/header conversion and Java output cleanup; the child
    dispatcher owns callback/fallback selection; ``invoke_java_request_service``
    binds child ``+27dd04`` to the owning request VM ``+2830c4``.  All three
    layers receive the same page transaction and optional provider-effect
    journal, so a failed nested request cannot publish staged pages or leave
    an unpaired provider effect at this boundary.
    """
    if (type(image_base) is not int or type(target) is not int
            or target != image_base + 0x17B8F8):
        raise RefillUnsupported('Java facade service requires normal +17b8f8 entry')
    if not isinstance(diagnostic_scope, dict):
        raise RefillUnsupported('Java facade service requires a diagnostic scope')
    if any(not callable(f) for f in (allocate, calloc, free, invoke_jni)):
        raise RefillUnsupported('Java facade service requires allocation/calloc/free/JNI services')
    import vm9_jni_request as facade

    def invoke_request(p, child_target, **abi):
        return invoke_java_request_service(p, child_target,
            image_base=image_base, thread_pointer=thread_pointer,
            thread_id=thread_id, return_address=return_address,
            vm_module=vm_module, seconds=seconds, nanoseconds=nanoseconds,
            allocate=allocate, free=free, diagnostic_scope=diagnostic_scope,
            diagnostic_observer=diagnostic_observer,
            acquire_environment=acquire_environment, invoke_jni=invoke_jni,
            effect_journal=effect_journal, max_callbacks=max_callbacks,
            max_nodes=max_nodes, **abi, **services)

    effect_journal = require_effect_journal(effect_journal)
    def run():
        return facade.invoke_java_request_facade(pages,
            image_base=image_base, entry_stack_address=entry_stack_address,
            thread_pointer=thread_pointer, thread_id=thread_id,
            environment_pointer=environment_pointer,
            facade_address=facade_address, url_reference=url_reference,
            header_array_reference=header_array_reference, allocate=allocate,
            calloc=calloc, free=free, invoke_jni=invoke_jni,
            invoke_request=invoke_request,
            diagnostic_observer=diagnostic_observer,
            acquire_environment=acquire_environment,
            wake_condition=wake_condition, lock_mutex=lock_mutex,
            unlock_mutex=unlock_mutex, max_pairs=max_pairs,
            max_bytes=max_bytes)
    if effect_journal is None:
        return run()
    with effect_journal.transaction():
        return run()


