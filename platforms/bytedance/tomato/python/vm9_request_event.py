"""+0x28dc38/28dc40 request event wrappers with explicit formatter boundary."""
from __future__ import annotations
from dataclasses import dataclass
import vm9_objects as objects
from vm9_cpp_strings import construct_cpp_string, clone_cpp_string, destroy_cpp_string, move_assign_cpp_string
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span


@dataclass(frozen=True)
class RequestEventResult:
    first_object_address: int
    second_object_address: int
    formatter_calls: int
    emit_error_event: bool


def execute_request_event(pages, *, image_base, entry_stack_address,
        argument_words, emit_error_event=0, allocate, free, format_event=None, observer=None):
    """Construct/copy/destroy C++ strings in native order.

    format_event(pages, cpp_string_address, x1,x2,x3,x4,w5) supplies +0x28ddd0.
    Missing formatter rejects at the real call and leaves caller pages unchanged.
    Observers may record the proven staged prefix without committing it.
    """
    if (not isinstance(entry_stack_address, int) or entry_stack_address < 0xF0
            or entry_stack_address & 15):
        raise RefillUnsupported('request event stack must be aligned')
    if len(argument_words) != 4 or any(not isinstance(w, int) or not 0 <= w < 1 << 64 for w in argument_words):
        raise RefillUnsupported('request event requires four uint64 ABI words')
    if not isinstance(emit_error_event, int) or not 0 <= emit_error_event < 1 << 32:
        raise RefillUnsupported('request event mode must fit uint32')
    p = _PageTransaction(pages)
    globals_ledger = []
    for source, mask, destination, flag in ((0x11F0C0, 0x11F2E0, 0x3E1990, 0x3E19A4),
            (0x11F0E0, 0x11F2C0, 0x3E19B0, 0x3E19C4)):
        before = int.from_bytes(_read_span(p, image_base + flag, 4), 'little')
        length = None
        if before == 0:
            length = objects.decode_masked_bytes(p, source_address=image_base + source,
                destination_address=image_base + destination, mask_address=image_base + mask)
            _write_span(p, image_base + flag, (1).to_bytes(4, 'little'))
        globals_ledger.append(dict(flag_address=image_base + flag, flag_before=before,
            decode_performed=before == 0, decoded_length=length))
    first, second, first_copy, second_copy = (entry_stack_address - n for n in (0x90, 0xB0, 0xD0, 0xF0))
    construct_cpp_string(p, object_address=first, source_address=image_base + 0x3E1990, allocate=allocate)
    construct_cpp_string(p, object_address=second, source_address=image_base + 0x3E19B0, allocate=allocate)
    clone_cpp_string(p, object_address=first_copy, source_object_address=first, allocate=allocate)
    context = dict(globals=globals_ledger, first_object_address=first,
        second_object_address=second, first_copy_address=first_copy,
        second_copy_address=second_copy, argument_words=list(argument_words),
        emit_error_event=emit_error_event)
    if observer:
        observer(p, phase='before_first_formatter', **context)
    if format_event is None:
        raise RefillUnsupported('request event formatter +0x28ddd0 is not recovered')
    format_event(p, first_copy, *argument_words, emit_error_event)
    destroy_cpp_string(p, object_address=first_copy, free=free)
    calls = 1
    if emit_error_event:
        clone_cpp_string(p, object_address=second_copy, source_object_address=second, allocate=allocate)
        if observer:
            observer(p, phase='before_second_formatter', **context)
        format_event(p, second_copy, *argument_words, emit_error_event)
        destroy_cpp_string(p, object_address=second_copy, free=free)
        calls += 1
    destroy_cpp_string(p, object_address=second, free=free)
    destroy_cpp_string(p, object_address=first, free=free)
    p.commit()
    return RequestEventResult(first, second, calls, bool(emit_error_event))


@dataclass(frozen=True)
class EventEmissionResult:
    logger_address: int
    appended: bool
    dropped: bool
    record_address: int | None
    record_count: int


def _word(p, address):
    return int.from_bytes(_read_span(p,address,8),'little')


def _store_word(p, address, value):
    _write_span(p,address,value.to_bytes(8,'little'))


def _move_record(p, destination, source):
    # +0x2901d4 move-constructs each string, zeroing all 24 source bytes.
    for index in range(4):
        src, dst = source+index*24, destination+index*24
        _write_span(p,dst,_read_span(p,src,24))
        _write_span(p,src,bytes(24))


def _destroy_record(p, record, free):
    for index in (3,2,1,0):
        destroy_cpp_string(p,object_address=record+index*24,free=free)


def execute_event_emission(pages, *, image_base, entry_stack_address,
        input_object_addresses, allocate, free, observer=None):
    """Warm +0x28ff44 record-vector publication with ownership transfer.

    Execute four move assignments, uncontended mutex, append/grow or >=200
    drop, and temporary destruction. Cold singleton and alternate publication
    branch refuse. Whole-native stack/TLS/OS and concurrent atomicity are not
    claimed. Guest pages commit on success; external Effects are not rollback.
    """
    if (not isinstance(entry_stack_address,int) or entry_stack_address < 0x140
            or entry_stack_address & 15):
        raise RefillUnsupported('event emission stack must be aligned')
    if len(input_object_addresses) != 4 or any(not isinstance(a,int) or not 0 <= a < (1<<64)-24
            for a in input_object_addresses):
        raise RefillUnsupported('event emission requires four uint64 object addresses')
    addresses=tuple(input_object_addresses)
    for index,a in enumerate(addresses):
        for b in addresses[index+1:]:
            if max(a,b)<min(a,b)+24:
                raise RefillUnsupported('event emission overlapping inputs are unsupported')
    p=_PageTransaction(pages)
    if _read_span(p,image_base+0x3E1B20,1)[0] & 1:
        raise RefillUnsupported('event alternate publication +0x290610 is not recovered')
    logger=_word(p,image_base+0x3E1B08)
    if not logger:
        raise RefillUnsupported('request event logger cold singleton +0x295de8 is not recovered')
    _read_span(p,logger,64)
    state=int.from_bytes(_read_span(p,logger,2),'little')
    if state not in (0,0x2000):
        raise RefillUnsupported('event logger requires an uncontended normal mutex')
    begin,end,capacity_end=(_word(p,logger+n) for n in (40,48,56))
    if (not 0 <= begin <= end <= capacity_end < 1<<64
            or (end-begin)%96 or (capacity_end-begin)%96
            or (capacity_end-begin)//96 > 512 or (begin==0 and (end or capacity_end))):
        raise RefillUnsupported('event record vector geometry or explicit bound is unsupported')
    count,capacity=(end-begin)//96,(capacity_end-begin)//96
    if capacity_end>begin:
        _read_span(p,begin,capacity_end-begin)
    local=entry_stack_address-0x140
    record=local+8
    _read_span(p,record,96)
    for a in addresses:
        _read_span(p,a,24)
        for b,n in ((record,96),(logger,64),(begin,capacity_end-begin)):
            if n and max(a,b)<min(a+24,b+n):
                raise RefillUnsupported('event input aliases logger/vector/temporary storage')
    _write_span(p,record,bytes(96))
    for index,a in enumerate(addresses):
        move_assign_cpp_string(p,object_address=record+index*24,source_object_address=a,free=free)
    objects.lock_uncontended_mutex(p,mutex_address=logger)
    appended=count<200
    destination=None
    if appended and count<capacity:
        destination=end
        _move_record(p,destination,record)
        _store_word(p,logger+48,end+96)
    elif appended:
        new_capacity=max(capacity*2,count+1)
        if new_capacity>512:
            raise RefillUnsupported('event record vector growth exceeds explicit bound')
        scratch=local+0x68
        _read_span(p,scratch,40)
        _store_word(p,scratch+24,0)
        _store_word(p,scratch+32,logger+56)
        new_begin=allocate(p,new_capacity*96)
        if not isinstance(new_begin,int) or not 0 < new_begin < (1<<64)-new_capacity*96:
            raise RefillUnsupported('event record vector operator-new failure is not recovered')
        _read_span(p,new_begin,new_capacity*96)
        destination=new_begin+count*96
        _store_word(p,scratch,new_begin)
        _store_word(p,scratch+8,destination)
        _store_word(p,scratch+16,destination)
        _store_word(p,scratch+24,new_begin+new_capacity*96)
        _move_record(p,destination,record)
        _store_word(p,scratch+16,destination+96)
        for index in range(count-1,-1,-1):
            _move_record(p,new_begin+index*96,begin+index*96)
            _store_word(p,scratch+8,new_begin+index*96)
        _store_word(p,logger+40,new_begin)
        _store_word(p,logger+48,destination+96)
        _store_word(p,logger+56,new_begin+new_capacity*96)
        _store_word(p,scratch,begin)
        _store_word(p,scratch+8,begin)
        _store_word(p,scratch+16,end)
        _store_word(p,scratch+24,capacity_end)
        for index in range(count-1,-1,-1):
            _store_word(p,scratch+16,begin+index*96)
            _destroy_record(p,begin+index*96,free)
        if begin:
            free(p,begin)
    objects.unlock_uncontended_mutex(p,mutex_address=logger)
    _destroy_record(p,record,free)
    if observer:
        observer(p,phase='event_emission_completed',logger_address=logger,
            record_count=count+int(appended),record_address=destination,
            appended=appended,dropped=not appended,
            warm_logger_publication_completed=True,whole_request_callback_completed=False)
    p.commit()
    return EventEmissionResult(logger,appended,not appended,destination,count+int(appended))
