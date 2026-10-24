"""Nested request append and Base64 reference consumers using accepted owners."""
from vm9_allocator import _PageTransaction,_read_span,_write_span,RefillUnsupported
import vm9_objects as objects
import vm9_reference_scopes as references


def construct_base64_string_reference(pages, *, reference_address, source_object_address,
        entry_stack_address, thread_pointer, image_base, allocate, free,
        thread_id=None, observer=None, max_bytes=0x100000):
    """+258c14: query, malloc, live encode, sized object, free, scoped reference.

    Length scratch is a guest Q word and the subsequent constructor reads its
    low W. Empty input constructs a NULL reference through the same scope owner.
    Unsupported failed buffers remain explicit; no physical X0 ABI is claimed.
    """
    if type(entry_stack_address) is not int or not 0x200<=entry_stack_address<1<<64 or entry_stack_address&15:
        raise RefillUnsupported('Base64 reference stack requires aligned scratch')
    objects._string_bound(max_bytes)
    p=_PageTransaction(pages);local=entry_stack_address-0x50
    def u(address,width=8):return int.from_bytes(_read_span(p,address,width),'little')
    _write_span(p,local+8,_read_span(p,thread_pointer+0x28,8))
    _write_span(p,local,bytes(8))
    length=objects._s32(u(source_object_address+12,4))
    if not 0<=length<=max_bytes:
        raise RefillUnsupported('Base64 reference source length exceeds bound')
    objects.encode_configuration_base64(p,destination_address=0,destination_size=0,
        length_address=local,source_address=u(source_object_address+16),source_size=length,
        image_base=image_base,max_source_bytes=max_bytes)
    needed=u(local);string=0
    if needed:
        if needed>max_bytes:raise RefillUnsupported('Base64 reference allocation exceeds bound')
        buffer=allocate(p,needed);objects._word(buffer)
        if not buffer:raise RefillUnsupported('Base64 reference NULL buffer branch is unsupported')
        length=objects._s32(u(source_object_address+12,4))
        if not 0<=length<=max_bytes:
            raise RefillUnsupported('Base64 reference live length exceeds bound')
        objects.encode_configuration_base64(p,destination_address=buffer,destination_size=needed,
            length_address=local,source_address=u(source_object_address+16),source_size=length,
            image_base=image_base,max_source_bytes=max_bytes)
        string=allocate(p,24);objects._word(string)
        if not string:raise RefillUnsupported('Base64 reference object allocation failed')
        objects.construct_sized_string_object(p,object_address=string,source_address=buffer,
            length=u(local,4),image_base=image_base,allocate=allocate,max_payload_bytes=max_bytes)
        free(p,buffer)
    references.construct_scoped_string_reference(p,reference_address=reference_address,
        string_address=string,entry_stack_address=local,image_base=image_base,thread_pointer=thread_pointer,
        allocate=allocate,thread_id=thread_id,diagnostic_observer=observer)
    if _read_span(p,local+8,8)!=_read_span(p,thread_pointer+0x28,8):
        raise RefillUnsupported('Base64 reference stack canary changed')
    p.commit()
    return string


def _apply_token_tail_callback_impl(pages, *, wrapper_offset, argument_block_address,
        image_base, entry_stack_address, thread_pointer, allocate, reallocate, free,
        thread_id=None, observer=None, max_bytes=0x100000):
    """+288bf0 append stores X0; +288c10 Base64 passes hidden X8 and child SP."""
    p=_PageTransaction(pages)
    words=tuple(int.from_bytes(_read_span(p,argument_block_address+i*8,8),'little') for i in range(3))
    pair=(wrapper_offset,words[0]-image_base)
    if pair==(0x288BF0,0x248684):
        result=objects.append_string_object(p,object_address=words[1],source_object_address=words[2],
            allocate=allocate,reallocate=reallocate,free=free,max_bytes=max_bytes)
        _write_span(p,argument_block_address+24,result.to_bytes(8,'little'))
    elif pair==(0x288C10,0x258C14):
        result=construct_base64_string_reference(p,reference_address=words[1],source_object_address=words[2],
            entry_stack_address=entry_stack_address-16,thread_pointer=thread_pointer,image_base=image_base,
            allocate=allocate,free=free,thread_id=thread_id,observer=observer,max_bytes=max_bytes)
    else:
        raise RefillUnsupported('unrecovered token tail callback')
    p.commit()
    return result


def apply_token_tail_callback(pages, *, wrapper_offset, argument_block_address,
        image_base, entry_stack_address, thread_pointer, allocate, reallocate, free,
        thread_id=None, observer=None, max_bytes=0x100000, effect_journal=None):
    """Run token append/Base64 tail with an optional allocator-effect journal."""
    from vm9_effects import require_effect_journal
    effect_journal=require_effect_journal(effect_journal)
    kwargs=dict(wrapper_offset=wrapper_offset,argument_block_address=argument_block_address,
        image_base=image_base,entry_stack_address=entry_stack_address,thread_pointer=thread_pointer,
        allocate=allocate,reallocate=reallocate,free=free,thread_id=thread_id,observer=observer,
        max_bytes=max_bytes)
    if effect_journal is None:
        return _apply_token_tail_callback_impl(pages,**kwargs)
    with effect_journal.transaction():
        return _apply_token_tail_callback_impl(pages,**kwargs)


def _apply_token_printf_callback_impl(pages, *, argument_block_address, image_base,
        entry_stack_address, thread_pointer, allocate, max_bytes=0x100000,va_list_frame=None):
    """+288c28 -> +278314: one packed argument, W0 result, child canary.

    The wrapper loads X0/X1/X2 before entering the accepted live two-pass
    formatter. It stores four result bytes; the following padding is retained.
    Save X2 and the two unconsumed AArch64 va_list descriptors in their actual
    stack cells. Other GP/FP spills, consumed copies and the complete physical
    return ABI remain separate.
    """
    from vm9_configuration_init import allocate_printf_cstring
    if type(entry_stack_address) is not int or not 0x200<=entry_stack_address<1<<64 or entry_stack_address&15:
        raise RefillUnsupported('token printf stack requires aligned child space')
    p=_PageTransaction(pages)
    words=tuple(int.from_bytes(_read_span(p,argument_block_address+i*8,8),'little') for i in range(4))
    if words[0]-image_base!=0x278314:
        raise RefillUnsupported('unrecovered token allocated printf callback')
    _write_span(p,entry_stack_address-0x110,words[3].to_bytes(8,'little'))
    canary=entry_stack_address-0x58
    _write_span(p,canary,_read_span(p,thread_pointer+0x28,8))
    saved_varargs=b''.join(v.to_bytes(8,'little') for v in
        (entry_stack_address-0x10,entry_stack_address-0xE0,entry_stack_address-0x110))
    saved_varargs+=(-0x30).to_bytes(4,'little',signed=True)+(-0x80).to_bytes(4,'little',signed=True)
    _write_span(p,entry_stack_address-0x78,saved_varargs)
    _write_span(p,entry_stack_address-0xA0,saved_varargs)
    result=allocate_printf_cstring(p,output_pointer_address=words[1],format_address=words[2],
        argument_addresses=(words[3],),allocate=allocate,max_bytes=max_bytes,va_list_frame=va_list_frame)
    if _read_span(p,canary,8)!=_read_span(p,thread_pointer+0x28,8):
        raise RefillUnsupported('token printf stack canary changed')
    _write_span(p,argument_block_address+32,result.to_bytes(4,'little'))
    p.commit()
    return result


def apply_token_printf_callback(pages, *, argument_block_address, image_base,
        entry_stack_address, thread_pointer, allocate, max_bytes=0x100000,
        va_list_frame=None, effect_journal=None):
    """Run token allocated printf with an optional allocator-effect journal."""
    from vm9_effects import require_effect_journal
    effect_journal=require_effect_journal(effect_journal)
    kwargs=dict(argument_block_address=argument_block_address,image_base=image_base,
        entry_stack_address=entry_stack_address,thread_pointer=thread_pointer,
        allocate=allocate,max_bytes=max_bytes,va_list_frame=va_list_frame)
    if effect_journal is None:
        return _apply_token_printf_callback_impl(pages,**kwargs)
    with effect_journal.transaction():
        return _apply_token_printf_callback_impl(pages,**kwargs)
