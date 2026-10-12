"""Request round schedule and block helpers driven by fresh guest memory.

The block operation reuses the existing Helios VM after checking guest bytecode.
Register spills, PAC and physical return registers remain separate contracts.
"""
from vm9_allocator import RefillUnsupported,_PageTransaction,_read_span,_write_span
import helios_vm

MASK64=(1<<64)-1


def resolve_token_cipher_helpers(pages, *, image_base):
    """Resolve actual encoded +383548/+383550 slots, refusing changed helpers."""
    address=image_base+0x287A78
    mixed=(((0x00A060400A021040|(~address&MASK64))&0x00A061440A061440)
        +(address&0x0000010400040400))|0x01010104
    delta=mixed^0xFF5F9EBBF407DE8C
    helpers=tuple((int.from_bytes(_read_span(pages,image_base+offset,8),'little')+delta)&MASK64
        for offset in (0x383548,0x383550))
    if helpers!=(image_base+0x287EDC,image_base+0x2881CC):
        raise RefillUnsupported('unrecovered request cipher helper slots')
    return helpers


def _stack(entry,minimum):
    if type(entry) is not int or not minimum<=entry<1<<64 or entry&15:
        raise RefillUnsupported('token cipher helper stack must be aligned')


def prepare_token_round_schedule(pages, *, context_address, key_address,
        entry_stack_address, thread_pointer):
    """+287edc: four live little-endian words, 34 schedule rounds.

    Key copies precede context publication. Retain the defined four-word
    scratch and canary; context words after the 35 written words are preserved.
    """
    _stack(entry_stack_address,0x200)
    scratch=entry_stack_address-0x90;canary=entry_stack_address-0x68
    for address,width,is_key in ((key_address,32,True),(context_address,280,False)):
        if address<entry_stack_address and address+width>entry_stack_address-0x200:
            if not (is_key and scratch<=address and address+width<=scratch+32):
                raise RefillUnsupported('token schedule aliases unmodeled physical spills')
    p=_PageTransaction(pages)
    _write_span(p,canary,_read_span(p,thread_pointer+0x28,8))
    _write_span(p,scratch,bytes(32))
    for i in range(4):
        _write_span(p,scratch+i*8,_read_span(p,key_address+i*8,8))
    _write_span(p,context_address,_read_span(p,scratch,8))
    for i in range(34):
        first=int.from_bytes(_read_span(p,scratch,8),'little')
        second=int.from_bytes(_read_span(p,scratch+8,8),'little')
        tail=((helios_vm.ror64(second,8)+first)&MASK64)^i
        next_key=tail^helios_vm.ror64(first,61)
        _write_span(p,scratch,next_key.to_bytes(8,'little'))
        for slot in range(2):
            _write_span(p,scratch+(slot+1)*8,_read_span(p,scratch+(slot+2)*8,8))
        _write_span(p,scratch+24,tail.to_bytes(8,'little'))
        _write_span(p,context_address+(i+1)*8,_read_span(p,scratch,8))
    if _read_span(p,canary,8)!=_read_span(p,thread_pointer+0x28,8):
        raise RefillUnsupported('token schedule stack canary changed')
    p.commit()
    return context_address


def encrypt_token_block(pages, *, context_address, source_address, output_address,
        entry_stack_address, thread_pointer, image_base):
    """+2881cc/+118f50 block VM with live caller schedule and payload.

    No captured backing registers initialize this computation. Only its 23
    instructions, input block and 34 round keys are needed by the existing VM.
    """
    _stack(entry_stack_address,0x600)
    for address,width in ((context_address,272),(source_address,16),(output_address,16)):
        if address<entry_stack_address and address+width>entry_stack_address-0x600:
            raise RefillUnsupported('token block aliases unmodeled physical spills')
    expected=b''.join(v.to_bytes(4,'little') for v in helios_vm.BC[:23])
    if _read_span(pages,image_base+0x118F50,len(expected))!=expected:
        raise RefillUnsupported('token block bytecode differs from recovered owner')
    p=_PageTransaction(pages);canary=entry_stack_address-0x28
    _write_span(p,canary,_read_span(p,thread_pointer+0x28,8))
    schedule=_read_span(p,context_address,272);source=_read_span(p,source_address,16)
    result=helios_vm.helios_compute(source,round_keys=schedule)
    _write_span(p,output_address,result)
    if _read_span(p,canary,8)!=_read_span(p,thread_pointer+0x28,8):
        raise RefillUnsupported('token block stack canary changed')
    p.commit()


def allocate_token_ciphertext(pages, *, source_address, length,
        output_pointer_address, output_length_address, key_address,
        entry_stack_address, thread_pointer, image_base, allocate, reallocate, free,
        max_bytes=0x100000):
    """+287a78: sized key/input, 16-byte padding, blocks, malloc and cleanup.

    The output allocation contains exactly padded bytes. A NULL output malloc
    publishes NULL and length zero after the same temporary cleanup order.
    """
    import vm9_objects as objects
    objects._string_bound(max_bytes);_stack(entry_stack_address,0x1000)
    if type(length) is not int or not 0<=length<=max_bytes:
        raise RefillUnsupported('token cipher input exceeds positive length bound')
    padded=(length//16+1)*16
    if padded>max_bytes:
        raise RefillUnsupported('token cipher padding exceeds byte bound')
    for address,width in ((source_address,length),(key_address,32),
            (output_pointer_address,8),(output_length_address,4)):
        if address<entry_stack_address and address+width>entry_stack_address-0x1000:
            raise RefillUnsupported('token allocated cipher aliases physical spills')
    resolve_token_cipher_helpers(pages,image_base=image_base)
    p=_PageTransaction(pages);local=entry_stack_address-0x310
    canary=entry_stack_address-0x70;context=local+0xA8
    key,input_string,padding,ciphertext=(local+n for n in (0x90,0x78,0x60,0x48))
    _write_span(p,canary,_read_span(p,thread_pointer+0x28,8))
    _write_span(p,context,bytes(0x1F8))
    def pointer(obj):return int.from_bytes(_read_span(p,obj+16,8),'little')
    objects.construct_sized_string_object(p,object_address=key,source_address=key_address,length=32,
        image_base=image_base,allocate=allocate,max_payload_bytes=max_bytes)
    objects.construct_sized_string_object(p,object_address=input_string,source_address=source_address,
        length=length,image_base=image_base,allocate=allocate,max_payload_bytes=max_bytes)
    prepare_token_round_schedule(p,context_address=context,key_address=pointer(key),
        entry_stack_address=local,thread_pointer=thread_pointer)
    current=int.from_bytes(_read_span(p,input_string+12,4),'little')
    if current!=length:
        raise RefillUnsupported('token input malloc failure branch is unsupported')
    objects.construct_string_object(p,object_address=padding,source_address=0,allocate=allocate,
        vtable_address=image_base+0x34F5F8,empty_descriptor_address=image_base+0x6E168)
    pad_length=padded-current
    objects.fill_string_object(p,object_address=padding,length=pad_length,fill=pad_length&255,
        allocate=allocate,reallocate=reallocate,free=free,max_bytes=max_bytes)
    objects.append_string_object(p,object_address=input_string,source_object_address=padding,
        allocate=allocate,reallocate=reallocate,free=free,max_bytes=max_bytes)
    objects.construct_filled_string_object(p,object_address=ciphertext,fill=0,length=padded,
        image_base=image_base,allocate=allocate,max_payload_bytes=max_bytes)
    for offset in range(0,padded,16):
        encrypt_token_block(p,context_address=context,source_address=pointer(input_string)+offset,
            output_address=pointer(ciphertext)+offset,entry_stack_address=local,
            thread_pointer=thread_pointer,image_base=image_base)
    output=allocate(p,padded);objects._word(output)
    _write_span(p,output_pointer_address,output.to_bytes(8,'little'))
    _write_span(p,output_length_address,(padded if output else 0).to_bytes(4,'little'))
    if output:
        copy_length=objects._s32(int.from_bytes(_read_span(p,ciphertext+12,4),'little'))
        if not 0<=copy_length<=max_bytes:
            raise RefillUnsupported('token output copy exceeds byte bound')
        _write_span(p,output,_read_span(p,pointer(ciphertext),copy_length))
    for obj in (ciphertext,padding,input_string,key):
        objects.destroy_string_object(p,object_address=obj,image_base=image_base,free=free)
    if _read_span(p,canary,8)!=_read_span(p,thread_pointer+0x28,8):
        raise RefillUnsupported('token allocated cipher stack canary changed')
    p.commit()
    return output


def encrypt_token_string_object(pages, *, source_object_address, object_address,
        key_object_address, entry_stack_address, thread_pointer, image_base,
        allocate, reallocate, free, max_bytes=0x100000):
    """+287580: clone/zero-pad key, allocated ciphertext, StringObject writeback."""
    import vm9_objects as objects
    objects._string_bound(max_bytes);_stack(entry_stack_address,0x1200)
    p=_PageTransaction(pages);local=entry_stack_address-0xA0
    canary=entry_stack_address-0x38
    _write_span(p,canary,_read_span(p,thread_pointer+0x28,8))
    if source_object_address:
        for address in (source_object_address,object_address,key_object_address):
            if address<entry_stack_address and address+24>entry_stack_address-0x1200:
                raise RefillUnsupported('token StringObject caller aliases physical spills')
        key=entry_stack_address-0x60;padding=entry_stack_address-0x78
        out_pointer=entry_stack_address-0x40;out_length=entry_stack_address-0x44
        _write_span(p,out_pointer,bytes(8));_write_span(p,out_length,bytes(4))
        key_length=objects._s32(int.from_bytes(_read_span(p,key_object_address+12,4),'little'))
        if key_length<0:
            raise RefillUnsupported('token cipher negative key length is unsupported')
        objects.clone_string_object(p,object_address=key,source_object_address=key_object_address,
            image_base=image_base,allocate=allocate,max_payload_bytes=max_bytes)
        if key_length<32:
            objects.construct_filled_string_object(p,object_address=padding,fill=0,length=32-key_length,
                image_base=image_base,allocate=allocate,max_payload_bytes=max_bytes)
            objects.append_string_object(p,object_address=key,source_object_address=padding,
                allocate=allocate,reallocate=reallocate,free=free,max_bytes=max_bytes)
            objects.destroy_string_object(p,object_address=padding,image_base=image_base,free=free)
        source=int.from_bytes(_read_span(p,source_object_address+16,8),'little')
        length=int.from_bytes(_read_span(p,source_object_address+12,4),'little')
        key_pointer=int.from_bytes(_read_span(p,key+16,8),'little')
        allocate_token_ciphertext(p,source_address=source,length=length,
            output_pointer_address=out_pointer,output_length_address=out_length,key_address=key_pointer,
            entry_stack_address=local,thread_pointer=thread_pointer,image_base=image_base,
            allocate=allocate,reallocate=reallocate,free=free,max_bytes=max_bytes)
        output=int.from_bytes(_read_span(p,out_pointer,8),'little')
        count=objects._s32(int.from_bytes(_read_span(p,out_length,4),'little'))
        if output:
            if count>0:
                objects.fill_string_object(p,object_address=object_address,length=count,fill=32,
                    allocate=allocate,reallocate=reallocate,free=free,max_bytes=max_bytes)
                destination=int.from_bytes(_read_span(p,object_address+16,8),'little')
                _write_span(p,destination,_read_span(p,output,count))
            free(p,output)
        objects.destroy_string_object(p,object_address=key,image_base=image_base,free=free)
    if _read_span(p,canary,8)!=_read_span(p,thread_pointer+0x28,8):
        raise RefillUnsupported('token StringObject cipher stack canary changed')
    p.commit()
