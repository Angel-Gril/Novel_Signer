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
