"""Request binary transform with explicit guest reference and SDK services."""
from vm9_allocator import _PageTransaction,_read_span,_write_span,RefillUnsupported
import vm9_objects as objects
import vm9_reference_scopes as references


def construct_transformed_reference(pages, *, output_reference_address,source_object_address,
        seed_u32,entry_stack_address,image_base,thread_pointer,allocate,reallocate,free,
        get_singleton,thread_id=None,diagnostic_observer=None,max_bytes=0x100000):
    """+0x286084 binary transform, when first singleton136 field+0x10 is zero.

    Preserve allocated-pointer and caller-scratch key bytes, live source reads,
    duplicate S-box writes and forward byte mixing. The initialized SDK wrapper
    is an explicit provider input; its other environment path is unrecovered.
    Publish only after success. External provider effects are not rolled back.
    """
    if type(entry_stack_address) is not int or entry_stack_address&15 or not 0x300<=entry_stack_address<1<<64:
        raise RefillUnsupported('request transform requires aligned scratch space')
    if type(seed_u32) is not int or not 0<=seed_u32<=0xFFFFFFFF:
        raise RefillUnsupported('request transform seed must fit W1')
    if type(max_bytes) is not int or not 0<=max_bytes<=0x100000:
        raise ValueError('invalid request transform byte bound')
    if not all(callable(s) for s in (allocate,reallocate,free,get_singleton)):
        raise RefillUnsupported('request transform requires owning services')
    p=_PageTransaction(pages);stack=entry_stack_address-0x190;key_address=entry_stack_address-0x78
    _read_span(p,key_address,8)
    string=objects._allocate(p,allocate,24)
    objects.construct_string_object(p,object_address=string,source_address=0,allocate=allocate,
        vtable_address=image_base+0x34F5F8,empty_descriptor_address=image_base+0x6E168)
    references.construct_scoped_string_reference(p,reference_address=output_reference_address,
        string_address=string,entry_stack_address=stack,image_base=image_base,thread_pointer=thread_pointer,
        allocate=allocate,thread_id=thread_id,diagnostic_observer=diagnostic_observer)
    length=objects._s32(int.from_bytes(_read_span(p,source_object_address+12,4),'little'))
    if not 0<=length<=max_bytes:
        raise RefillUnsupported('request transform source length is unsupported')
    status=objects.fill_string_object(p,object_address=string,length=length+6,fill=0,
        allocate=allocate,reallocate=reallocate,free=free,max_bytes=min(max_bytes+7,0x100000))
    if status!=0:
        raise RefillUnsupported('request transform output reserve failed')
    payload=int.from_bytes(_read_span(p,string+16,8),'little')
    key=bytearray(_read_span(p,key_address,8))
    key[7]=payload&255;key[3]=(payload>>8)&255
    wrapper=get_singleton(p)
    sdk=int.from_bytes(_read_span(p,wrapper,8),'little')
    first=int.from_bytes(_read_span(p,sdk+16,8),'little')
    wrapper=get_singleton(p)
    sdk=int.from_bytes(_read_span(p,wrapper,8),'little')
    _read_span(p,sdk+24,8)
    if first:
        raise RefillUnsupported('request transform nonzero SDK field is unrecovered')
    key[0]=0x4A;key[2]=0x16
    _write_span(p,payload,b'\x84')
    key[5:7]=_read_span(p,payload+2,2)
    seed=seed_u32.to_bytes(4,'little')
    key[1]=seed[0];key[6]=seed[1]
    box=bytearray(256)
    for i in range(256):
        if i==244:key[4:6]=b'\x47\x6C'
        if i==182:key[4:6]=_read_span(p,payload+2,2)
        box[i]=i
        if i==165:key[4:6]=_read_span(p,payload+4,2)
    j=0
    for i in range(256):
        if i==203:_write_span(p,payload+3,bytes([key[3]]))
        j=(j+box[i]+key[i&7])&255
        value=box[j];box[i]=value
        if i==224:_write_span(p,payload+4,seed[:2])
        box[j]=value
    if length:
        source=int.from_bytes(_read_span(p,source_object_address+16,8),'little')
        _write_span(p,payload+6,_read_span(p,source,length))
    i=j=0
    for offset in range(length):
        i=(i+1)&255;j=(j+box[i])&255
        value=box[j];box[i]=value;box[j]=value
        byte=_read_span(p,payload+6+offset,1)[0]^box[(box[i]+value)&255]
        _write_span(p,payload+6+offset,bytes([byte]))
    for offset in range(length):
        byte=_read_span(p,payload+6+offset,1)[0]
        value=((byte>>4)|(byte<<4))&255
        if offset+1<length:value^=_read_span(p,payload+7+offset,1)[0]
        if offset==0:_write_span(p,payload+2,bytes([key[7]]))
        elif offset==length-1:value^=_read_span(p,payload+6,1)[0]
        reversed_byte=int(f'{value:08b}'[::-1],2)
        _write_span(p,payload+6+offset,bytes([(length^~reversed_byte)&255]))
    _write_span(p,payload+1,b'\x04')
    p.commit()
    return string
