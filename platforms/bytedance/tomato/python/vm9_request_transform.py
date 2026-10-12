"""Request transforms and URL conditions using accepted guest object owners."""
from vm9_allocator import _PageTransaction,_read_span,_write_span,RefillUnsupported
import vm9_objects as objects
import vm9_reference_scopes as references


def evaluate_request_url_condition(pages, *, handler_address, source_object_address,
        image_base, entry_stack_address, max_bytes=0x100000, max_pattern_bytes=0x10000):
    """+2828d4: three lazy constants, handler byte and ordered URL searches.

    Decode all constants before reading handler+53. A zero handler byte skips
    the URL entirely. Otherwise the first nonnegative signed-W search wins.
    """
    if type(entry_stack_address) is not int or not 0x40<=entry_stack_address<1<<64 or entry_stack_address&15:
        raise RefillUnsupported('request URL condition requires aligned caller stack')
    p=_PageTransaction(pages)
    constants=((0x3E0B70,0xF2398,0x3E0B60,0xF2564),
        (0x3E0B80,0xF23A8,0x3E0B74,0xF2558),(0x3E0BA8,0xF23C0,0x3E0B90,0xF2540))
    for flag,source,destination,mask in constants:
        if not int.from_bytes(_read_span(p,image_base+flag,4),'little'):
            objects.decode_masked_bytes(p,source_address=image_base+source,
                destination_address=image_base+destination,mask_address=image_base+mask,max_bytes=max_pattern_bytes)
            _write_span(p,image_base+flag,(1).to_bytes(4,'little'))
    result=True
    if _read_span(p,handler_address+0x53,1)[0]:
        result=False
        for flag,source,destination,mask in constants:
            found=objects.find_string_object_cstring(p,object_address=source_object_address,
                pattern_address=image_base+destination,start_u32=0,
                entry_stack_address=entry_stack_address,max_comparisons=max_bytes)
            if not found&0x80000000:
                result=True
                break
    p.commit()
    return result


def apply_request_url_condition_callback(pages, *, argument_block_address,
        image_base, entry_stack_address, max_bytes=0x100000, max_pattern_bytes=0x10000):
    """+285f14: two packed pointers and only bit zero of W0 at packed+24."""
    p=_PageTransaction(pages)
    words=tuple(int.from_bytes(_read_span(p,argument_block_address+i*8,8),'little') for i in range(3))
    if words[0]-image_base!=0x2828D4:
        raise RefillUnsupported('unrecovered request URL condition callback')
    result=evaluate_request_url_condition(p,handler_address=words[1],source_object_address=words[2],
        image_base=image_base,entry_stack_address=entry_stack_address-0x40,
        max_bytes=max_bytes,max_pattern_bytes=max_pattern_bytes)
    _write_span(p,argument_block_address+24,bytes([int(result)]))
    p.commit()
    return result


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


def construct_request_suffix(pages, *, object_address, entry_stack_address,
        image_base, thread_pointer, allocate, reallocate, free, get_singleton,
        parse_decimal, thread_id=None, diagnostic_observer=None, max_bytes=0x100000):
    """+0x2869f0: compose two output C strings and destroy temporary ownership.

    The guest input contains timestamp, two StringObjects, seed pointer, two
    output-pointer slots and mode. Recover lazy constants from the ELF table;
    reuse all string, reference, digest, version, transform and printf owners.
    Helper entry SP is outer SP-0x260. Physical callee spills and unwind remain
    outside this semantic composition. Providers own their external rollback.
    """
    import vm9_configuration_init as configuration
    if type(entry_stack_address) is not int or entry_stack_address&15 or not 0x600<=entry_stack_address<1<<64:
        raise RefillUnsupported('request suffix requires aligned scratch space')
    if type(max_bytes) is not int or not 64<=max_bytes<=0x100000:
        raise ValueError('invalid request suffix byte bound')
    if not all(callable(s) for s in (allocate,reallocate,free,get_singleton,parse_decimal)):
        raise RefillUnsupported('request suffix requires owning services')
    if type(object_address) is not int or not 0<object_address<(1<<64)-64:
        raise RefillUnsupported('request suffix input must fit uint64')
    if object_address<entry_stack_address and object_address+64>entry_stack_address-0x600:
        raise RefillUnsupported('request suffix input aliases physical caller scratch')
    p=_PageTransaction(pages);E=entry_stack_address;body=E-0x260
    _read_span(p,E-0x600,0x600)
    canary=_read_span(p,thread_pointer+0x28,8)
    def u(a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
    def w(a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
    pc=image_base+0x2869F0;mask=(1<<64)-1
    delta=(((((~pc|0xA060400A021040)&0xA061440A061440)+(pc&0x10400040400))|0x1010104)^0xFF5F9EBBF407DE8C)&mask
    table=image_base+0x383560
    def selector(offset):return (u(table+offset)+delta)&mask
    first,fmt,third=selector(0),selector(8),selector(16)
    for flag,source,destination,key in ((0x18,0x20,0,0x28),(0x30,0x38,8,0x40),(0x48,0x50,16,0x58)):
        if not u(selector(flag),4):
            objects.decode_masked_bytes(p,source_address=selector(source),
                destination_address=selector(destination),mask_address=selector(key),max_bytes=max_bytes)
            w(selector(flag),1,4)
    timestamp=u(object_address);output1=u(object_address+32);mode=u(object_address+48,4)
    digest_source=u(object_address+16);seed_pointer=u(object_address+24);output2=u(object_address+40)
    constant,md5ref,rawref,sizedref=E-0x110,E-0x120,E-0x130,E-0x140
    version_scratch,time_scratch,combined=E-0x150,E-0x160,E-0x180
    transformed,hexclone,hexref=E-0x230,E-0x250,E-0x260
    kw=dict(entry_stack_address=body,image_base=image_base,thread_pointer=thread_pointer,
        allocate=allocate,thread_id=thread_id,diagnostic_observer=diagnostic_observer)
    def cstring(a,source):
        return objects.construct_string_object(p,object_address=a,source_address=source,allocate=allocate,
            vtable_address=image_base+0x34F5F8,empty_descriptor_address=image_base+0x6E168,max_source_bytes=max_bytes)
    def destroy(a):objects.destroy_string_object(p,object_address=a,image_base=image_base,free=free)
    def release(a):references.release_scoped_string_reference(p,reference_address=a,free=free,**kw)
    cstring(constant,first)
    _write_span(p,md5ref,bytes(16))
    if mode==1:
        clone=objects._allocate(p,allocate,24)
        objects.clone_string_object(p,object_address=clone,source_object_address=constant,
            image_base=image_base,allocate=allocate,max_payload_bytes=max_bytes)
        references.assign_scoped_owned_string_reference(p,reference_address=md5ref,string_address=clone,free=free,**kw)
        second=constant
    else:
        references.construct_scoped_digest_reference(p,output_reference_address=rawref,source_object_address=digest_source,
            reallocate=reallocate,free=free,max_source_bytes=max_bytes,flag=0,**kw)
        references.assign_scoped_string_reference(p,destination_address=md5ref,source_address=rawref,free=free,**kw)
        release(rawref)
        second=u(object_address+8)
    sized=objects._allocate(p,allocate,24)
    objects.construct_filled_string_object(p,object_address=sized,fill=0,length=16,
        image_base=image_base,allocate=allocate,max_payload_bytes=max_bytes)
    references.construct_scoped_string_reference(p,reference_address=sizedref,string_address=sized,**kw)
    version=configuration.get_request_version_word(p,image_base=image_base,allocate=allocate,free=free,
        parse_decimal=parse_decimal,thread_id=thread_id,max_bytes=max_bytes)
    w(version_scratch,version,4)
    w(time_scratch,int.from_bytes((timestamp&0xFFFFFFFF).to_bytes(4,'little'),'big'),4)
    cstring(combined,0)
    for reference,source,temp in ((md5ref,0,E-0x1A0),(0,second,E-0x1C0),(sizedref,0,E-0x1E0)):
        if reference:source=u(reference)
        objects.construct_substring_string_object(p,object_address=temp,source_object_address=source,
            start_u32=0,count_u32=4,image_base=image_base,entry_stack_address=body,thread_pointer=thread_pointer,
            allocate=allocate,max_payload_bytes=max_bytes)
        objects.append_string_object(p,object_address=combined,source_object_address=temp,
            allocate=allocate,reallocate=reallocate,free=free,max_bytes=max_bytes)
        destroy(temp)
    for source,temp in ((version_scratch,E-0x200),(time_scratch,E-0x220)):
        objects.construct_sized_string_object(p,object_address=temp,source_address=source,length=4,
            image_base=image_base,allocate=allocate,max_payload_bytes=max_bytes)
        objects.append_string_object(p,object_address=combined,source_object_address=temp,
            allocate=allocate,reallocate=reallocate,free=free,max_bytes=max_bytes)
        destroy(temp)
    target=selector(-0x20)
    if target!=image_base+0x286084:
        raise RefillUnsupported('request suffix transform dispatch is unsupported')
    construct_transformed_reference(p,output_reference_address=transformed,source_object_address=combined,
        seed_u32=u(seed_pointer,2),reallocate=reallocate,free=free,get_singleton=get_singleton,max_bytes=max_bytes,**kw)
    references.construct_hexadecimal_string_reference(p,output_reference_address=hexref,source_object_address=u(transformed),
        reallocate=reallocate,free=free,max_bytes=max_bytes,**kw)
    objects.clone_string_object(p,object_address=hexclone,source_object_address=u(hexref),
        image_base=image_base,allocate=allocate,max_payload_bytes=max_bytes)
    release(hexref)
    configuration.allocate_printf_cstring(p,output_pointer_address=output1,format_address=fmt,
        argument_addresses=(third,),allocate=allocate,max_bytes=max_bytes)
    configuration.allocate_printf_cstring(p,output_pointer_address=output2,format_address=fmt,
        argument_addresses=(u(hexclone+16),),allocate=allocate,max_bytes=max_bytes)
    destroy(hexclone);release(transformed);destroy(combined);release(sizedref);release(md5ref);destroy(constant)
    if _read_span(p,thread_pointer+0x28,8)!=canary:
        raise RefillUnsupported('request suffix TLS canary changed')
    result=(u(output1),u(output2))
    p.commit()
    return result


def construct_request_metadata(pages, *, object_address, image_base, allocate,
        max_bytes=0x100000):
    """+0x287168: decode constants and allocate string and unsigned-word outputs.

    Read the input W0 and both output-slot addresses before the first malloc;
    preserve the second formatter's uint32 return, including allocation failure.
    All printf passes use the existing owner and reread their live input bytes.
    Guest writes commit together. External allocation effects are not undone.
    """
    import vm9_configuration_init as configuration
    if type(max_bytes) is not int or not 1<=max_bytes<=0x100000:
        raise ValueError('invalid request metadata byte bound')
    if not callable(allocate):
        raise RefillUnsupported('request metadata requires owning malloc')
    p=_PageTransaction(pages)
    def u(a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
    pc=image_base+0x287168;mask=(1<<64)-1
    delta=(((((~pc|0xA060400A021040)&0xA061440A061440)+(pc&0x10400040400))|0x1010104)^0xFF5F9EBBF407DE8C)&mask
    table=image_base+0x383568
    def selector(offset):return (u(table+offset)+delta)&mask
    first_format,constant,second_format=selector(0),selector(0x70),selector(0x78)
    for destination,flag,source,key in ((0,0x28,0x30,0x38),(0x70,0x80,0x88,0x90),(0x78,0x98,0xA0,0xA8)):
        if not u(selector(flag),4):
            objects.decode_masked_bytes(p,source_address=selector(source),
                destination_address=selector(destination),mask_address=selector(key),max_bytes=max_bytes)
            _write_span(p,selector(flag),(1).to_bytes(4,'little'))
    value=u(object_address,4)
    first_slot,second_slot=u(object_address+8),u(object_address+16)
    configuration.allocate_printf_cstring(p,output_pointer_address=first_slot,
        format_address=first_format,argument_addresses=(constant,),allocate=allocate,max_bytes=max_bytes)
    result=configuration.allocate_printf_cstring(p,output_pointer_address=second_slot,
        format_address=second_format,argument_addresses=(value,),allocate=allocate,max_bytes=max_bytes)
    p.commit()
    return result
