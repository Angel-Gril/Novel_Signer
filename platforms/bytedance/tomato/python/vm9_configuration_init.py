"""Bounded configuration initialization around the restored Python parser.

Guest ELF supplies lazy constants, identifiers, descriptors and vtables.
Explicit allocator/singleton services model environment effects. Supports
observed non-file configuration mode with an empty publication container;
other file/tree/diagnostic branches reject transactionally.
"""
from __future__ import annotations
from dataclasses import dataclass
import vm9_objects as objects
import vm9_stream_cipher as stream
import vm9_protobuf as protobuf
import vm9_parser as parser
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported

MASK64 = (1 << 64) - 1


def _u(pages, address, size=8):
    return int.from_bytes(_read_span(pages,address,size),'little')


def _w(pages,address,value,size=8):
    _write_span(pages,address,(value & ((1 << (size*8))-1)).to_bytes(size,'little'))


def copy_string_reference(pages, *, destination_address, source_address):
    """+0x15f580: zero destination before reloading and incrementing source."""
    staged=_PageTransaction(pages)
    _write_span(staged,destination_address,bytes(16))
    _w(staged,destination_address,_u(staged,source_address))
    counter=_u(staged,source_address+8)
    _w(staged,destination_address+8,counter)
    if counter:_w(staged,counter,_u(staged,counter,4)+1,4)
    staged.commit()


def assign_owned_string_reference(pages, *, reference_address, object_address,
        image_base, allocate, free):
    """+0x162944: release old ownership, then publish new object/count."""
    staged=_PageTransaction(pages)
    if _u(staged,reference_address+8):
        stream.release_string_reference(staged,reference_address=reference_address,image_base=image_base,free=free)
    _w(staged,reference_address,object_address)
    counter=allocate(staged,4)
    if not counter:raise RefillUnsupported('reference operator-new NULL abort is unsupported')
    _w(staged,reference_address+8,counter);_w(staged,counter,1,4)
    staged.commit()


def string_equals_cstring(pages, *, object_address, cstring_address, max_bytes=0x100000):
    """+0x24880c/+0x247374: declared byte length must match terminating NUL."""
    if not object_address or not cstring_address:return False
    length=objects._s32(_u(pages,object_address+12,4));payload=_u(pages,object_address+16)
    if length<0 or not payload:return False
    if length>max_bytes:raise RefillUnsupported('string equality exceeds explicit bound')
    for i in range(length):
        byte=_u(pages,cstring_address+i,1)
        if byte==0 or byte!=_u(pages,payload+i,1):return False
    return _u(pages,cstring_address+length,1)==0


def strings_equal(pages, *, first_object, second_object, max_bytes=0x100000):
    """+0x1a7e10 flag bit0=1 / +0x2487e8 exact binary equality."""
    if not first_object or not second_object:return False
    first,second=_u(pages,first_object+16),_u(pages,second_object+16)
    a,b=objects._s32(_u(pages,first_object+12,4)),objects._s32(_u(pages,second_object+12,4))
    if not first or not second or a<0 or b<0 or a!=b:return False
    if a>max_bytes:raise RefillUnsupported('binary equality exceeds explicit bound')
    return first==second or _read_span(pages,first,a)==_read_span(pages,second,a)


def get_guest_identifier(pages, *, image_base):
    """+0x172dbc relocated pointer table; no identifier text is embedded."""
    staged=_PageTransaction(pages);table=image_base+0x379940
    # Observed address-mask algebra, same for both tested image bases.
    address=lambda slot:(_u(staged,table+slot)-0x912040)&MASK64
    selected=address(0);flag=address(8)
    if not _u(staged,flag,4):
        objects.decode_masked_bytes(staged,source_address=address(16),
            destination_address=address(0),mask_address=address(24))
        # Native reloads the flag slot after decoding.
        _w(staged,address(8),1,4)
    _read_span(staged,selected,1)
    staged.commit();return selected


def publication_container_size(pages, *, container_address, image_base, max_nodes=4096):
    """+0x25c71c/+0x24b6fc: distance between begin/end linked iterators.

    The controller's second word is not a count. The active iterator table
    has no subtraction callback, so +0x24b568 advances next links until the
    begin iterator equals the sentinel end iterator.
    """
    table=image_base+0x381AB8
    if _u(pages,table+0x38) or _u(pages,table+0x40):
        raise RefillUnsupported('publication iterator subtraction callback is unsupported')
    if (_u(pages,table+0x58)!=image_base+0x24B8AC or
            _u(pages,table+0x18)!=image_base+0x24B864):
        raise RefillUnsupported('unrecovered publication iterator table')
    controller=_u(pages,container_address+0x28)
    sentinel=_u(pages,controller)
    current=_u(pages,sentinel);seen=set()
    while current!=sentinel:
        if current in seen or len(seen)>=max_nodes:
            raise RefillUnsupported('publication iterator cycle or bound')
        seen.add(current);current=_u(pages,current) if current else 0
    return len(seen)


def release_parsed_reference(pages, *, reference_address, image_base, free):
    """+0x2633f0 and +0x2633cc: count, message graph and wrapper deletion."""
    staged=_PageTransaction(pages);counter=_u(staged,reference_address+8)
    if counter:
        original_count=_u(staged,counter,4)
        value=(original_count-1)&0xFFFFFFFF;_w(staged,counter,value,4)
        if objects._s32(original_count)<=1:
            free(staged,counter);pointer=_u(staged,reference_address)
            _w(staged,reference_address+8,0)
            if pointer:
                table=_u(staged,pointer)
                if _u(staged,table+8)!=image_base+0x2633CC:
                    raise RefillUnsupported('unrecovered parsed-object deleting destructor')
                _w(staged,pointer,image_base+0x35BA98)
                protobuf.free_configuration_message(staged,message_address=_u(staged,pointer+8),
                    image_base=image_base,free=free)
                free(staged,pointer);_w(staged,reference_address,0)
    staged.commit()


@dataclass
class ConfigurationResult:
    status: int
    parser_steps: int
    matched_selector: int


def initialize_configuration_context(pages, *, identity_object_address,
        configuration_address, entry_stack_address, thread_pointer, image_base,
        vm_module, allocate, reallocate, free, get_singleton):
    """+0x261cb0 observed mode/empty-tree path, including owned-message cleanup.

    Caller supplies the identity string and newly constructed 88-byte object.
    Parser workspaces are derived here, not read from a native parser snapshot.
    No file-provider, nonempty publication-tree or nonmatching selector path
    is treated as a successfully initialized configuration.
    """
    if entry_stack_address&15:raise RefillUnsupported('configuration stack must be aligned')
    staged=_PageTransaction(pages)
    frame=entry_stack_address-0x60;working=entry_stack_address-0x340
    _read_span(staged,working-0xD00,0x1000)
    _w(staged,frame-0x70,thread_pointer);_w(staged,frame-0x68,identity_object_address)
    _w(staged,frame-0x10,_u(staged,thread_pointer+0x28))
    _w(staged,frame-0x20,configuration_address)
    # All five lazy strings are initialized before the mode branch.
    for flag,source,destination,mask in ((0x3DEB74,0x9A694,0x3DEB6C,0x9A6D4),
        (0x3DEB80,0x9A69C,0x3DEB78,0x9A6CC),(0x3DEB88,0x9A6A4,0x3DEB84,0x9A6C8),
        (0x3DEB94,0x9A6A8,0x3DEB8C,0x9A6C0),(0x3DEBA0,0x9A6B0,0x3DEB98,0x9A6B8)):
        if not _u(staged,image_base+flag,4):
            objects.decode_masked_bytes(staged,source_address=image_base+source,
                destination_address=image_base+destination,mask_address=image_base+mask)
            _w(staged,image_base+flag,1,4)
    parsed_ref=entry_stack_address-0x130;source_ref=entry_stack_address-0x140;key_ref=entry_stack_address-0x150
    _w(staged,frame-0x18,parsed_ref)
    # Native source-reference constructor reads configuration +8.
    source=configuration_address+8
    _w(staged,frame-0xC0,source)
    copy_string_reference(staged,destination_address=source_ref,source_address=source)
    _write_span(staged,key_ref,bytes(16));counter=allocate(staged,4)
    if not counter:raise RefillUnsupported('key-reference count allocation abort')
    _w(staged,key_ref+8,counter);_w(staged,counter,1,4)
    parsed=parser.parse_configuration_caller(staged,first_argument=source_ref,
        second_argument=key_ref,third_argument=configuration_address+0x28,output_address=parsed_ref,
        entry_stack_address=working,return_address=image_base+0x262068,thread_pointer=thread_pointer,
        image_base=image_base,vm_module=vm_module,allocate=allocate,reallocate=reallocate,
        free=free,get_singleton=get_singleton)
    stream.release_string_reference(staged,reference_address=key_ref,image_base=image_base,free=free)
    stream.release_string_reference(staged,reference_address=source_ref,image_base=image_base,free=free)
    body=_u(staged,parsed_ref)
    if not body:raise RefillUnsupported('configuration parser produced no owned object')
    message=_u(staged,body+8)
    if not string_equals_cstring(staged,object_address=identity_object_address,cstring_address=_u(staged,message+32)):
        raise RefillUnsupported('configuration identity diagnostic branch is unsupported')
    result_string=allocate(staged,24)
    if not result_string:raise RefillUnsupported('configuration result-string allocation abort')
    objects.construct_string_object(staged,object_address=result_string,source_address=_u(staged,message+40),
        allocate=allocate,vtable_address=image_base+0x34F5F8,empty_descriptor_address=image_base+0x6E168)
    assign_owned_string_reference(staged,reference_address=configuration_address+0x18,
        object_address=result_string,image_base=image_base,allocate=allocate,free=free)
    _w(staged,configuration_address+0x40,_u(staged,message+48,4),4)
    if _u(staged,message+104,4)==1:
        raise RefillUnsupported('configuration file-provider mode is unsupported')
    container=_u(staged,configuration_address+0x48)
    if container:
        if publication_container_size(staged,container_address=container,image_base=image_base):
            raise RefillUnsupported('nonempty configuration publication tree is unsupported')
    count=_u(staged,message+72)
    if not 0<count<=16:raise RefillUnsupported('selector diagnostic or bound branch is unsupported')
    array=_u(staged,message+80);matched=None
    # Only fields written by live branches are constructed; unused workspaces
    # retain caller bytes, just as the native stack does.
    choices={0:(entry_stack_address-0x1E0,entry_stack_address-0x1B0,0x3DEB78),
        1:(entry_stack_address-0x2A0,entry_stack_address-0x2C0,0x3DEB84),
        3:(entry_stack_address-0x2E0,entry_stack_address-0x300,0x3DEB8C),
        5:(entry_stack_address-0x320,entry_stack_address-0x340,0x3DEB98)}
    for i in range(count):
        item=_u(staged,array+i*8);selector=_u(staged,item+48,4)
        if selector not in choices:continue
        first,second,constant=choices[selector]
        objects.construct_string_object(staged,object_address=first,source_address=image_base+constant,
            allocate=allocate,vtable_address=image_base+0x34F5F8,empty_descriptor_address=image_base+0x6E168)
        identifier=get_guest_identifier(staged,image_base=image_base)
        objects.construct_string_object(staged,object_address=second,source_address=identifier,
            allocate=allocate,vtable_address=image_base+0x34F5F8,empty_descriptor_address=image_base+0x6E168)
        equal=strings_equal(staged,first_object=first,second_object=second)
        objects.destroy_string_object(staged,object_address=second,image_base=image_base,free=free)
        objects.destroy_string_object(staged,object_address=first,image_base=image_base,free=free)
        if equal:matched=_u(staged,item+48,4);break
    if matched is None:raise RefillUnsupported('no matching configuration selector is unsupported')
    status=(matched*2+6)&0xFFFFFFFF
    release_parsed_reference(staged,reference_address=parsed_ref,image_base=image_base,free=free)
    staged.commit();return ConfigurationResult(status,parsed.steps,matched)


def initialize_configuration_wrapper(pages, *, argument_block_address,
        first_word, second_word, entry_stack_address, thread_pointer, image_base,
        vm_module, allocate, reallocate, free, get_singleton):
    """+0x261c54: initialize then conditionally replace two saved frame words.

    +0x26ecb4 returns the caller's saved X29 from its own stack. It does not
    fetch TLS. This wrapper sets X29 to its entry SP minus 0x30, hence that
    getter returns the same frame at which +0x261cb0 starts.
    """
    if entry_stack_address&15:
        raise RefillUnsupported('configuration wrapper stack must be aligned')
    staged=_PageTransaction(pages);frame=entry_stack_address-0x30
    identity=_u(staged,argument_block_address)
    configuration=_u(staged,argument_block_address+8)
    result=initialize_configuration_context(staged,identity_object_address=identity,
        configuration_address=configuration,entry_stack_address=frame,
        thread_pointer=thread_pointer,image_base=image_base,vm_module=vm_module,
        allocate=allocate,reallocate=reallocate,free=free,get_singleton=get_singleton)
    if first_word>4096 and second_word>4096:
        _w(staged,frame,first_word-0xE9);_w(staged,frame+8,second_word-0xD5)
    staged.commit();return result


def construct_initialized_configuration(pages, *, object_address,
        first_string_address, second_string_address, identity_object_address,
        entry_stack_address, thread_pointer, image_base, vm_module,
        allocate, reallocate, free, get_singleton):
    """+0x26194c observed path: layout, argument block and initializer.

    The relocated ELF supplies the decimal dispatch constant. The known
    +0x271998 trampoline preserves the constructor frame and +0x261b64
    continuation by encoding those two addresses into the wrapper arguments.
    Physical spill frames and unobserved constructor branches are excluded.
    """
    if entry_stack_address&15:
        raise RefillUnsupported('configuration constructor stack must be aligned')
    staged=_PageTransaction(pages);frame=entry_stack_address-0x60
    block=entry_stack_address-0xB0
    _w(staged,frame-8,_u(staged,thread_pointer+0x28))
    objects.construct_configuration_object_layout(staged,object_address=object_address,
        first_string_address=first_string_address,second_string_address=second_string_address,
        image_base=image_base,allocate=allocate)
    _write_span(staged,block,bytes(64))
    # +0x261b98 copies exactly two variadic register arguments here.
    _w(staged,block,identity_object_address);_w(staged,block+8,object_address)
    dispatch=objects._cstring(staged,image_base+0x3DEB60,64)[:-1]
    try:
        number=int(dispatch,10)
    except ValueError as exc:
        raise RefillUnsupported('unrecovered decimal configuration dispatch') from exc
    if not 0<=number<(1<<63) or (number>>2)!=0x522:
        raise RefillUnsupported('unrecovered configuration dispatch target')
    result=initialize_configuration_wrapper(staged,argument_block_address=block,
        first_word=frame+0xE9,second_word=image_base+0x261B64+0xD5,
        entry_stack_address=block,thread_pointer=thread_pointer,image_base=image_base,
        vm_module=vm_module,allocate=allocate,reallocate=reallocate,free=free,
        get_singleton=get_singleton)
    staged.commit();return result


# Cold shared/environment dependencies of state VM +0xa46a0. All constants
# remain in caller-provided ELF pages; host environment effects are explicit.
def _lazy_constant(pages, image_base, flag, source, destination, mask):
    if not _u(pages,image_base+flag,4):
        objects.decode_masked_bytes(pages,source_address=image_base+source,
            destination_address=image_base+destination,mask_address=image_base+mask)
        _w(pages,image_base+flag,1,4)
    return image_base+destination


def get_cached_sdk(pages, *, image_base, read_property, buffer_address):
    """+0x271ba8, bounded decimal property supplied by the environment.

    The property name is decoded from guest ELF bytes. The environment returns
    bytes or None; its find/read implementation is outside this native helper.
    Positive results are cached; missing/invalid/nonpositive values are not.
    Long/overflow property conversions are unsupported rather than guessed.
    """
    staged=_PageTransaction(pages)
    name=_lazy_constant(staged,image_base,0x3DF168,0xA5A60,0x3DF150,0xA5A80)
    value=_u(staged,image_base+0x3DF148,4)
    if value:
        staged.commit();return objects._s32(value)
    _write_span(staged,buffer_address,bytes(92))
    raw=read_property(staged,name)
    if raw is None:
        staged.commit();return 0
    if not isinstance(raw,bytes) or len(raw)>91 or b'\0' in raw:
        raise RefillUnsupported('SDK property must fit a native 92-byte buffer')
    _write_span(staged,buffer_address,raw+b'\0')
    # +0x2771bc reads the existing singleton twice before plain conversion.
    # Its cold construction/instrumentation branches are outside this helper.
    guard=_read_span(staged,image_base+0x3D1680,2)
    if not guard[0] and guard[1]!=1:
        raise RefillUnsupported('SDK conversion requires an initialized singleton136')
    wrapper=_u(staged,image_base+0x3D1678);service=_u(staged,wrapper)
    if _u(staged,service+0x10) and _u(staged,service+0x18):
        raise RefillUnsupported('SDK conversion instrumentation is unsupported')
    data=raw.lstrip(b' \t\n\v\f\r');negative=data.startswith(b'-')
    if data.startswith((b'-',b'+')):data=data[1:]
    n=0
    for byte in data:
        if not 48<=byte<=57:break
        n=n*10+byte-48
        if n>0x80000000:raise RefillUnsupported('SDK decimal overflow is unsupported')
    if negative:n=-n
    if not -0x80000000<=n<=0x7FFFFFFF:
        raise RefillUnsupported('SDK decimal overflow is unsupported')
    if n>0:_w(staged,image_base+0x3DF148,n,4)
    staged.commit();return max(0,n)


def initialize_unavailable_logger(pages, *, image_base, read_property, syscall,
        errno_address, property_buffer_address):
    """+0x271ddc observed unavailable file/socket sinks.

    Reproduce cold lazy decode, SDK dispatch, uncontended mutex and errno
    effects. syscall(staged_pages, number, argument_tuple) returns a signed
    Linux result. Successful descriptors, EINTR retries and live log writes
    remain unsupported. No real host file or socket is opened by this model.
    Physical variadic/spill frames and log message buffers are excluded.
    """
    staged=_PageTransaction(pages)
    def invoke(number,*args):
        result=syscall(staged,number,tuple(a&MASK64 for a in args))
        if not isinstance(result,int) or not -(1<<63)<=result<(1<<63):
            raise RefillUnsupported('log syscall requires a signed int64 result')
        if -4095<=result<0:
            _w(staged,errno_address,-result,4)
            return -1
        return result
    mode=objects._s32(_u(staged,image_base+0x382600,4))
    if mode==-1:
        sdk=get_cached_sdk(staged,image_base=image_base,read_property=read_property,
            buffer_address=property_buffer_address)
        mode=int(sdk<21);_w(staged,image_base+0x382600,mode,4)
    if mode==1:
        for flag,source,destination,mask in (
                (0x3DF17C,0xA5A98,0x3DF16C,0xA5B60),
                (0x3DF190,0xA5AA8,0x3DF180,0xA5B50),
                (0x3DF1A4,0xA5AB8,0x3DF194,0xA5B40),
                (0x3DF1B8,0xA5AC8,0x3DF1A8,0xA5B30)):
            _lazy_constant(staged,image_base,flag,source,destination,mask)
        objects.lock_uncontended_mutex(staged,mutex_address=image_base+0x3DF1EC)
        dispatch=_u(staged,image_base+0x382610)
        if dispatch==image_base+0x271F40:
            for i,path in enumerate((0x3DF16C,0x3DF180,0x3DF194,0x3DF1A8)):
                fd=invoke(56,0xFFFFFF9C,image_base+path,0x80001,0)
                if fd!=-1 or _u(staged,errno_address,4)==4:
                    raise RefillUnsupported('live or interrupted log open is unsupported')
                _w(staged,image_base+0x382620+i*4,fd,4)
            _w(staged,image_base+0x382610,image_base+0x272194)
            for _ in range(3):
                if invoke(57,0xFFFFFFFF)!=-1 or _u(staged,errno_address,4)==4:
                    raise RefillUnsupported('successful or interrupted log close is unsupported')
            _w(staged,image_base+0x382610,image_base+0x27220C)
        elif dispatch!=image_base+0x27220C:
            raise RefillUnsupported('live/unrecovered file logger dispatch is unsupported')
        objects.unlock_uncontended_mutex(staged,mutex_address=image_base+0x3DF1EC)
    elif mode==0:
        objects.lock_uncontended_mutex(staged,mutex_address=image_base+0x3DF1EC)
        if _u(staged,image_base+0x382618)!=image_base+0x272214:
            raise RefillUnsupported('live/unrecovered socket logger dispatch is unsupported')
        _lazy_constant(staged,image_base,0x3DF1C8,0xA5AD8,0x3DF1BC,0xA5B24)
        _lazy_constant(staged,image_base,0x3DF1E4,0xA5AF0,0x3DF1D0,0xA5B10)
        if objects._s32(_u(staged,image_base+0x382604,4))<0:
            fd=invoke(56,0xFFFFFF9C,image_base+0x3DF1BC,1,0)
            if fd!=-1 or _u(staged,errno_address,4)==4:
                raise RefillUnsupported('live or interrupted fallback log open is unsupported')
            _w(staged,image_base+0x382604,fd,4)
        if objects._s32(_u(staged,image_base+0x382608,4))>=0:
            raise RefillUnsupported('live log socket is unsupported')
        fd=invoke(198,1,0x80002,0)
        if fd!=-1 or _u(staged,errno_address,4)==4:
            raise RefillUnsupported('live or interrupted log socket is unsupported')
        objects.unlock_uncontended_mutex(staged,mutex_address=image_base+0x3DF1EC)
        if objects._s32(_u(staged,image_base+0x382604,4))>=0:
            raise RefillUnsupported('fallback log write is unsupported')
    # Any other mode does not dispatch, as in +0x271e9c.
    staged.commit()


def construct_default_shared_reference(pages, *, entry_stack_address, image_base,
        allocate, free, read_property, syscall, errno_address):
    """+0x26cdc4 default/no-JNI factory, publishing an inline global reference.

    Preserve four allocations and temporary-string free in their actual order.
    This is not the existing wrapper/payload singleton allocation layout.
    Native JNI and operator-new abort branches are explicitly unsupported.
    """
    if entry_stack_address&15:
        raise RefillUnsupported('shared factory stack must be aligned')
    staged=_PageTransaction(pages)
    for flag,source,destination,mask in (
            (0x3DEDC0,0xA55A0,0x3DEDB8,0xA5648),
            (0x3DEDF8,0xA55B0,0x3DEDD0,0xA5620),
            (0x3DEE18,0xA55E0,0x3DEE00,0xA5600)):
        _lazy_constant(staged,image_base,flag,source,destination,mask)
    if _u(staged,image_base+0x3DEED8):
        raise RefillUnsupported('shared factory JNI branch is not recovered')
    temporary=entry_stack_address-0x60
    objects.construct_string_object(staged,object_address=temporary,
        source_address=image_base+0x3DEDB8,allocate=allocate,
        vtable_address=image_base+0x34F5F8,empty_descriptor_address=image_base+0x6E168)
    initialize_unavailable_logger(staged,image_base=image_base,
        read_property=read_property,syscall=syscall,errno_address=errno_address,
        property_buffer_address=entry_stack_address-0x700)
    objects.destroy_string_object(staged,object_address=temporary,image_base=image_base,free=free)
    payload=allocate(staged,24)
    if not payload:raise RefillUnsupported('shared string operator-new NULL abort is unsupported')
    objects.construct_string_object(staged,object_address=payload,
        source_address=image_base+0x3DEE00,allocate=allocate,
        vtable_address=image_base+0x34F5F8,empty_descriptor_address=image_base+0x6E168)
    objects.construct_reference_wrapper(staged,object_address=image_base+0x3DEE28,
        referenced_address=payload,allocate=allocate)
    staged.commit();return image_base+0x3DEE28


def get_inline_shared_reference(pages, *, output_reference_address,
        entry_stack_address, image_base, allocate, free, read_property,
        syscall, errno_address, thread_id=None, register_destructor=None):
    """+0x26cd0c serialized cold acquire/factory/atexit/release/copy.

    Output alias behavior is the actual zero-before-source-read +0x15f580.
    Page writes roll back on rejection; external allocator/syscall/registration
    effects are outside that rollback and may already have occurred.
    """
    staged=_PageTransaction(pages);guard=image_base+0x3DEE20
    raw=_read_span(staged,guard,8)
    # Getter tests byte0 bit0; __cxa_guard_acquire then tests all of byte0.
    if not raw[0] and raw[1]!=1:
        if raw[1]&2:raise RefillUnsupported('contended/recursive shared guard is unsupported')
        if not isinstance(thread_id,int) or not 0<=thread_id<=0xFFFFFFFF:
            raise RefillUnsupported('cold shared getter requires explicit uint32 thread id')
        if register_destructor is None:
            raise RefillUnsupported('cold shared getter requires destructor registration')
        _w(staged,guard+4,thread_id,4);_w(staged,guard+1,2,1)
        construct_default_shared_reference(staged,entry_stack_address=entry_stack_address-0x40,
            image_base=image_base,allocate=allocate,free=free,
            read_property=read_property,syscall=syscall,errno_address=errno_address)
        # Native does not inspect __cxa_atexit's return.
        register_destructor(staged,image_base+0x15E1A8,guard+8,image_base+0x34C700)
        _w(staged,guard,1,1);_w(staged,guard+1,1,1)
    copy_string_reference(staged,destination_address=output_reference_address,
        source_address=guard+8)
    staged.commit();return output_reference_address


def get_environment_service_reference(pages, *, image_base, allocate, thread_id=None):
    """+0x172d40:16-byte wrapper/1-byte untouched payload/4-byte count."""
    return objects.construct_lazy_reference(pages,guard_address=image_base+0x3D18D8,
        slot_address=image_base+0x3D18D0,payload_size=1,allocate=allocate,
        initialize_payload=lambda p,a:None,thread_id=thread_id)


def get_environment_constant(pages, *, image_base, entry_offset):
    """+0x2562dc/+0x256330: lazy guest C strings, independent of X0."""
    staged=_PageTransaction(pages)
    layout={0x2562DC:(0x3DE4D0,0x98A64,0x3DE4C8,0x98CEC),
        0x256330:(0x3DE4D8,0x98A6C,0x3DE4D4,0x98CE8)}
    if entry_offset not in layout:raise RefillUnsupported('unknown environment constant getter')
    result=_lazy_constant(staged,image_base,*layout[entry_offset])
    staged.commit();return result



def _format_guest_strings(pages,format_address,argument_addresses,max_bytes):
    """Bounded printf %s/%% subset; read guest inputs on each formatter call."""
    fmt=objects._cstring(pages,format_address,max_bytes)[:-1]
    result=bytearray();i=0;argument=0
    while i<len(fmt):
        if fmt[i]!=37:result.append(fmt[i]);i+=1
        else:
            if i+1>=len(fmt):raise RefillUnsupported('incomplete printf conversion')
            conversion=fmt[i+1];i+=2
            if conversion==37:result.append(37)
            elif conversion==115:
                if argument>=len(argument_addresses) or not argument_addresses[argument]:
                    raise RefillUnsupported('missing/NULL printf string argument')
                result.extend(objects._cstring(pages,argument_addresses[argument],max_bytes)[:-1]);argument+=1
            else:raise RefillUnsupported('printf conversion outside %s/%% is unsupported')
        if len(result)>max_bytes:raise RefillUnsupported('formatted string exceeds bound')
    return bytes(result)


def format_string_object(pages, *, object_address, format_address,
        argument_addresses, image_base, allocate, reallocate, free, max_bytes=0x100000,
        prepare_format=None):
    """+0x248908 non-NULL %s/%% formatting, growth/retry/copy/cleanup.

    Restore the 16-byte temporary capacity/length/pointer allocation, initial
    buffer, strict capacity rounding, truncated vsnprintf writes and retries.
    Unsupported conversions and malloc failure fallback remain explicit.
    No formatted native output is copied into the model.
    """
    if not format_address:raise RefillUnsupported('NULL format fallback is unsupported')
    if not 1<=max_bytes<=0x100000:raise ValueError('invalid formatter bound')
    staged=_PageTransaction(pages)
    _lazy_constant(staged,image_base,0x3DE3B8,0x95EA0,0x3DE3B0,0x95EA8)
    empty_source=image_base+0x6FE64
    initial_length=len(objects._cstring(staged,empty_source,max_bytes))-1
    capacity=objects.round_string_capacity(initial_length+(2 if initial_length==0 else 1))
    if capacity>max_bytes or capacity<=initial_length:
        raise RefillUnsupported('formatter initial string exceeds bound')
    temporary=allocate(staged,16)
    if not temporary:raise RefillUnsupported('formatter temporary malloc failure is unsupported')
    _w(staged,temporary,capacity,4);_w(staged,temporary+4,initial_length,4)
    payload=allocate(staged,capacity);_w(staged,temporary+8,payload)
    if not payload:raise RefillUnsupported('formatter initial buffer failure is unsupported')
    _write_span(staged,payload,_read_span(staged,empty_source,initial_length+1))
    fmt_length=len(objects._cstring(staged,format_address,max_bytes))-1
    width=max(16,fmt_length*2)
    while True:
        if width+2>max_bytes:raise RefillUnsupported('formatter reserve exceeds bound')
        status=objects.reserve_string_fields(staged,fields_address=temporary,
            requested=width+2,allocate=allocate,reallocate=reallocate,free=free,max_bytes=max_bytes)
        if status:raise RefillUnsupported('formatter reserve failure fallback is unsupported')
        if prepare_format is not None:prepare_format(staged)
        rendered=_format_guest_strings(staged,format_address,argument_addresses,max_bytes)
        payload=_u(staged,temporary+8)
        truncated=rendered[:width]
        _write_span(staged,payload,truncated+b'\0');_write_span(staged,payload+width,b'\0')
        _w(staged,temporary+4,len(truncated),4)
        if len(truncated)<width:break
        width=len(rendered) if len(rendered)>width else width*2
    length=_u(staged,temporary+4,4)
    if length>=_u(staged,object_address+8,4):
        objects.reserve_string_fields(staged,fields_address=object_address+8,
            requested=length,allocate=allocate,reallocate=reallocate,free=free,max_bytes=max_bytes)
        length=_u(staged,temporary+4,4)
    destination=_u(staged,object_address+16);_w(staged,object_address+12,length,4)
    if destination:
        _write_span(staged,destination,_read_span(staged,_u(staged,temporary+8),length))
        _write_span(staged,destination+_u(staged,object_address+12,4),b'\0')
    else:_write_span(staged,object_address+8,bytes(8))
    objects.destroy_string_fields(staged,fields_address=temporary,free=free)
    staged.commit();return object_address


def _guest_syscall(pages,syscall,errno_address,number,*args):
    value=syscall(pages,number,tuple(a&MASK64 for a in args))
    if not isinstance(value,int) or not -(1<<63)<=value<(1<<63):
        raise RefillUnsupported('guest syscall requires signed int64 result')
    if -4095<=value<0:_w(pages,errno_address,-value,4);return -1
    return value


def ensure_environment_directory(pages, *, object_address, entry_stack_address,
        syscall, errno_address, mkdir, mode=0x1ED):
    """+0x25eb54 W2 bit0=1: bounded recursive directory probe/create."""
    staged=_PageTransaction(pages);source=_u(staged,object_address+16)
    raw=objects._cstring(staged,source,257)[:-1]
    if not raw or len(raw)>=256:
        staged.commit();return False
    buffer=entry_stack_address-0x148;stat=entry_stack_address-0x1C8
    _write_span(staged,buffer,raw+b'\0')
    if raw[-1:]==b'/':_write_span(staged,buffer+len(raw)-1,b'\0')
    def is_directory():
        result=_guest_syscall(staged,syscall,errno_address,79,0xFFFFFF9C,buffer,stat,0)
        return None if result else _u(staged,stat+0x10,4)&0xF000==0x4000
    first=is_directory()
    if first is True:
        staged.commit();return True
    index=1
    while _u(staged,buffer+index,1):
        if _u(staged,buffer+index,1)==47:
            _write_span(staged,buffer+index,b'\0')
            exists=is_directory()
            if exists is None:
                if objects._s32(mkdir(staged,buffer,mode))<0:
                    staged.commit();return False
            elif not exists:
                staged.commit();return False
            _write_span(staged,buffer+index,b'/')
        index+=1
    exists=is_directory()
    result=exists if exists is not None else objects._s32(mkdir(staged,buffer,mode))>=0
    staged.commit();return bool(result)


def construct_environment_reference(pages, *, output_reference_address,
        entry_stack_address, image_base, allocate, reallocate, free,
        read_property, syscall, errno_address, mkdir,
        thread_id=None, register_destructor=None, prepare_format=None):
    """+0x25ee84 observed default shared/getter/format/filesystem branch.

    All path content is generated from loaded guest constants and references.
    Host property/syscall/mkdir/registration callbacks are environment inputs.
    A native VM input snapshot is not required by this helper.
    """
    if entry_stack_address&15:raise RefillUnsupported('environment helper stack must be aligned')
    staged=_PageTransaction(pages)
    fmt=_lazy_constant(staged,image_base,0x3DE9A8,0x9A488,0x3DE99C,0x9A494)
    reference=entry_stack_address-0x60
    get_inline_shared_reference(staged,output_reference_address=reference,
        entry_stack_address=entry_stack_address-0x60,image_base=image_base,
        allocate=allocate,free=free,read_property=read_property,syscall=syscall,
        errno_address=errno_address,thread_id=thread_id,register_destructor=register_destructor)
    # +0x25eef4 latches the shared object before zeroing caller output.
    shared=_u(staged,reference);_write_span(staged,output_reference_address,bytes(16))
    if shared:
        obj=allocate(staged,24)
        if not obj:raise RefillUnsupported('environment operator-new NULL abort is unsupported')
        objects.construct_string_object(staged,object_address=obj,source_address=0,
            allocate=allocate,vtable_address=image_base+0x34F5F8,empty_descriptor_address=image_base+0x6E168)
        assign_owned_string_reference(staged,reference_address=output_reference_address,
            object_address=obj,image_base=image_base,allocate=allocate,free=free)
        # Native reloads shared and result pointers after all allocation effects.
        shared_string=_u(staged,_u(staged,reference)+16);result_object=_u(staged,output_reference_address)
        get_environment_service_reference(staged,image_base=image_base,allocate=allocate,thread_id=thread_id)
        first=get_environment_constant(staged,image_base=image_base,entry_offset=0x2562DC)
        get_environment_service_reference(staged,image_base=image_base,allocate=allocate,thread_id=thread_id)
        second=get_environment_constant(staged,image_base=image_base,entry_offset=0x256330)
        format_string_object(staged,object_address=result_object,format_address=fmt,
            argument_addresses=(shared_string,first,second),image_base=image_base,
            allocate=allocate,reallocate=reallocate,free=free,prepare_format=prepare_format)
        result_object=_u(staged,output_reference_address)
        exists=environment_path_exists(staged,object_address=result_object,
            syscall=syscall,errno_address=errno_address)
        if not exists:
            ensure_environment_directory(staged,object_address=result_object,
                entry_stack_address=entry_stack_address-0x60,syscall=syscall,
                errno_address=errno_address,mkdir=mkdir)
    stream.release_string_reference(staged,reference_address=reference,image_base=image_base,free=free)
    staged.commit();return output_reference_address



def prepare_bionic_format_locale(pages, *, once_address, key_address,
        generation_table, thread_pointer, wake):
    """Measured bionic uselocale(0) dependency of its vsnprintf oracle.

    This optional environment adapter is needed when comparing libc once/key,
    TLS/generation and wake effects. Pure Python formatting needs no libc.
    The caller supplies matching libc addresses; no libc is executed here.
    """
    from vm9_allocator import pthread_key_create, pthread_getspecific
    staged=_PageTransaction(pages);state=_u(staged,once_address,4)
    if not state:
        _w(staged,once_address,1,4)
        if pthread_key_create(staged,key_address=key_address,destructor=0,
                generation_table=generation_table):
            raise RefillUnsupported('bionic locale key exhaustion is unsupported')
        _w(staged,once_address,2,4)
        result=wake(staged,once_address,129,0x7FFFFFFF)
        if result not in (None,0):raise RefillUnsupported('bionic locale wake errno branch is unsupported')
    elif state!=2:raise RefillUnsupported('in-progress bionic locale once is unsupported')
    pthread_getspecific(staged,key=_u(staged,key_address,4),thread_pointer=thread_pointer,
        generation_table=generation_table)
    staged.commit()



def construct_empty_state_container(pages, *, image_base, allocate):
    """+0x24a4d8/+0x2493e8 default malloc-backed 64-byte empty container."""
    staged=_PageTransaction(pages)
    if _u(staged,image_base+0x381AA0)!=image_base+0x347FD0:
        raise RefillUnsupported('state container custom allocator is unsupported')
    address=allocate(staged,64)
    if address:
        _write_span(staged,address,bytes(64));_w(staged,address+0x18,64,4)
    staged.commit();return address


def environment_path_exists(pages, *, object_address, syscall, errno_address):
    """+0x25ddec: nonempty string and successful faccessat(R_OK)."""
    staged=_PageTransaction(pages);result=False
    if _u(staged,object_address+12,4):
        result=_guest_syscall(staged,syscall,errno_address,48,
            0xFFFFFF9C,_u(staged,object_address+16),4,0)==0
    staged.commit();return result
