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
