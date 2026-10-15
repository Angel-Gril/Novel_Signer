"""Guest identifier seed, formatter and cached reference from +25bd8c.

File operations are explicit providers. Matching guest state, guards, locks,
strings and reference scopes retain their existing owners. Page rollback does
not undo external provider effects; physical ABI/PAC and concurrency are unproved.
"""
from vm9_allocator import _PageTransaction,RefillUnsupported,_read_span,_write_span
from vm9_configuration_init import _u,_w,_lazy_constant
import vm9_objects as objects
import vm9_reference_scopes as references
MASK64=(1<<64)-1


def _stack(address):
    if type(address) is not int or not 0x1000<=address<=MASK64 or address&15:
        raise RefillUnsupported('identifier requires an aligned guest stack')
    return address


def advance_identifier_state(pages, *, image_base):
    """+255ec0: update two X64 words and return their wrapped sum."""
    p=_PageTransaction(pages);state=objects._image_address(image_base,0x3DE470)
    x,y=_u(p,state),_u(p,state+8)
    x^=(x<<23)&MASK64
    value=x^y^(y>>5)^(x>>18)
    _w(p,state,y);_w(p,state+8,value)
    result=(value+y)&MASK64
    p.commit();return result


def initialize_identifier_seed(pages, *, image_base,file_services):
    """+255cb4: lazy file path/mode, fopen, fread16 and fclose.

    Preserve partial reads and ignore fclose status. A NULL file or a read
    count other than16 returns -1; the factory still publishes its guard.
    """
    if file_services is None or any(not callable(file_services.get(k)) for k in ('fopen','fread','fclose')):
        raise RefillUnsupported('identifier seed requires explicit file providers')
    p=_PageTransaction(pages)
    path=_lazy_constant(p,image_base,0x3DE460,0x97EB8,0x3DE450,0x97F6C)
    mode=_lazy_constant(p,image_base,0x3DE468,0x97EC8,0x3DE464,0x97F68)
    handle=file_services['fopen'](p,path,mode)
    if type(handle) is not int or not 0<=handle<=MASK64:
        raise RefillUnsupported('identifier fopen result must fit uint64')
    result=-1
    if handle:
        count=file_services['fread'](p,image_base+0x3DE470,1,16,handle)
        if type(count) is not int or not 0<=count<=MASK64:
            raise RefillUnsupported('identifier fread result must fit size_t')
        status=file_services['fclose'](p,handle)
        if type(status) is not int:
            raise RefillUnsupported('identifier fclose result must be an integer')
        result=0 if count&0xFFFFFFFF==16 else -1
    p.commit();return result


def generate_identifier(pages, *, output_address,entry_stack_address,image_base,
        max_template_bytes=256):
    """+255d84: two state advances, low nibble first, guest template/alphabet.

    The16-byte entropy scratch is retained at entry SP-0x50. Re-read template
    and alphabet bytes in order, including aliases. Refuse templates beyond
    the explicit byte bound or32 placeholders (unmodeled physical spill reads).
    """
    _stack(entry_stack_address)
    if type(max_template_bytes) is not int or not 0<=max_template_bytes<=0x100000:
        raise ValueError('invalid identifier template bound')
    p=_PageTransaction(pages)
    template=_lazy_constant(p,image_base,0x3DE4A8,0x97ED0,0x3DE480,0x97F40)
    alphabet=_lazy_constant(p,image_base,0x3DE4C4,0x97F00,0x3DE4B0,0x97F20)
    scratch=entry_stack_address-0x50
    _w(p,scratch,advance_identifier_state(p,image_base=image_base))
    _w(p,scratch+8,advance_identifier_state(p,image_base=image_base))
    nibbles=0
    for index in range(max_template_bytes+1):
        char=_u(p,template+index,1)
        if not char:
            _w(p,output_address+index,0,1);p.commit();return index
        if index==max_template_bytes:
            raise RefillUnsupported('identifier template exceeds the explicit bound')
        if char in (0x78,0x79):
            if nibbles>=32:raise RefillUnsupported('identifier template reads unmodeled entropy spills')
            byte=_u(p,scratch+(nibbles>>1),1)
            nibble=(byte>>(4 if nibbles&1 else 0))&15
            char=_u(p,alphabet+(8+(nibble&3) if char==0x79 else nibble),1)
            nibbles+=1
        _w(p,output_address+index,char,1)
    raise AssertionError('unreachable identifier formatter bound')


def _guard(p,address,image,thread_id,observer,initialize):
    if not _u(p,address,1)&1 and objects.acquire_static_initialization_guard(p,
            guard_address=address,image_base=image,thread_id=thread_id,observer=observer):
        initialize()
        objects.release_static_initialization_guard(p,guard_address=address,image_base=image,observer=observer)


def construct_identifier_reference(pages, *, output_reference_address,
        entry_stack_address,image_base,thread_pointer,allocate,file_services,
        thread_id=None,diagnostic_observer=None,max_template_bytes=256):
    """+25bce4: initialize seed once, construct the string and owning pair."""
    stack=_stack(entry_stack_address)-0x60;p=_PageTransaction(pages)
    _guard(p,image_base+0x3DE718,image_base,thread_id,diagnostic_observer,
        lambda:initialize_identifier_seed(p,image_base=image_base,file_services=file_services))
    generate_identifier(p,output_address=stack,entry_stack_address=stack,
        image_base=image_base,max_template_bytes=max_template_bytes)
    string=objects._allocate(p,allocate,24)
    objects.construct_string_object(p,object_address=string,source_address=stack,allocate=allocate,
        vtable_address=image_base+0x34F5F8,empty_descriptor_address=image_base+0x6E168,
        max_source_bytes=max_template_bytes)
    references.construct_scoped_string_reference(p,reference_address=output_reference_address,
        string_address=string,entry_stack_address=stack,image_base=image_base,
        thread_pointer=thread_pointer,allocate=allocate,thread_id=thread_id,
        diagnostic_observer=diagnostic_observer)
    p.commit();return string


def copy_cached_identifier_reference(pages, *, output_reference_address,
        entry_stack_address,image_base,thread_pointer,allocate,free,file_services=None,
        thread_id=None,diagnostic_observer=None,max_template_bytes=256):
    """+25bd8c: two lazy slots, retained normal mutex and cached string pair.

    Clear/copy output before checking NULL, then construct/assign/release a
    temporary and publish the cache. No host file is opened implicitly.
    Direct output aliases into physical spills are conservatively refused.
    """
    entry=_stack(entry_stack_address);stack=entry-0x70;p=_PageTransaction(pages)
    if output_reference_address<entry and output_reference_address+16>entry-0x1000:
        raise RefillUnsupported('identifier output aliases unmodeled native spills')
    def mutex_init():
        pointer=objects._allocate(p,allocate,48)
        objects.construct_normal_mutex_object(p,object_address=pointer,image_base=image_base)
        _w(p,image_base+0x3DE720,pointer)
    def cache_init():
        pointer=objects._allocate(p,allocate,16)
        _write_span(p,pointer,bytes(16));_w(p,image_base+0x3DE730,pointer)
    _guard(p,image_base+0x3DE728,image_base,thread_id,diagnostic_observer,mutex_init)
    _guard(p,image_base+0x3DE738,image_base,thread_id,diagnostic_observer,cache_init)
    owner=_u(p,image_base+0x3DE720);guard=stack+0x20;vtable=image_base+0x34C778
    _w(p,guard,vtable);_w(p,guard+8,owner)
    def normal(lock,address):
        if diagnostic_observer is not None:diagnostic_observer('pthread_mutex_lock' if lock else 'pthread_mutex_unlock',address)
        operation=objects.lock_uncontended_mutex if lock else objects.unlock_uncontended_mutex
        return operation(p,mutex_address=address)
    _w(p,guard+16,normal(True,owner+8),4)
    kw=dict(entry_stack_address=stack,image_base=image_base,thread_pointer=thread_pointer,
        allocate=allocate,thread_id=thread_id,diagnostic_observer=diagnostic_observer)
    references.copy_scoped_string_reference(p,destination_address=output_reference_address,
        source_address=_u(p,image_base+0x3DE730),**kw)
    if not _u(p,output_reference_address):
        temporary=stack+0x10
        construct_identifier_reference(p,output_reference_address=temporary,
            file_services=file_services,max_template_bytes=max_template_bytes,**kw)
        references.assign_scoped_string_reference(p,destination_address=output_reference_address,
            source_address=temporary,free=free,**kw)
        references.release_scoped_string_reference(p,reference_address=temporary,free=free,**kw)
        references.assign_scoped_string_reference(p,destination_address=_u(p,image_base+0x3DE730),
            source_address=output_reference_address,free=free,**kw)
    _w(p,guard,vtable)
    if not _u(p,guard+16,4):normal(False,_u(p,guard+8)+8)
    p.commit();return output_reference_address


def apply_request_identifier_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,**services):
    """+2886b0 retains packed X0, loads only target/X8, no packed store."""
    _stack(entry_stack_address);p=_PageTransaction(pages)
    target=_u(p,argument_block_address);output=_u(p,argument_block_address+8)
    if target!=image_base+0x25BD8C:raise RefillUnsupported('unexpected identifier callback target')
    if argument_block_address<entry_stack_address and argument_block_address+16>entry_stack_address-0x1000:
        raise RefillUnsupported('identifier packed input aliases unmodeled native spills')
    copy_cached_identifier_reference(p,output_reference_address=output,
        entry_stack_address=entry_stack_address-16,image_base=image_base,**services)
    p.commit();return output
