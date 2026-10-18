"""Bounded +263174 configuration parser and scoped string lookup caller."""
import vm9_objects as objects
import vm9_configuration_init as configuration
import vm9_reference_scopes as references
import vm9_diagnostics as diagnostics
from vm9_parser import parse_configuration_caller
from vm9_allocator import _PageTransaction,_read_span,_write_span,RefillUnsupported


def lookup_configuration_reference(pages, *, output_reference_address,
        configuration_address, key_object_address, entry_stack_address,
        image_base, thread_pointer, vm_module, allocate, reallocate, free,
        get_singleton, thread_id=None, diagnostic_observer=None,
        protected_ranges=(), max_entries=4096, max_bytes=0x100000):
    """Parse the live source with the first publication key and select a value.

    Entry SP is the wrapper's SP, before its 16-byte LR save. The two NULL
    references, parser caller and deleting cleanup retain their existing
    owners. Explicit parser diagnostic services use the recovered scope owner.
    Whole physical ABI and external provider rollback are outside this contract.
    """
    if (type(entry_stack_address) is not int or not 0x8000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('configuration lookup requires an aligned guest stack')
    if (type(max_entries) is not int or not 1<=max_entries<=4096 or
            type(max_bytes) is not int or not 1<=max_bytes<=0x100000):
        raise RefillUnsupported('configuration lookup requires bounded entries and bytes')
    if not all(callable(fn) for fn in (allocate,reallocate,free,get_singleton)):
        raise RefillUnsupported('configuration lookup requires allocation and singleton services')
    def check(a,n):
        if type(a) is not int or not 0<a<=(1<<64)-n:
            raise RefillUnsupported('configuration lookup address wraps uint64')
        if a<entry_stack_address and a+n>entry_stack_address-0x8000:
            raise RefillUnsupported('configuration lookup aliases unmodeled native spills')
    fixed=((output_reference_address,16),(configuration_address,88),(key_object_address,24),*protected_ranges)
    for a,n in fixed:check(a,n)
    if any(output_reference_address<a+n and a<output_reference_address+16 for a,n in fixed[1:]):
        raise RefillUnsupported('configuration lookup output aliases input')
    p=_PageTransaction(pages)
    def read(a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
    def checked_allocate(tx,n):
        a=allocate(tx,n)
        if type(a) is not int or not 0<=a<=(1<<64)-n:
            raise RefillUnsupported('configuration lookup allocator returned an invalid address')
        if a:
            check(a,n)
            if any(a<b+m and b<a+n for b,m in fixed):
                raise RefillUnsupported('configuration lookup allocation aliases input or output')
        return a
    def checked_free(tx,a):
        if a:check(a,1)
        free(tx,a)
    frame=entry_stack_address-0xC0
    first,parser_key=frame+0x58,frame+0x48
    source_copy,key_copy,parsed=frame+0x28,frame+0x18,frame+0x38
    _read_span(p,frame-0x2000,0x20C0)
    _write_span(p,frame+0x68,_read_span(p,thread_pointer+0x28,8))
    scope=dict(entry_stack_address=frame,image_base=image_base,thread_pointer=thread_pointer,
        allocate=checked_allocate,thread_id=thread_id,diagnostic_observer=diagnostic_observer)
    references.construct_scoped_string_reference(p,reference_address=first,string_address=0,**scope)
    references.construct_scoped_string_reference(p,reference_address=parser_key,string_address=0,**scope)
    container=read(configuration_address+0x48)
    if container:
        check(container,0x30)
        if configuration.publication_container_size(p,container_address=container,image_base=image_base,max_nodes=max_entries):
            # +25c734/+24b6d0 returns table plus first node; +25c744 dereferences it.
            table=image_base+0x381AB8
            if read(table+8)!=image_base+0x24B848:
                raise RefillUnsupported('configuration lookup iterator dereference is unrecovered')
            controller=read(container+0x28);sentinel=read(controller);node=read(sentinel)
            check(node,24);entry=read(node+16);check(entry,24)
            obj=checked_allocate(p,24)
            if not obj:raise RefillUnsupported('configuration lookup operator-new NULL abort is unsupported')
            length=read(entry+12,4);data=read(entry+16)
            if length>max_bytes:raise RefillUnsupported('configuration publication key exceeds its bound')
            if data:check(data,length)
            objects.construct_sized_string_object(p,object_address=obj,source_address=data,length=length,
                image_base=image_base,allocate=checked_allocate)
            references.assign_scoped_owned_string_reference(p,reference_address=parser_key,string_address=obj,free=checked_free,**scope)
    references.copy_scoped_string_reference(p,destination_address=source_copy,
        source_address=configuration_address+8,**scope)
    references.copy_scoped_string_reference(p,destination_address=key_copy,source_address=parser_key,**scope)
    parse_configuration_caller(p,first_argument=source_copy,second_argument=key_copy,
        third_argument=configuration_address+0x28,output_address=parsed,entry_stack_address=frame,
        return_address=image_base+0x2632B4,thread_pointer=thread_pointer,image_base=image_base,
        vm_module=vm_module,allocate=checked_allocate,reallocate=reallocate,free=checked_free,
        get_singleton=get_singleton,diagnostic_services=dict(thread_pointer=thread_pointer,
            thread_id=thread_id,observer=diagnostic_observer))
    references.release_scoped_string_reference(p,reference_address=key_copy,free=checked_free,**scope)
    references.release_scoped_string_reference(p,reference_address=source_copy,free=checked_free,**scope)
    body=read(parsed)
    if body:
        check(body,16);message=read(body+8);check(message,104)
        index=0
        while True:
            count=read(message+88)
            if count>max_entries:raise RefillUnsupported('configuration lookup entry bound exceeded')
            if index>=count:break
            array=read(message+96);check(array,count*8);item=read(array+index*8);check(item,40)
            cstring=read(item+24)
            if cstring:check(cstring,len(objects._cstring(p,cstring,max_bytes+1)))
            objects.construct_string_object(p,object_address=frame,source_address=cstring,
                allocate=checked_allocate,vtable_address=image_base+0x34F5F8,
                empty_descriptor_address=image_base+0x6E168,max_source_bytes=max_bytes)
            matched=configuration.strings_equal(p,first_object=frame,second_object=key_object_address,max_bytes=max_bytes)
            objects.destroy_string_object(p,object_address=frame,image_base=image_base,free=checked_free)
            if matched:
                obj=checked_allocate(p,24)
                if not obj:raise RefillUnsupported('configuration lookup result allocation abort is unsupported')
                array=read(message+96);check(array,(index+1)*8);item=read(array+index*8);check(item,40)
                cstring=read(item+32)
                if cstring:check(cstring,len(objects._cstring(p,cstring,max_bytes+1)))
                objects.construct_string_object(p,object_address=obj,source_address=cstring,
                    allocate=checked_allocate,vtable_address=image_base+0x34F5F8,
                    empty_descriptor_address=image_base+0x6E168,max_source_bytes=max_bytes)
                references.assign_scoped_owned_string_reference(p,reference_address=first,string_address=obj,free=checked_free,**scope)
                break
            index+=1
        references.copy_scoped_string_reference(p,destination_address=output_reference_address,source_address=first,**scope)
    else:
        references.construct_scoped_string_reference(p,reference_address=output_reference_address,string_address=0,**scope)
    # +2627d8 uses the same diagnostic frame as the string-reference release,
    # with parsed-object deletion supplied by its existing semantic owner.
    cleanup=frame-0x40
    diagnostics.enter_diagnostic_scope(p,object_address=cleanup,input_word=read(parsed),image_base=image_base,
        thread_pointer=thread_pointer,thread_id=thread_id,allocate=checked_allocate,observer=diagnostic_observer)
    configuration.release_parsed_reference(p,reference_address=parsed,image_base=image_base,free=checked_free)
    diagnostics.leave_diagnostic_scope(p,object_address=cleanup,image_base=image_base,
        thread_pointer=thread_pointer,observer=diagnostic_observer)
    references.release_scoped_string_reference(p,reference_address=parser_key,free=checked_free,**scope)
    references.release_scoped_string_reference(p,reference_address=first,free=checked_free,**scope)
    p.commit();return output_reference_address
