"""Bounded normal Java request facade with explicit JNI and request services.

The virtual request target is read from the live receiver table. Its provider
owns request execution; this composition supplies real URL/header references
and preserves the original copy, output conversion and cleanup order.
"""
import vm9_jni_environment as environment
import vm9_jni_header_array as headers
import vm9_reference_scopes as references
import vm9_registry as registry
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported


def invoke_java_request_facade(pages, *, image_base, entry_stack_address,
        thread_pointer, thread_id, environment_pointer, facade_address,
        url_reference, header_array_reference, allocate, calloc, free,
        invoke_jni, invoke_request, diagnostic_observer=None,
        acquire_environment=None, wake_condition=None, lock_mutex=None,
        unlock_mutex=None, max_pairs=4096, max_bytes=0x100000):
    """+17b8f8 normal branch with mask 0x200 and virtual method +0x20.

    invoke_request(pages, target, **keywords) receives receiver_address,
    url_reference_address, header_reference_address, mode (0x138),
    output_reference_address (native X8), and entry_stack_address. It must
    publish a supported owning tree reference and account for its ownership.
    The alternate +2a8824 branch refuses; provider effects, physical register
    spills, concurrent execution and C++ unwind are outside page rollback.
    """
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('Java request facade requires an aligned guest stack')
    if any(type(v) is not int or not 0<=v<1<<64 for v in
            (image_base,thread_pointer,environment_pointer,facade_address,url_reference,header_array_reference)):
        raise RefillUnsupported('Java request facade pointers must fit uint64')
    if type(max_pairs) is not int or not 1<=max_pairs<=4096:
        raise RefillUnsupported('Java request facade requires a bounded pair count')
    if type(max_bytes) is not int or not 1<=max_bytes<=0x100000:
        raise RefillUnsupported('Java request facade requires bounded strings')
    if any(not callable(f) for f in (allocate,calloc,free,invoke_jni,invoke_request)):
        raise RefillUnsupported('Java request facade requires allocation/free/JNI/request services')
    def span(a,n):
        if type(a) is not int or not 0<a<=(1<<64)-n:
            raise RefillUnsupported('Java request facade address wraps uint64')
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('Java request facade storage aliases native scratch')
    p=_PageTransaction(pages);u=lambda a:int.from_bytes(_read_span(p,a,8),'little')
    span(image_base,0x3E3000);span(thread_pointer,0x30);span(facade_address,32)
    _read_span(p,facade_address,32);_read_span(p,entry_stack_address-0x1000,0x1000)
    fixed=[(image_base,0x3E3000),(thread_pointer,0x30),(facade_address,32)]
    if environment_pointer:
        span(environment_pointer,8);table=u(environment_pointer);span(table,0x748)
        fixed.extend(((environment_pointer,8),(table,0x748)))
    live=[]
    def checked_allocation(tx,n,provider):
        if type(n) is not int or not 1<=n<=max(0x800,max_bytes+32):
            raise RefillUnsupported('Java request facade allocation exceeds byte bound')
        a=provider(tx,n)
        if type(a) is not int or not 0<=a<=(1<<64)-n:
            raise RefillUnsupported('Java request facade allocator returned invalid address')
        if a:
            span(a,n);_read_span(tx,a,n)
            if any(a<b+m and b<a+n for b,m in fixed+live):
                raise RefillUnsupported('Java request facade allocation aliases active storage')
            live.append((a,n))
        return a
    def alloc(tx,n):return checked_allocation(tx,n,allocate)
    def zero(tx,count,n):
        if count!=1:raise RefillUnsupported('Java request facade calloc requires count one')
        return checked_allocation(tx,n,lambda tx,n:calloc(tx,1,n))
    def release(tx,a):
        free(tx,a);live[:]=[(b,n) for b,n in live if b!=a]
    canary=entry_stack_address-0x48
    _write_span(p,canary,_read_span(p,thread_pointer+0x28,8))
    stack=entry_stack_address-0xB0
    selected=environment.check_cold_java_switch_mask(p,image_base=image_base,
        entry_stack_address=stack,mask=0x200,acquire_environment=acquire_environment,
        invoke_jni=invoke_jni,wake_condition=wake_condition)
    if selected.matched:
        raise RefillUnsupported('alternate Java request facade +2a8824 is unrecovered')
    receiver=u(facade_address+24);result=0
    if receiver:
        span(receiver,8);table=u(receiver);span(table,0x28)
        fixed.extend(((receiver,8),(table,0x28)))
        url=entry_stack_address-0x58;tree=entry_stack_address-0x68
        url_copy=entry_stack_address-0x88;tree_copy=entry_stack_address-0x98
        returned=entry_stack_address-0x78;output_copy=entry_stack_address-0xA8
        kw=dict(image_base=image_base,entry_stack_address=stack,thread_pointer=thread_pointer,
            thread_id=thread_id,allocate=alloc,diagnostic_observer=diagnostic_observer)
        environment.convert_java_object_to_byte_reference(p,output_reference_address=url,
            environment_pointer=environment_pointer,object_reference=url_reference,
            calloc=zero,free=release,invoke_jni=invoke_jni,max_payload_bytes=max_bytes,**kw)
        headers.construct_configuration_tree_from_java_headers(p,output_reference_address=tree,
            environment_pointer=environment_pointer,array_reference=header_array_reference,
            calloc=zero,free=release,invoke_jni=invoke_jni,max_pairs=max_pairs,max_bytes=max_bytes,**kw)
        references.copy_scoped_string_reference(p,destination_address=url_copy,source_address=url,**kw)
        references.copy_scoped_string_reference(p,destination_address=tree_copy,source_address=tree,**kw)
        # Native reloads the receiver table after both reference copies.
        table=u(receiver);span(table,0x28);target=u(table+0x20);span(target,1)
        invoke_request(p,target,receiver_address=receiver,url_reference_address=url_copy,
            header_reference_address=tree_copy,mode=0x138,output_reference_address=returned,
            entry_stack_address=stack)
        registry.release_scoped_configuration_tree_reference(p,reference_address=tree_copy,
            free=release,max_nodes=max_pairs,**kw)
        references.release_scoped_string_reference(p,reference_address=url_copy,free=release,**kw)
        references.copy_scoped_string_reference(p,destination_address=output_copy,source_address=returned,**kw)
        result=headers.construct_java_header_array(p,image_base=image_base,entry_stack_address=stack,
            thread_pointer=thread_pointer,environment_pointer=environment_pointer,input_reference_address=output_copy,
            allocate=alloc,free=release,invoke_jni=invoke_jni,max_nodes=max_pairs,max_bytes=max_bytes,
            lock_mutex=lock_mutex,unlock_mutex=unlock_mutex)
        for reference in (output_copy,returned,tree):
            registry.release_scoped_configuration_tree_reference(p,reference_address=reference,
                free=release,max_nodes=max_pairs,**kw)
        references.release_scoped_string_reference(p,reference_address=url,free=release,**kw)
    if _read_span(p,canary,8)!=_read_span(p,thread_pointer+0x28,8):
        raise RefillUnsupported('Java request facade stack canary changed')
    p.commit();return result
