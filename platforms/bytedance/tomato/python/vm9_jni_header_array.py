"""Bounded +271384 configuration tree to Java header array composition.

Cold class lookup requires explicit serial lock services. Tree traversal, C++/JNI UTF
conversion and reference cleanup retain their existing owners. JNI/provider
ledgers and mapping effects are outside guest-page transaction rollback.
"""
import vm9_registry as registry
import vm9_objects as objects
import vm9_jni_environment as environment
from vm9_configuration_init import _lazy_constant
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported


def construct_java_header_array(pages, *, image_base, entry_stack_address,
        thread_pointer, environment_pointer, input_reference_address,
        allocate, free, invoke_jni, max_nodes=4096, max_bytes=0x100000,
        lock_mutex=None, unlock_mutex=None):
    """+271384: ordered key/value UTF strings, array stores, reference release.

    Model the class cache and original lazy class-name decode. The
    iterator and initialized UTF fields are declared stack state. Physical
    register spills, untouched SSO padding and host concurrency are separate.
    Input reference and value pointers are read live around JNI effects.
    """
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('header array requires an aligned guest stack')
    if any(type(v) is not int or not 0<=v<1<<64 for v in
            (image_base,thread_pointer,environment_pointer,input_reference_address)):
        raise RefillUnsupported('header array inputs must fit uint64')
    if type(max_nodes) is not int or not 1<=max_nodes<=4096:
        raise RefillUnsupported('header array requires a bounded tree')
    if type(max_bytes) is not int or not 1<=max_bytes<=0x100000:
        raise RefillUnsupported('header array requires bounded strings')
    if any(not callable(f) for f in (allocate,free,invoke_jni)):
        raise RefillUnsupported('header array requires explicit allocation/free/JNI services')
    def span(a,n):
        if type(a) is not int or not 0<a<=(1<<64)-n:
            raise RefillUnsupported('header array address wraps uint64')
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('header array input aliases native spills')
    p=_PageTransaction(pages)
    def u(a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
    def write(a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
    span(thread_pointer,0x30);span(image_base,0x3DF118)
    canary=entry_stack_address-0x68
    _write_span(p,canary,_read_span(p,thread_pointer+0x28,8))
    _lazy_constant(p,image_base,0x3DF094,0xA5910,0x3DF080,0xA5930)
    def finish(result):
        if _read_span(p,canary,8)!=_read_span(p,thread_pointer+0x28,8):
            raise RefillUnsupported('header array stack canary changed')
        p.commit();return result
    if not environment_pointer:return finish(0)
    span(environment_pointer,8);table=u(environment_pointer);span(table,0x748)
    span(input_reference_address,16);container=u(input_reference_address)
    if not container:return finish(0)
    cached_class=u(image_base+0x3DF110)
    if not cached_class:
        if not callable(lock_mutex) or not callable(unlock_mutex):
            raise RefillUnsupported('header array cold String class requires explicit lock/unlock services')
        mutex=image_base+0x3DF120;span(image_base+0x3DF118,48)
        status=lock_mutex(p,mutex_address=mutex)
        if type(status) is not int or status!=0:
            raise RefillUnsupported('header array class cache lock failure is unrecovered')
        if not u(image_base+0x3DF110):
            local=environment._invoke_jni(p,environment_pointer,0x30,(image_base+0x3DF080,),invoke_jni)
            # +26f0ec checks after FindClass, clears and discards on low-byte
            # exception. It does not obtain or delete an exception reference.
            if environment._invoke_jni(p,environment_pointer,0x720,(),invoke_jni)&255:
                environment._invoke_jni(p,environment_pointer,0x88,(),invoke_jni);local=0
            if local:
                retained=environment.retain_global_jni_reference(p,environment_pointer=environment_pointer,
                    reference=local,invoke_jni=invoke_jni)
                write(image_base+0x3DF110,retained)
        status=unlock_mutex(p,mutex_address=mutex)
        if type(status) is not int or status!=0:
            raise RefillUnsupported('header array class cache unlock failure is unrecovered')
        cached_class=u(image_base+0x3DF110)
        if not cached_class:return finish(0)
        container=u(input_reference_address)
    span(container,40)
    registry._ConfigurationTree(p,container,image_base,max_nodes,max_bytes)
    count=registry.configuration_tree_size(p,container_address=container)
    array=environment._invoke_jni(p,environment_pointer,0x560,(count*2,cached_class,0),invoke_jni)
    end=entry_stack_address-0x90;begin=entry_stack_address-0xA0;copy=entry_stack_address-0xB0
    pair_copy=entry_stack_address-0x78;visited=set();live=[];current=[]
    def iterator(destination,position):
        address=u(input_reference_address);span(address,40)
        words=registry.configuration_tree_iterator(p,container_address=address,image_base=image_base,position=position)
        _write_span(p,destination,b''.join(v.to_bytes(8,'little') for v in words))
    iterator(end,'end');iterator(begin,'begin')
    fixed=((environment_pointer,8),(table,0x748),(input_reference_address,16),
        (thread_pointer,0x30),(container,40),(image_base+0x3DF080,0x98))
    def checked_allocate(tx,n):
        if type(n) is not int or not 1<=n<=max_bytes+32:
            raise RefillUnsupported('header array allocation exceeds byte bound')
        a=allocate(tx,n)
        if type(a) is not int or not 0<=a<=(1<<64)-n:
            raise RefillUnsupported('header array allocator returned invalid address')
        if a:
            span(a,n);_read_span(tx,a,n)
            if any(a<b+m and b<a+n for b,m in fixed+tuple(current)+tuple(live)):
                raise RefillUnsupported('header array allocation aliases active storage')
            live.append((a,n))
        return a
    def checked_free(tx,a):
        free(tx,a);live[:]=[(b,n) for b,n in live if b!=a]
    def utf(object_address,pair):
        span(object_address,24);source=u(object_address+16)
        current[:]=[(pair,16),(object_address,24)]
        if source:
            span(source,1);raw=objects._cstring(p,source,max_bytes+1);span(source,len(raw))
            current.append((source,len(raw)))
        return environment.construct_java_utf_string(p,entry_stack_address=entry_stack_address-0xB0,
            environment_pointer=environment_pointer,source_address=source,allocate=checked_allocate,
            free=checked_free,invoke_jni=invoke_jni,max_bytes=max_bytes)
    index=0
    while not registry.configuration_tree_iterators_equal(p,first_address=begin,second_address=end):
        node=u(begin+8)
        if node in visited or len(visited)>=max_nodes or u(begin)!=image_base+0x381B20:
            raise RefillUnsupported('header array iterator exceeds recovered tree boundary')
        visited.add(node)
        _write_span(p,copy,_read_span(p,begin,16));_write_span(p,pair_copy,_read_span(p,copy,16))
        pair=registry.configuration_tree_iterator_pair(p,iterator_address=pair_copy);span(pair,16)
        key=utf(u(pair),pair)
        value=utf(u(pair+8),pair)
        environment._invoke_jni(p,environment_pointer,0x570,(array,index,key),invoke_jni)
        environment._invoke_jni(p,environment_pointer,0x570,(array,index+1,value),invoke_jni)
        environment.release_java_reference(p,environment_pointer=environment_pointer,reference=key,invoke_jni=invoke_jni)
        environment.release_java_reference(p,environment_pointer=environment_pointer,reference=value,invoke_jni=invoke_jni)
        if u(begin)!=image_base+0x381B20:
            raise RefillUnsupported('header array provider changed iterator dispatch')
        registry.advance_configuration_tree_iterator(p,iterator_address=begin,max_nodes=max_nodes)
        index+=2
    return finish(array)
