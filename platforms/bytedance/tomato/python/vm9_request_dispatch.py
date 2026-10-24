"""Signer-child request routing with explicit callback execution services.

The child owns callback iteration and fallback selection. Its callback ABI
uses URL/header references, a uint32 mode, context and an X8 result reference.
The provider owns callback execution, including any request VM.
"""
import vm9_objects as objects
import vm9_registry as registry
import vm9_reference_scopes as references
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported
from vm9_effects import require_effect_journal


def _invoke_signer_child_request_impl(pages, *, image_base, entry_stack_address,
        thread_pointer, receiver_address, url_reference_address,
        header_reference_address, mode, output_reference_address,
        allocate, free, invoke_callback, thread_id=None,
        diagnostic_observer=None, max_callbacks=4096, max_nodes=4096):
    """+27dd04, bounded serial shared-reader path for the measured child type.

    invoke_callback(pages, target, **keywords) receives url_reference_address,
    header_reference_address, mode, context_address, output_reference_address
    and entry_stack_address. It publishes an owning tree reference. Original
    reference copies, result assignment and cleanup execute around each call.
    Unknown iterator/receiver types and excessive traversal refuse. Contention,
    physical spills, C++ unwind and external provider rollback are unverified.
    """
    if (type(entry_stack_address) is not int or
            not 0x1000<=entry_stack_address<1<<64 or entry_stack_address&15):
        raise RefillUnsupported('request dispatcher requires an aligned guest stack')
    if any(type(v) is not int or not 0<=v<1<<64 for v in
            (image_base,thread_pointer,receiver_address,url_reference_address,
             header_reference_address,mode,output_reference_address)):
        raise RefillUnsupported('request dispatcher ABI words must fit uint64')
    if any(type(n) is not int or not 1<=n<=4096 for n in (max_callbacks,max_nodes)):
        raise RefillUnsupported('request dispatcher requires explicit traversal bounds')
    if any(not callable(f) for f in (allocate,free,invoke_callback)):
        raise RefillUnsupported('request dispatcher requires allocation/free/callback services')
    def span(a,n):
        if not a or a>(1<<64)-n:
            raise RefillUnsupported('request dispatcher address wraps uint64')
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('request dispatcher input aliases native scratch')
    p=_PageTransaction(pages);u=lambda a:int.from_bytes(_read_span(p,a,8),'little')
    for a,n in ((image_base,0x3E3000),(thread_pointer,0x30),(receiver_address,40),
            (url_reference_address,16),(header_reference_address,16),(output_reference_address,16)):
        span(a,n)
    _read_span(p,entry_stack_address-0x1000,0x1000)
    if u(receiver_address)!=objects._image_address(image_base,0x35D5F0):
        raise RefillUnsupported('unrecovered request dispatcher receiver type')
    stack=entry_stack_address-0x160;guard=entry_stack_address-0x88
    canary=entry_stack_address-0x70
    _write_span(p,canary,_read_span(p,thread_pointer+0x28,8))
    mutex=u(receiver_address+8);span(mutex,0x98)
    _write_span(p,guard,objects._word(image_base+0x34C758)+objects._word(mutex))
    objects.acquire_uncontended_shared_reader(p,mutex_address=mutex+8)
    _write_span(p,mutex+0x94,b'\x01');_write_span(p,guard+16,bytes(4))
    kw=dict(image_base=image_base,entry_stack_address=stack,thread_pointer=thread_pointer,
        thread_id=thread_id,allocate=allocate,diagnostic_observer=diagnostic_observer)
    references.construct_scoped_string_reference(p,reference_address=output_reference_address,
        string_address=0,**kw)
    container=u(receiver_address+0x10);span(container,40)
    if u(container)!=image_base+0x35B828:
        raise RefillUnsupported('unrecovered request callback container type')
    current=entry_stack_address-0xA8;end=entry_stack_address-0x98
    for a,position in ((end,'end'),(current,'begin')):
        pair=registry.configuration_tree_iterator(p,container_address=container,
            image_base=image_base,position=position)
        _write_span(p,a,b''.join(objects._word(v) for v in pair))
    def invoke(pair,fallback=False):
        span(pair,16);target=u(pair)
        if not target:return
        span(target,1)
        url=entry_stack_address-(0xE8 if fallback else 0xC8)
        tree=entry_stack_address-(0xF8 if fallback else 0xD8)
        result=entry_stack_address-0xB8
        references.copy_scoped_string_reference(p,destination_address=url,
            source_address=url_reference_address,**kw)
        references.copy_scoped_string_reference(p,destination_address=tree,
            source_address=header_reference_address,**kw)
        # Fallback pair and both contexts are read again after the copies.
        if fallback:pair=u(receiver_address+0x20);span(pair,16)
        invoke_callback(p,target,url_reference_address=url,header_reference_address=tree,
            mode=mode&0xFFFFFFFF,context_address=u(pair+8),
            output_reference_address=result,entry_stack_address=stack)
        registry.assign_scoped_configuration_tree_reference(p,
            destination_address=output_reference_address,source_address=result,
            free=free,max_nodes=max_nodes,**kw)
        for reference in (result,tree):
            registry.release_scoped_configuration_tree_reference(p,
                reference_address=reference,free=free,max_nodes=max_nodes,**kw)
        references.release_scoped_string_reference(p,reference_address=url,free=free,**kw)
    seen=set()
    while not registry.configuration_tree_iterators_equal(p,first_address=current,second_address=end):
        node=u(current+8);span(node,40)
        if node in seen or len(seen)>=max_callbacks:
            raise RefillUnsupported('cyclic or excessive request callback traversal')
        seen.add(node)
        invoke(registry.configuration_tree_iterator_pair(p,iterator_address=current))
        if u(output_reference_address):break
        # A traversal may also visit the sentinel after the last callback node.
        registry.advance_configuration_tree_iterator(p,iterator_address=current,max_nodes=max_callbacks+1)
    if not u(output_reference_address):invoke(u(receiver_address+0x20),True)
    _write_span(p,guard,objects._word(image_base+0x34C758))
    if not int.from_bytes(_read_span(p,guard+16,4),'little'):
        mutex=u(guard+8)
        if not _read_span(p,mutex+0x94,1)[0]:
            raise RefillUnsupported('request dispatcher writer-mode release is unrecovered')
        objects.release_uncontended_shared_reader(p,mutex_address=mutex+8)
    if _read_span(p,canary,8)!=_read_span(p,thread_pointer+0x28,8):
        raise RefillUnsupported('request dispatcher stack canary changed')
    p.commit()


def invoke_signer_child_request(*args, effect_journal=None, **kwargs):
    """Run child dispatch with an optional provider-effect transaction.

    The child owns a page transaction, while callback providers may mutate an
    allocator/JNI/OS owner. An explicit journal makes a later child failure
    undo those effects in the same LIFO scope; default calls retain the prior
    page-only behavior.
    """
    effect_journal = require_effect_journal(effect_journal)
    if effect_journal is None:
        return _invoke_signer_child_request_impl(*args, **kwargs)
    with effect_journal.transaction():
        return _invoke_signer_child_request_impl(*args, **kwargs)
