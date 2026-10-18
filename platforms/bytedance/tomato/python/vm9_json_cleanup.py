"""Bounded default-hook JSON tree and deleting-object cleanup."""
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported


def delete_json_object(pages, *, object_address, entry_stack_address, image_base,
        free, protected_ranges=(), max_nodes=4096, max_depth=64):
    """+2614ec/+2614d4/+2490e0: children, value, key, node, then wrapper.

    Bit8 marks references; bit9 marks constant keys. Preserve the saved next
    pointer and native flag/key/hook reloads after provider calls. Payloads
    are opaque free arguments, never scanned as strings. Reject repeated
    ownership and overlap with known node/wrapper/protected ranges. Model
    pages roll back on failure; external free effects do not. No X0 promise
    is made for this void destructor or for physical register/stack spills.
    """
    if (type(image_base) is not int or not 0<=image_base<=(1<<64)-0x400000):
        raise RefillUnsupported('JSON delete requires a bounded image address')
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('JSON delete requires an aligned native stack')
    if (type(max_nodes) is not int or not 1<=max_nodes<=4096 or
            type(max_depth) is not int or not 1<=max_depth<=64):
        raise RefillUnsupported('JSON delete requires bounded nodes and depth')
    if not callable(free):raise RefillUnsupported('JSON delete requires an explicit free service')
    def check(a,n):
        if type(a) is not int or not 0<a<=(1<<64)-n:
            raise RefillUnsupported('JSON delete address wraps uint64')
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('JSON delete aliases unmodeled native spills')
    def overlap(a,n,b,m):return a<b+m and b<a+n
    protected=tuple(protected_ranges)
    for a,n in protected:
        if type(n) is not int or n<1:raise RefillUnsupported('invalid JSON delete protected range')
        check(a,n)
    check(object_address,16)
    if any(overlap(object_address,16,a,n) for a,n in protected):
        raise RefillUnsupported('JSON delete wrapper aliases protected input')
    protected+=((object_address,16),)
    p=_PageTransaction(pages);nodes=set();freed=set();node_ranges=[]
    def read(a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
    def release(a,*,node=False):
        check(a,1)
        if a in freed or (not node and any(b<=a<b+64 for b in nodes)):
            raise RefillUnsupported('JSON delete repeats or aliases ownership')
        if any(b<=a<b+n for b,n in protected):
            raise RefillUnsupported('JSON delete payload aliases protected input or wrapper')
        if read(image_base+0x381AA8)!=image_base+0x347FA0:
            raise RefillUnsupported('JSON delete custom free hook is unrecovered')
        freed.add(a);free(p,a)
    def delete(first,depth):
        current=first
        while current:
            if depth>max_depth or len(nodes)>=max_nodes or current in nodes or current in freed:
                raise RefillUnsupported('JSON delete graph repeats ownership or exceeds its bound')
            check(current,64)
            if any(overlap(current,64,a,n) for a,n in protected+tuple(node_ranges)):
                raise RefillUnsupported('JSON delete node aliases a known object or input')
            nodes.add(current);node_ranges.append((current,64))
            flags=read(current+24,4);following=read(current)
            if not flags&0x100:
                child=read(current+16)
                if child:delete(child,depth+1);flags=read(current+24,4)
            if not flags&0x100:
                value=read(current+32)
                if value:release(value);flags=read(current+24,4)
            if not flags&0x200:
                key=read(current+56)
                if key:release(key)
            release(current,node=True);current=following
    root=read(object_address+8)
    _write_span(p,object_address,(image_base+0x35BA58).to_bytes(8,'little'))
    delete(root,1)
    free(p,object_address)
    p.commit()
