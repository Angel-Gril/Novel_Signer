"""Bounded compact JSON printing with original buffer allocation semantics."""
import math,struct,sys
from vm9_allocator import _PageTransaction,_read_span,_write_span,RefillUnsupported
from vm9_configuration_init import _lazy_constant


def print_json_unformatted(pages, *, node_address, entry_stack_address, image_base,
        allocate, free, prepare_format=None, max_bytes=0x100000, max_nodes=4096, max_depth=64):
    """+249af0/+2499b0 compact printer, malloc/free hooks and no reallocator.

    Values use the low type byte. Strings preserve non-ASCII bytes; finite
    numbers use 15 significant digits, then 17 if the native tolerance fails.
    Only staged pages roll back. Physical spills and external service state
    are outside this contract; native stack aliases are rejected.
    """
    if (type(entry_stack_address) is not int or not 0x4000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('JSON printer requires an aligned guest stack')
    if any(type(n) is not int or not 1<=n<=0x100000 for n in (max_bytes,max_nodes)):
        raise RefillUnsupported('JSON printer requires bounded byte and node limits')
    if type(max_depth) is not int or not 1<=max_depth<=64:
        raise RefillUnsupported('JSON printer requires a bounded recursion depth')
    if not callable(allocate) or not callable(free):
        raise RefillUnsupported('JSON printer requires allocation and free services')
    p=_PageTransaction(pages)
    def check(a,n):
        if type(a) is not int or not 0<=a<=(1<<64)-n:
            raise RefillUnsupported('JSON printer address wraps uint64')
        if a and a<entry_stack_address and a+n>entry_stack_address-0x4000:
            raise RefillUnsupported('JSON printer aliases unmodeled native spills')
    def read(a,n):check(a,n);return _read_span(p,a,n)
    def u(a,n=8):return int.from_bytes(read(a,n),'little')
    if (u(image_base+0x381AA0)!=image_base+0x347FD0 or
            u(image_base+0x381AA8)!=image_base+0x347FA0 or u(image_base+0x381AB0)):
        raise RefillUnsupported('JSON printer custom hooks or realloc are unrecovered')
    def cstring(a):
        data=bytearray()
        for i in range(max_bytes):
            value=read(a+i,1)[0];data.append(value)
            if not value:return bytes(data)
        raise RefillUnsupported('JSON printer string exceeds its byte bound')
    def new(n):
        if not 1<=n<=max(256,2*max_bytes):
            raise RefillUnsupported('JSON printer allocation exceeds its byte bound')
        a=allocate(p,n)
        if type(a) is not int or not 0<=a<(1<<64)-n:
            raise RefillUnsupported('JSON printer allocator returned an invalid address')
        if a:check(a,n)
        return a
    def constant(flag,source,dest,mask):
        return _lazy_constant(p,image_base,flag,source,dest,mask)
    pointer=new(256);capacity=256;offset=0;visited=0
    if not pointer:p.commit();return 0
    class PrintFailure(Exception):pass
    def ensure(n):
        nonlocal pointer,capacity
        needed=n+offset+1
        if n>=1<<31 or needed>max_bytes:
            raise RefillUnsupported('JSON printer output exceeds its byte bound')
        if offset>=capacity:raise RefillUnsupported('JSON printer offset exceeds capacity')
        if needed<=capacity:return pointer+offset
        size=2*needed if needed<1<<30 else 0x7FFFFFFF
        replacement=new(size)
        if not replacement:
            free(p,pointer);pointer=capacity=0;raise PrintFailure()
        _write_span(p,replacement,read(pointer,offset+1));free(p,pointer)
        pointer,capacity=replacement,size
        return pointer+offset
    def update():
        nonlocal offset
        offset+=len(cstring(pointer+offset))-1
    def string(a):
        constant(0x3DE40C,0x95EFC,0x3DE408,0x95F10)
        constant(0x3DE418,0x95F00,0x3DE410,0x95F08)
        data=cstring(a)[:-1] if a else b''
        escaped=bytearray(b'"');short={8:b'b',9:b't',10:b'n',12:b'f',13:b'r',34:b'"',92:b'\\'}
        for value in data:
            if value<32 and value not in short and prepare_format is not None:prepare_format(p)
            escaped.extend(b'\\'+short[value] if value in short else
                ('\\u%04x'%value).encode() if value<32 else bytes([value]))
        escaped.extend(b'"\0')
        out=ensure(len(escaped))
        if a and cstring(a)[:-1]!=data:
            raise RefillUnsupported('JSON printer source changed during buffer growth')
        _write_span(p,out,escaped)
    def value(a,depth,ancestors):
        nonlocal offset,visited
        null=constant(0x3DE3CC,0x95ED0,0x3DE3C4,0x95F38)
        false=constant(0x3DE3D8,0x95ED8,0x3DE3D0,0x95F30)
        true=constant(0x3DE3E4,0x95EE0,0x3DE3DC,0x95F28)
        if not a:raise PrintFailure()
        check(a,64);visited+=1
        if visited>max_nodes or depth>=max_depth or a in ancestors:
            raise RefillUnsupported('JSON printer graph exceeds its node/depth bound or is cyclic')
        kind=u(a+24,1)
        if kind in (1,2,4):
            text=cstring({1:false,2:true,4:null}[kind]);_write_span(p,ensure(len(text)),text)
        elif kind==8:
            constant(0x3DE3F0,0x95EE8,0x3DE3E8,0x95F20)
            constant(0x3DE3F8,0x95EF0,0x3DE3F4,0x95F1C)
            constant(0x3DE404,0x95EF4,0x3DE3FC,0x95F14)
            number=struct.unpack('<d',read(a+48,8))[0]
            if prepare_format is not None:prepare_format(p)
            if not math.isfinite(number):text=cstring(null)[:-1]
            else:
                text=format(number,'.15g').encode();parsed=float(text)
                if abs(number-parsed)>max(abs(number),abs(parsed))*sys.float_info.epsilon:
                    if prepare_format is not None:prepare_format(p)
                    text=format(number,'.17g').encode()
            out=ensure(len(text)+1);_write_span(p,out,text+b'\0');offset+=len(text)
        elif kind==16:string(u(a+32))
        elif kind==128:
            source=u(a+32)
            if not source:raise PrintFailure()
            data=cstring(source);out=ensure(len(data));_write_span(p,out,read(source,len(data)))
        elif kind in (32,64):
            child=u(a+16);out=ensure(1 if kind==32 else 2)
            _write_span(p,out,b'[' if kind==32 else b'{');offset+=1
            siblings=set()
            while child:
                if child in siblings:raise RefillUnsupported('JSON printer child list is cyclic')
                siblings.add(child);check(child,64)
                if kind==64:
                    string(u(child+56));update();out=ensure(1);_write_span(p,out,b':');offset+=1
                value(child,depth+1,ancestors|{a});update();following=u(child)
                if kind==64 or following:
                    out=ensure((1 if following else 0)+1)
                    _write_span(p,out,(b',' if following else b'')+b'\0');offset+=bool(following)
                child=following
            _write_span(p,ensure(2),(b']' if kind==32 else b'}')+b'\0')
        else:raise PrintFailure()
    try:
        value(node_address,0,set());update();result=new(offset+1)
        if not result:raise PrintFailure()
        _write_span(p,result,read(pointer,min(capacity,offset+1)))
        _write_span(p,result+offset,b'\0');free(p,pointer)
    except PrintFailure:
        if pointer:free(p,pointer)
        result=0
    p.commit();return result
