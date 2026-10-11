"""Bounded ELF64/AArch64 image loading with explicit symbol services.

Parse program headers and dynamic metadata from caller-owned bytes. No section
headers, native execution, captured process state or implicit dependency loads
are required. Symbol providers supply addresses and must defer external effects.
"""
from dataclasses import dataclass
from struct import unpack_from
from vm9_allocator import RefillUnsupported

MASK64=(1<<64)-1

@dataclass(frozen=True)
class ElfSymbolRequest:
    name: str
    version: str | None
    dependency: str | None
    weak: bool
    symbol_type: int

@dataclass(frozen=True)
class ElfLoadSegment:
    address: int
    file_size: int
    memory_size: int
    flags: int

@dataclass(frozen=True)
class ElfImageResult:
    pages: dict[int, bytearray]
    segments: tuple[ElfLoadSegment, ...]
    page_permissions: tuple[tuple[int, int], ...]
    init_array: tuple[int, ...]
    fini_array: tuple[int, ...]
    init_function: int
    fini_function: int
    dependencies: tuple[str, ...]
    exports: tuple[tuple[str, int], ...]
    imported_bindings: tuple[tuple[ElfSymbolRequest, int], ...]
    relocation_counts: tuple[tuple[int, int], ...]


def load_elf_image(data, *, image_base, resolve_symbol,
        max_image_bytes=64*1024*1024, max_relocations=1048576,
        max_symbols=65536):
    """Load one ELF image and eagerly bind ABS64/GLOB_DAT/JUMP_SLOT/RELATIVE.

    Return newly owned pages and effective PT_LOAD/GNU_RELRO permissions.
    Each undefined symbol is resolved once by resolve_symbol(ElfSymbolRequest).
    None or zero denotes an absent weak symbol; unresolved strong symbols reject
    the complete result. Dependencies and symbol versions are explicit metadata;
    this function never loads a file, invokes an initializer or changes a caller
    mapping. TLS, IFUNC, REL/RELR and Android packed relocations are unsupported.
    """
    def require(condition,message):
        if not condition:raise RefillUnsupported('ELF image '+message)
    require(isinstance(data,(bytes,bytearray)),'requires binary bytes')
    data=bytes(data)
    require(type(image_base) is int and 0<image_base<=MASK64 and not image_base&4095,'base is invalid')
    require(all(type(v) is int and 0<v<=limit for v,limit in (
        (max_image_bytes,256*1024*1024),(max_relocations,1048576),(max_symbols,1048576))),'budget is invalid')
    require(callable(resolve_symbol),'requires a symbol provider')
    def file(offset,size):
        require(0<=offset<=len(data) and 0<=size<=len(data)-offset,'file range is truncated')
        return data[offset:offset+size]
    header=file(0,64)
    require(header[:7]==b'\x7fELF\x02\x01\x01','class, byte order or identity is unsupported')
    kind,machine,version,entry,phoff,_,_,ehsize,phsize,phnum,_,_,_=unpack_from('<HHIQQQIHHHHHH',header,16)
    require((kind,machine,version,ehsize,phsize)==(3,183,1,64,56) and 1<=phnum<=256,'header is unsupported')
    file(phoff,phnum*phsize)
    loads=[];dynamic=[];relro=[]
    for i in range(phnum):
        pt,flags,offset,address,_,filesz,memsz,align=unpack_from('<IIQQQQQQ',data,phoff+i*56)
        if pt==1:
            require(0<memsz and filesz<=memsz and address<=MASK64-memsz,'load range is invalid')
            require(address+memsz<=max_image_bytes and image_base<=MASK64-address-memsz,'load exceeds address or image budget')
            require(flags&~7==0 and not flags&3==3,'load permissions are unsupported')
            require(align in (0,1) or align&(align-1)==0,'load alignment is invalid')
            require(align in (0,1) or offset%align==address%align,'file and virtual alignment differ')
            file(offset,filesz);loads.append((address,memsz,offset,filesz,flags))
        elif pt==2:dynamic.append((address,filesz))
        elif pt==0x6474E552:relro.append((address,memsz))
        elif pt==7:raise RefillUnsupported('ELF image PT_TLS is unsupported')
    require(loads and len(dynamic)==1,'requires load segments and one dynamic table')
    loads.sort()
    require(all(a+n<=b for (a,n,*_),(b,*_) in zip(loads,loads[1:])),'load segments overlap')
    def in_memory(address,size):
        return any(a<=address and size<=n-(address-a) for a,n,_,_,_ in loads)
    def read(address,size):
        for a,_,offset,n,_ in loads:
            if a<=address and 0<=size<=n-(address-a):return file(offset+address-a,size)
        raise RefillUnsupported('ELF image metadata is outside file-backed loads')
    def number(address,width=8):return int.from_bytes(read(address,width),'little')
    tags={};needed=[];terminated=False
    da,dn=dynamic[0];require(dn and dn%16==0 and dn<=65536,'dynamic range is invalid')
    for i in range(dn//16):
        tag,value=unpack_from('<qQ',read(da+i*16,16))
        if tag==0:terminated=True;break
        if tag==1:needed.append(value)
        else:
            require(tag not in tags,'dynamic tag is duplicated');tags[tag]=value
    require(terminated,'dynamic table has no terminator')
    require(22 not in tags and not tags.get(30,0)&4,'text relocations are unsupported')
    require(not any(tags.get(t,0) for t in (17,18,19,35,36,37,0x6000000F,0x60000010,0x60000011,0x60000012)),
        'REL, RELR or packed relocations are unsupported')
    require(5 in tags and 10 in tags and 6 in tags and tags.get(11)==24,'symbol metadata is missing')
    strings=read(tags[5],tags[10]);require(len(strings)<=max_image_bytes,'string table exceeds budget')
    def string(offset):
        require(offset<len(strings),'symbol string offset is invalid')
        end=strings.find(b'\0',offset);require(end>=0,'symbol string is unterminated')
        try:return strings[offset:end].decode('utf-8')
        except UnicodeDecodeError:raise RefillUnsupported('ELF image symbol string encoding is unsupported')
    if 4 in tags:
        buckets,symbol_count=unpack_from('<II',read(tags[4],8))
        require(buckets<=max_symbols and 1<=symbol_count<=max_symbols,'hash count exceeds budget')
        read(tags[4]+8,4*(buckets+symbol_count))
    else:
        require(0x6FFFFEF5 in tags,'symbol count hash is missing')
        address=tags[0x6FFFFEF5]
        buckets,first,bloom,_=unpack_from('<IIII',read(address,16))
        require(0<buckets<=max_symbols and 0<bloom<=max_symbols and first<=max_symbols,'GNU hash count exceeds budget')
        address+=16+bloom*8;read(address,buckets*4)
        symbol_count=first;chain_reads=0
        for i in range(buckets):
            index=number(address+i*4,4)
            if not index:continue
            require(first<=index<max_symbols,'GNU hash bucket is invalid')
            while True:
                require(index<max_symbols,'GNU hash chain exceeds budget')
                chain_reads+=1;require(chain_reads<=max_symbols,'GNU hash work exceeds budget')
                value=number(address+buckets*4+(index-first)*4,4)
                index+=1;symbol_count=max(symbol_count,index)
                if value&1:break
        require(symbol_count>0,'symbol table is empty')
    symbol_data=read(tags[6],symbol_count*24)
    versions={};seen=set();vn=tags.get(0x6FFFFFFE,0);vcount=tags.get(0x6FFFFFFF,0)
    require(0<=vcount<=1024 and bool(vn)==bool(vcount),'version dependency metadata is invalid')
    for index in range(vcount):
        require(vn not in seen,'version dependency chain is cyclic');seen.add(vn)
        version,count,name,aux,next_vn=unpack_from('<HHIII',read(vn,16))
        require(version==1 and 0<count<=1024,'version dependency header is unsupported')
        dependency=string(name);va=vn+aux;auxseen=set()
        for j in range(count):
            require(va not in auxseen,'symbol version chain is cyclic');auxseen.add(va)
            _,_,vid,name,next_va=unpack_from('<IHHII',read(va,16))
            vid&=0x7FFF;require(vid>1 and vid not in versions,'symbol version index is invalid')
            versions[vid]=(string(name),dependency)
            require(bool(next_va)==(j<count-1),'symbol version chain length differs');va+=next_va
        require(bool(next_vn)==(index<vcount-1),'version dependency chain length differs');vn+=next_vn
    require(not tags.get(0x6FFFFFFC,0),'versioned export definitions are unsupported')
    versym=read(tags[0x6FFFFFF0],symbol_count*2) if 0x6FFFFFF0 in tags else bytes(symbol_count*2)
    cache={};exports=[]
    def symbol(index):
        require(0<=index<symbol_count,'relocation symbol index is invalid')
        name,info,other,section,value,size=unpack_from('<IBBHQQ',symbol_data,index*24)
        return string(name),info>>4,info&15,other,section,value,size
    for i in range(1,symbol_count):
        name,bind,kind,other,section,value,size=symbol(i)
        if section and bind in (1,2) and kind in (0,1,2) and not other&3:
            address=value if section==0xFFF1 else image_base+value
            require(section==0xFFF1 or in_memory(value,max(1,size)),'export is outside loads')
            exports.append((name,address))
    def address_of(index):
        name,bind,kind,_,section,value,size=symbol(index)
        require(bind in (0,1,2) and kind in (0,1,2),'relocation symbol type or binding is unsupported')
        if section==0xFFF1:return value
        if section:
            require(section<0xFF00 and in_memory(value,max(1,size)),'defined symbol is outside loads')
            return image_base+value
        require(index and name and bind in (1,2),'undefined symbol is invalid')
        vid=int.from_bytes(versym[index*2:index*2+2],'little')&0x7FFF
        require(vid<=1 or vid in versions,'symbol version is unresolved')
        version,dependency=versions.get(vid,(None,None))
        request=ElfSymbolRequest(name,version,dependency,bind==2,kind)
        if request not in cache:
            address=resolve_symbol(request)
            if address is None:address=0
            require(type(address) is int and 0<=address<=MASK64,'symbol provider returned an invalid address')
            require(address or request.weak,'strong symbol is unresolved')
            cache[request]=address
        return cache[request]
    relocation_rows=[];counts={};targets=set()
    for address,size in ((tags.get(7,0),tags.get(8,0)),(tags.get(23,0),tags.get(2,0))):
        require(bool(address)==bool(size) and size%24==0,'relocation table is invalid')
        if not size:continue
        require(tags.get(9)==24 and (address!=tags.get(23) or tags.get(20)==7),'relocation format is unsupported')
        require(len(relocation_rows)+size//24<=max_relocations,'relocation count exceeds budget')
        for offset in range(0,size,24):
            target,info,addend=unpack_from('<QQq',read(address+offset,24));kind=info&0xFFFFFFFF;index=info>>32
            require(kind in (257,1025,1026,1027) and in_memory(target,8),'relocation kind or target is unsupported')
            require(target not in targets,'relocation target is duplicated');targets.add(target)
            require(kind!=1027 or index==0,'relative relocation has a symbol')
            relocation_rows.append((target,index,kind,addend));counts[kind]=counts.get(kind,0)+1
    pages={};permissions={}
    for address,memsz,offset,filesz,flags in loads:
        for a in range((image_base+address)&~4095,(image_base+address+memsz+4095)&~4095,4096):
            pages.setdefault(a>>12,bytearray(4096));permissions[a]=permissions.get(a,0)|flags
        require(len(pages)*4096<=max_image_bytes,'mapped pages exceed budget')
        content=memoryview(file(offset,filesz));start=image_base+address;position=0
        while position<len(content):
            n=min(len(content)-position,4096-(start&4095))
            pages[start>>12][start&4095:(start&4095)+n]=content[position:position+n]
            position+=n;start+=n
    def write(address,value):
        raw=value.to_bytes(8,'little');start=image_base+address
        for i,byte in enumerate(raw):pages[(start+i)>>12][(start+i)&4095]=byte
    for target,index,kind,addend in relocation_rows:
        value=image_base if kind==1027 else address_of(index)
        write(target,(value+addend)&MASK64)
    for address,size in relro:
        # Linkers may extend RELRO through unmapped padding to their maximum
        # page alignment. Protect only pages belonging to PT_LOAD segments.
        require(size>0 and in_memory(address,1) and address+size<=max(a+n for a,n,_,_,_ in loads),
            'RELRO range is outside the image reservation')
        for a in range((image_base+address)&~4095,(image_base+address+size)&~4095,4096):
            if a in permissions:permissions[a]&=~2
    def executable(address):
        return any(image_base+a<=address<image_base+a+n and flags&1 for a,n,_,_,flags in loads)
    def array(address_tag,size_tag):
        address,size=tags.get(address_tag,0),tags.get(size_tag,0)
        require(bool(address)==bool(size) and size%8==0 and size//8<=4096,'initializer array is invalid')
        if not size:return ()
        require(in_memory(address,size),'initializer array is outside loads')
        result=[]
        for offset in range(0,size,8):
            start=image_base+address+offset
            value=int.from_bytes(bytes(pages[(start+i)>>12][(start+i)&4095] for i in range(8)),'little')
            require(executable(value),'initializer entry is outside executable loads');result.append(value)
        return tuple(result)
    init,fini=tags.get(12,0),tags.get(13,0)
    require(all(not v or executable(image_base+v) for v in (init,fini)),'init/fini function is invalid')
    require(not entry or executable(image_base+entry),'entry point is invalid')
    return ElfImageResult(pages,tuple(ElfLoadSegment(image_base+a,f,n,flags) for a,n,_,f,flags in loads),
        tuple(sorted(permissions.items())),array(25,27),array(26,28),image_base+init if init else 0,
        image_base+fini if fini else 0,tuple(string(n) for n in needed),tuple(exports),
        tuple(cache.items()),tuple(sorted(counts.items())))
