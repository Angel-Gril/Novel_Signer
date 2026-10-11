"""Independent ELF support constructors with explicit guest services.

Compose existing object and JNI owners from caller-owned relocated ELF pages.
Clock, allocation, property and exit registration providers stage guest effects;
they must defer external actions until the complete result is accepted.
The loader order and full JNI are separate work.
"""
from dataclasses import dataclass
import vm9_objects as objects
import vm9_jni_environment as jni
import vm9_registry as registry
import vm9_diagnostics as diagnostics
from vm9_allocator import RefillUnsupported,_PageTransaction,_read_span,_write_span

MASK64=(1<<64)-1


@dataclass(frozen=True)
class SupportConstructorResult:
    entry: int
    publication_addresses: tuple[int, ...]
    allocations: tuple[tuple[int, int], ...]
    finalizers: tuple[tuple[int, int, int, int], ...]


def run_support_constructor(pages, *, image_base, constructor_entry,
        entry_stack_address, entry_return_address=None, allocate=None,
        register_exit=None, read_clock=None, get_auxval=None, get_property=None,
        reserved_regions=(), thread_id=None):
    """Recover seven actual loader support constructors as one page transaction.

    +17319c publishes monotonic microseconds through its GOT and initializes
    the singleton table with the original incoming return address when cold.
    +180d28 clears two vectors, constructs a normal mutex and registers three
    finalizers. +1834e4 constructs the actual ELF sized string, including NULL
    malloc, and registers its GOT-selected destructor. +271940 delegates to
    the JNI cache mutex owner. +28300c publishes realtime milliseconds.
    +343a84 retains the auxv-bit/property/strncmp control branch.
    +15db50 constructs the guarded empty string and registers its destructor.
    Its uncontended C++ guard records an explicit thread_id when cold; warm
    guard paths need no allocator, registration or thread service.

    Providers receive staged pages. read_clock(p,clock_id) returns signed
    status/seconds/nanoseconds; get_property(p,name,buffer) writes the bounded
    property buffer and returns its signed length/status. Registration status
    is ignored by native, including nonzero values. Clock failure diagnostics
    are unsupported. Native saves and retired stack bytes are not outputs.
    """
    entries={0x15DB50,0x17319C,0x180D28,0x1834E4,0x271940,0x28300C,0x343A84}
    if type(constructor_entry) is not int or constructor_entry not in entries:
        raise RefillUnsupported('ELF support constructor entry is unsupported')
    if type(image_base) is not int or image_base&4095 or not 0<image_base<=MASK64-0x3E3238:
        raise RefillUnsupported('ELF support constructor image base is invalid')
    if type(entry_stack_address) is not int or entry_stack_address&15 or not 0x2000<entry_stack_address<=MASK64:
        raise RefillUnsupported('ELF support constructor requires aligned incoming SP')
    if (constructor_entry==0x17319C and
            (type(entry_return_address) is not int or not 0<entry_return_address<=MASK64)):
        raise RefillUnsupported('ELF clock constructor requires its incoming return address')
    p=_PageTransaction(pages);publications=[];allocations=[];finalizers=[]
    regions=list(reserved_regions)
    for start,end in regions:
        if type(start) is not int or type(end) is not int or not 0<=start<end<=MASK64+1:
            raise RefillUnsupported('ELF support constructor reserved region is invalid')
    def u(address,n=8):return int.from_bytes(_read_span(p,address,n),'little')
    def write(address,data,publish=False):
        if type(address) is not int or not 0<address<=MASK64 or address+len(data)>MASK64+1:
            raise RefillUnsupported('ELF support constructor output address is invalid')
        if any(address<end and start<address+len(data) for start,end in regions):
            raise RefillUnsupported('ELF support constructor output overlaps reserved storage')
        _write_span(p,address,data)
        if publish:publications.append(address)
    def word(address,value,publish=True):write(address,(value&MASK64).to_bytes(8,'little'),publish)
    def signed_status(value,label):
        if type(value) is not int or not -(1<<31)<=value<=0xFFFFFFFF:
            raise RefillUnsupported(label+' status exceeds uint32')
        value&=0xFFFFFFFF
        return value-(1<<32) if value>>31 else value
    def plan(staged,size):
        if not callable(allocate):raise RefillUnsupported('ELF support constructor requires an allocator')
        address=allocate(staged,size)
        if type(address) is not int or not 0<=address<=MASK64-size:
            raise RefillUnsupported('ELF support constructor allocation exceeds the guest ABI')
        if address:
            retained=[(image_base,image_base+0x400000),(entry_stack_address-0x1000,entry_stack_address),*regions]
            retained.extend((a,a+n) for a,n in allocations if a)
            if any(address<end and start<address+size for start,end in retained):
                raise RefillUnsupported('ELF support constructor allocation aliases retained storage')
            _read_span(staged,address,size)
        allocations.append((address,size));return address
    def register(staged,function,obj,dso):
        if not callable(register_exit):raise RefillUnsupported('ELF support constructor requires exit registration')
        status=signed_status(register_exit(staged,function,obj,dso),'exit registration')&0xFFFFFFFF
        finalizers.append((function,obj,dso,status));return status
    def clock(identifier,monotonic=False):
        if not callable(read_clock):raise RefillUnsupported('ELF support constructor requires a clock service')
        result=read_clock(p,identifier)
        if not isinstance(result,(tuple,list)) or len(result)!=3:
            raise RefillUnsupported('ELF support constructor clock result is invalid')
        status,seconds,nanoseconds=result
        if signed_status(status,'clock'):
            raise RefillUnsupported('ELF support constructor clock failure diagnostics are unsupported')
        if (type(seconds) is not int or not -(1<<63)<=seconds<(1<<63)
                or type(nanoseconds) is not int or not 0<=nanoseconds<1000000000):
            raise RefillUnsupported('ELF support constructor timespec is invalid')
        if monotonic:
            value=(seconds*1000000000+nanoseconds)&MASK64
            value=value-(1<<64) if value>>63 else value
            return (abs(value)//1000)*(-1 if value<0 else 1)
        value=(seconds*1000000+nanoseconds//1000)&MASK64
        value=value-(1<<64) if value>>63 else value
        return (abs(value)//1000)*(-1 if value<0 else 1)
    entry=constructor_entry
    if entry==0x15DB50:
        guard_address=image_base+0x3D1418;guard=_read_span(p,guard_address,8)
        if not guard[0]&1:
            mutex=image_base+0x3E2F40
            write(mutex,_read_span(p,mutex,40))
            objects.lock_uncontended_mutex(p,mutex_address=mutex)
            if guard[0] or guard[1]==1:
                objects.unlock_uncontended_mutex(p,mutex_address=mutex)
            else:
                if guard[1]!=0:
                    raise RefillUnsupported('ELF string guard recursion or wait is unsupported')
                if type(thread_id) is not int or not 0<thread_id<=0xFFFFFFFF:
                    raise RefillUnsupported('ELF cold string guard requires a nonzero uint32 thread id')
                write(guard_address+4,thread_id.to_bytes(4,'little'))
                write(guard_address+1,b'\2')
                objects.unlock_uncontended_mutex(p,mutex_address=mutex)
                address=image_base+0x3D1400;write(address,_read_span(p,address,24))
                objects.construct_string_object(p,object_address=address,source_address=0,
                    allocate=plan,vtable_address=image_base+0x34F5F8,
                    empty_descriptor_address=image_base+0x6E168)
                publications.append(address)
                register(p,u(image_base+0x374F28),address,image_base+0x34C700)
                write(guard_address,b'\1',True)
                objects.lock_uncontended_mutex(p,mutex_address=mutex)
                write(guard_address+1,b'\1')
                objects.unlock_uncontended_mutex(p,mutex_address=mutex)
    elif entry==0x17319C:
        clock_slot=u(image_base+0x374F80)
        word(clock_slot,clock(1,True))
        # Same relocated signed table index as +173470's existing getter.
        table_slot=(u(image_base+0x379968)-0xE6FDE0)&MASK64
        if not u(table_slot):word(table_slot,entry_return_address)
    elif entry==0x180D28:
        for offset in (0x3D1DA8,0x3D1DC0):
            address=image_base+offset;write(address,bytes(24),True)
            register(p,image_base+0x17D58C,address,image_base+0x34C700)
        address=image_base+0x3D1DD8;write(address,_read_span(p,address,48))
        objects.construct_normal_mutex_object(p,object_address=address,image_base=image_base)
        publications.append(address);register(p,image_base+0x165388,address,image_base+0x34C700)
    elif entry==0x1834E4:
        address=image_base+0x3D1E88;write(address,_read_span(p,address,24))
        objects.construct_sized_string_object(p,object_address=address,source_address=image_base+0x7D247,
            length=0x9B5,image_base=image_base,allocate=plan)
        publications.append(address);register(p,u(image_base+0x374F28),address,image_base+0x34C700)
    elif entry==0x271940:
        for offset,size in ((0x3DF0A8,8),(0x3DF118,48)):
            address=image_base+offset;write(address,_read_span(p,address,size))
        result=jni.initialize_java_cache_mutexes(p,image_base=image_base,allocate=plan,register_exit=register)
        publications.extend((image_base+0x3DF0A8,result.inline_mutex_object))
    elif entry==0x28300C:
        word(image_base+0x3E0B58,clock(0))
    else:
        if not callable(get_auxval):raise RefillUnsupported('ELF support constructor requires auxv service')
        value=get_auxval(p,16)
        if type(value) is not int or not 0<=value<=MASK64:
            raise RefillUnsupported('ELF support constructor auxv result is invalid')
        enabled=(value>>8)&1
        if enabled:
            if not callable(get_property):raise RefillUnsupported('ELF support constructor requires property service')
            buffer=entry_stack_address-0x6C;_read_span(p,buffer,92)
            if any(buffer<end and start<buffer+92 for start,end in regions):
                raise RefillUnsupported('ELF support constructor property scratch overlaps reserved storage')
            status=signed_status(get_property(p,image_base+0x6FEFB,buffer),'property')
            if status>0:
                for index in range(10):
                    actual=u(buffer+index,1);expected=u(image_base+0x6EC1E+index,1)
                    if actual!=expected:break
                    if not actual:enabled=0;break
                else:enabled=0
        write(image_base+0x3E3230,bytes([enabled]),True)
    p.commit()
    return SupportConstructorResult(entry,tuple(publications),tuple(allocations),tuple(finalizers))


@dataclass(frozen=True)
class ConfigurationConstructorResult:
    singleton_reference_address: int
    singleton_payload_address: int
    diagnostic_scope_addresses: tuple[int, ...]
    publication_addresses: tuple[int, ...]


def run_configuration_constructor(pages, *, image_base, entry_stack_address,
        thread_pointer, thread_id, allocate, free, read_clock, get_tls,
        initialize_registry, broadcast, parse_decimal,
        max_nodes=4096, max_bytes=0x100000, reserved_regions=()):
    """Compose actual +2679f0, including cold singleton/registry and logging.

    Decode fresh ELF constants, resolve the decimal dispatch through its
    evidenced target, perform +267444's ELF template copies and retain the
    observed cold zero-bound +276b9c copy branch. Existing registry, scoped
    TLS, ownership and diagnostic owners execute the complete constructors.
    parse_decimal(staged,source) is the explicit signed strtol service.
    OS/TLS/allocator providers must defer effects outside the staged pages.
    Nonzero copy-hook bounds and alternate dispatch targets fail closed.
    """
    if (type(image_base) is not int or image_base&4095 or not 0<image_base<=MASK64-0x3E3238
            or type(entry_stack_address) is not int or entry_stack_address&15
            or not 0x2000<entry_stack_address<=MASK64
            or type(thread_pointer) is not int or thread_pointer&7
            or not 0<thread_pointer<=MASK64-0x30
            or type(thread_id) is not int or not 0<thread_id<=0xFFFFFFFF):
        raise RefillUnsupported('ELF configuration constructor guest ABI is invalid')
    if not all(callable(f) for f in (allocate,free,read_clock,get_tls,initialize_registry,broadcast,parse_decimal)):
        raise RefillUnsupported('ELF configuration constructor requires explicit guest services')
    if type(max_nodes) is not int or not 1<=max_nodes<=4096 or type(max_bytes) is not int or not 1<=max_bytes<=0x100000:
        raise RefillUnsupported('ELF configuration constructor resource budget is invalid')
    p=_PageTransaction(pages);regions=list(reserved_regions);allocations=[];scopes=[];publications=[]
    for start,end in regions:
        if type(start) is not int or type(end) is not int or not 0<=start<end<=MASK64+1:
            raise RefillUnsupported('ELF configuration reserved region is invalid')
    def u(a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
    def write(a,data):
        if type(a) is not int or not 0<a<=MASK64 or a+len(data)>MASK64+1:
            raise RefillUnsupported('ELF configuration output address is invalid')
        if any(a<end and start<a+len(data) for start,end in regions):
            raise RefillUnsupported('ELF configuration output overlaps reserved storage')
        _write_span(p,a,data)
    def plan(staged,n):
        address=allocate(staged,n)
        if type(n) is not int or not 0<n<=max_bytes or type(address) is not int or not 0<address<=MASK64-n:
            raise RefillUnsupported('ELF configuration allocation is invalid')
        retained=[(image_base,image_base+0x400000),(entry_stack_address-0x1000,entry_stack_address),*regions,*allocations]
        if any(address<end and start<address+n for start,end in retained):
            raise RefillUnsupported('ELF configuration allocation aliases retained storage')
        _read_span(staged,address,n);allocations.append((address,address+n));return address
    def scope(staged,address,sp):
        scratch=sp-0x50
        if any(scratch<end and start<scratch+24 for start,end in regions):
            raise RefillUnsupported('ELF diagnostic scope overlaps reserved storage')
        diagnostics.enter_diagnostic_scope(staged,object_address=scratch,input_word=address,
            image_base=image_base,thread_pointer=thread_pointer,allocate=plan,thread_id=thread_id)
        diagnostics.leave_diagnostic_scope(staged,object_address=scratch,
            image_base=image_base,thread_pointer=thread_pointer)
        scopes.append(scratch)
    # Validate the caller frame before any shared owner writes within it.
    _read_span(p,entry_stack_address-0x1000,0x1000)
    if any(entry_stack_address-0x1000<end and start<entry_stack_address for start,end in regions):
        raise RefillUnsupported('ELF configuration caller frame overlaps reserved storage')
    for source,mask,destination,flag in (
            (0x9D7EC,0x9D81C,0x3DECF4,0x3DECFC),
            (0x9D7BC,0x9D848,0x3DEC64,0x3DEC70),
            (0x9D7C8,0x9D83C,0x3DEC88,0x3DEC94),
            (0x9D7D4,0x9D830,0x3DECAC,0x3DECB8),
            (0x9D7E0,0x9D824,0x3DECD0,0x3DECDC)):
        if not u(image_base+flag,4):
            address=image_base+destination
            # These destinations occupy disjoint fixed 24-byte global slots.
            write(address,_read_span(p,address,24))
            objects.decode_masked_bytes(p,source_address=image_base+source,
                destination_address=address,mask_address=image_base+mask,max_bytes=24)
            write(image_base+flag,(1).to_bytes(4,'little'))
        if destination==0x3DECF4:
            value=parse_decimal(p,image_base+destination)
            if type(value) is not int or not -(1<<63)<=value<(1<<63):
                raise RefillUnsupported('ELF decimal dispatch result exceeds signed64')
            instruction=u(image_base+0x267CB0,4)
            if instruction&0xFFC003FF!=0x91000100:
                raise RefillUnsupported('ELF decimal dispatch instruction is unsupported')
            adjustment=(instruction>>10)&4095
            if image_base+0x267CE4-(value>>2)+adjustment!=image_base+0x267CE4:
                raise RefillUnsupported('ELF decimal dispatch selects an unsupported target')
    reference=registry.get_singleton136_reference(p,entry_stack_address=entry_stack_address-0x1F0,
        image_base=image_base,allocate=plan,free=free,read_clock=read_clock,get_tls=get_tls,
        initialize_registry=initialize_registry,broadcast=broadcast,thread_id=thread_id,
        max_nodes=max_nodes,max_bytes=max_bytes,diagnostic_scope=scope)
    payload=u(reference.wrapper_address)
    if not payload or u(payload+0x10) or u(payload+0x18):
        raise RefillUnsupported('ELF constructor copy hook requires zero singleton bounds')
    pc=image_base+0x267444
    index=(((((~pc|0xA060400A021040)&0xA061440A061440)+(pc&0x10400040400))|0x1010104)^0xFF5F9EBBF421C8D4)&MASK64
    def template(offset,n):
        address=(u(image_base+0x3822F8+offset)+index)&MASK64
        return _read_span(p,address,n)
    # These selectors also drive the original decoder/publication addresses.
    # Keep that fixed global layout explicit; template +20 is decoded data.
    for offset,destination in ((8,0x3DEC64),(0x10,0x3DEC74),(0x20,0x3DEC88),
            (0x28,0x3DEC98),(0x38,0x3DECAC),(0x40,0x3DECBC),
            (0x50,0x3DECD0),(0x58,0x3DECE0),(0x60,0x3DEC70)):
        if (u(image_base+0x3822F8+offset)+index)&MASK64!=image_base+destination:
            raise RefillUnsupported('ELF configuration global selector layout is unsupported')
    def immediate(low,high):
        first,second=u(image_base+low,4),u(image_base+high,4)
        if first&0xFFE0001F!=0x52800000|(first&31) or second&0xFFE0001F!=0x72A00000|(first&31):
            raise RefillUnsupported('ELF constructor publication immediate grammar is unsupported')
        return ((first>>5)&65535)|(((second>>5)&65535)<<16)
    for offset,local in ((0,entry_stack_address-0x180),(0x30,entry_stack_address-0x1A0),(0x48,entry_stack_address-0x1B0)):
        write(local,template(offset,16))
    for destination,source,n in (
            (entry_stack_address-0x178,image_base+0x3DEC64,8),
            (image_base+0x3DEC74,entry_stack_address-0x180,16),
            (entry_stack_address-0x198,image_base+0x3DECAC,8),
            (image_base+0x3DECBC,entry_stack_address-0x1A0,16),
            (entry_stack_address-0x1A8,image_base+0x3DECD0,8),
            (image_base+0x3DECE0,entry_stack_address-0x1B0,16)):
        write(destination,_read_span(p,source,n))
        if image_base<=destination<image_base+0x400000:publications.append(destination)
    value=immediate(0x26791C,0x267924).to_bytes(4,'little')
    for offset in (0x3DEC84,0x3DECCC,0x3DECF0):write(image_base+offset,value);publications.append(image_base+offset)
    write(image_base+0x3DEC98,template(0x18,8)+template(0x20,8));publications.append(image_base+0x3DEC98)
    write(image_base+0x3DECA8,immediate(0x267944,0x267948).to_bytes(4,'little'));publications.append(image_base+0x3DECA8)
    # Shared owners also stage global writes. Validate their final changes
    # against caller reservations before any page reaches the caller.
    for page in p:
        start=page<<12
        for low,high in regions:
            first,last=max(start,low),min(start+4096,high)
            if first<last and _read_span(p,first,last-first)!=_read_span(pages,first,last-first):
                raise RefillUnsupported('ELF configuration shared owner changed reserved storage')
    p.commit()
    return ConfigurationConstructorResult(reference.wrapper_address,payload,tuple(scopes),tuple(publications))
