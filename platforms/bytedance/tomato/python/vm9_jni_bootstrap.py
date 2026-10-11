"""Actual JNI_OnLoad composition from a constructed, linked guest ELF."""
from dataclasses import dataclass
import vm9_objects as objects
import vm9_registry as registry
import vm9_jni_environment as environment
import vm9_startup as startup
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported,_PageTransaction,_read_span,_write_span

MASK64=(1<<64)-1

@dataclass(frozen=True)
class JniOnLoadResult:
    jni_version: int
    environment_pointer: int
    switch_word: int | None
    startup_entry: int | None
    startup_result: object
    finalizer_queue_address: int
    finalizer_callable_address: int
    elapsed_microseconds: int


def run_jni_onload(pages, *, image_base, entry_stack_address, entry_return_address,
        java_vm_address, thread_pointer, thread_id, allocate, free, read_clock,
        get_tls, initialize_registry, broadcast, parse_decimal, register_exit,
        register_thread_destructor, invoke_javavm, invoke_jni, wake_condition,
        create_thread, signal_condition, vm_module,
        max_steps=100000, max_depth=64, max_nodes=4096, reserved_regions=()):
    """Compose original +27b41c through JNI return with exactly one startup.

    Existing owners execute JavaVM publication, JNI registration, cold switch,
    conditional main-thread startup and callback cleanup. Caller pages must
    contain all successful ELF constructors and linked symbols. Guest services
    are explicit; thread creation queues workers for the caller's scheduler.
    Nonzero self-copy bounds and unsupported dispatch/code checks fail closed.
    Service providers must stage external effects until the result is accepted.
    """
    def fail(message):raise RefillUnsupported('JNI bootstrap '+message)
    if (type(image_base) is not int or image_base&4095 or not 0<image_base<=MASK64-0x400000
            or type(entry_stack_address) is not int or entry_stack_address&15 or not 0x10000<entry_stack_address<=MASK64
            or type(entry_return_address) is not int or not 0<entry_return_address<=MASK64
            or type(java_vm_address) is not int or not 0<java_vm_address<=MASK64-8
            or type(thread_pointer) is not int or thread_pointer&7 or not 0<thread_pointer<=MASK64-0x30
            or type(thread_id) is not int or not 0<thread_id<=0xFFFFFFFF):fail('guest ABI is invalid')
    services=(allocate,free,read_clock,get_tls,initialize_registry,broadcast,parse_decimal,register_exit,
        register_thread_destructor,invoke_javavm,invoke_jni,wake_condition,create_thread,signal_condition)
    if not all(callable(f) for f in services):fail('requires explicit guest services')
    if (type(max_steps) is not int or not 1<=max_steps<=1000000 or type(max_depth) is not int or not 1<=max_depth<=64
            or type(max_nodes) is not int or not 1<=max_nodes<=4096):fail('resource budget is invalid')
    p=_PageTransaction(pages);base=image_base;SP=entry_stack_address;body=SP-0x200
    regions=list(reserved_regions)
    for a,b in regions:
        if type(a) is not int or type(b) is not int or not 0<=a<b<=MASK64+1:fail('reserved region is invalid')
    if any(SP-0x9000<b and a<SP for a,b in regions):fail('caller frame overlaps reserved storage')
    _read_span(p,SP-0x9000,0x9000);canary=_read_span(p,thread_pointer+0x28,8)
    def u(a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
    def w(a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))
    def decode(source,dest,mask,flag,max_bytes=64):
        if not u(base+flag,4):
            objects.decode_masked_bytes(p,source_address=base+source,destination_address=base+dest,
                mask_address=base+mask,max_bytes=max_bytes)
            w(base+flag,1,4)
    def singleton(sp):
        r=registry.get_singleton136_reference(p,image_base=base,entry_stack_address=sp,
            allocate=allocate,free=free,read_clock=read_clock,get_tls=get_tls,
            initialize_registry=initialize_registry,broadcast=broadcast,thread_id=thread_id,max_nodes=max_nodes)
        payload=u(r.wrapper_address)
        if not payload or u(payload+0x10) or u(payload+0x18):fail('requires zero singleton copy bounds')
        return payload
    if u(base+0x375010)!=base+0x27B41C:fail('defined JNI GOT binding is invalid')
    decode(0xA61E8,0x3E0764,0xA6244,0x3E076C,8)
    singleton(SP-0x90);singleton(SP-0x90)
    outer=SP-0x90;_write_span(p,outer,bytes(64));w(outer,java_vm_address)
    number=parse_decimal(p,base+0x3E0764)
    if type(number) is not int or not -(1<<63)<=number<(1<<63) or number>>2!=0x522:fail('outer decimal dispatch is unsupported')
    pc=base+0x27B7A8
    delta=(((((~pc|0xA060400A021040)&0xA061440A061440)+(pc&0x10400040400))|0x1010104)^0xFF5F9EBBF5D685DC)&MASK64
    def selector(offset):return (u(base+0x382890+offset)+delta)&MASK64
    for offset,expected in ((0,0x3E0764),(8,0x3E0770),(0x10,0x3E076C),(0x18,0xA61E8),
            (0x20,0xA6244),(0x28,0x3E0794),(0x30,0xA61F0),(0x38,0xA6220)):
        if selector(offset)!=base+expected:fail('encoded constant selector is unsupported')
    # The first flags share the outer wrapper's decoder; the class text has
    # its own dynamic-table layout. Resolve it directly from fresh ELF words.
    if not u(selector(0x28),4):
        objects.decode_masked_bytes(p,source_address=selector(0x30),destination_address=selector(8),
            mask_address=selector(0x38),max_bytes=64)
        w(selector(0x28),1,4)
    singleton(body);singleton(body)
    function=u(base+0x375010);instruction=u(function,4)
    if instruction!=0xA9BC7BFD:fail('JNI entry code check is unsupported')
    w(body+0xA0,instruction,4);w(body+0x90,0)
    vm_table=u(java_vm_address);vm_get=u(vm_table+0x30)
    status=invoke_javavm(p,vm_get,(java_vm_address,body+0x90,0x10006))
    if type(status) is not int or not -(1<<31)<=status<=0xFFFFFFFF:fail('GetEnv status exceeds uint32')
    env=u(body+0x90);chosen=word=result=None;finalizer_queue=finalizer_callable=0
    if status&0xFFFFFFFF:version=0xFFFFFFFF
    else:
        ref=registry.get_registry320_reference(p,image_base=base,entry_stack_address=body,
            allocate=allocate,free=free,read_clock=read_clock,get_tls=get_tls,
            initialize_registry=initialize_registry,broadcast=broadcast,thread_id=thread_id,max_nodes=max_nodes)
        payload=u(ref.wrapper_address);state=u(payload+0x130)
        w(base+0x3D1990,u(state,4)^u(state+4,4),4);w(state+8,u(state+8)|4)
        block=body+0x50;_write_span(p,block,bytes(64));w(block,java_vm_address)
        number=parse_decimal(p,selector(0))
        if type(number) is not int or not -(1<<63)<=number<(1<<63) or number>>2!=0x522:fail('publication decimal dispatch is unsupported')
        environment.publish_java_vm_callback(p,image_base=base,entry_stack_address=body,
            argument_block_address=block,saved_frame_pointer=body+0xE0,return_address=base+0x27BCA0,
            saved_x20=body,saved_x19=java_vm_address)
        environment.initialize_java_dispatch(p,image_base=base,entry_stack_address=body,
            environment_pointer=env,class_name_address=selector(8),invoke_jni=invoke_jni)
        def acquire(staged,*,entry_stack_address,output_pair_address):
            return environment.acquire_thread_environment(staged,image_base=base,entry_stack_address=entry_stack_address,
                output_pair_address=output_pair_address,get_tls=get_tls,
                register_destructor=register_thread_destructor,invoke_javavm=invoke_javavm)
        switch=environment.check_cold_java_switch_mask(p,image_base=base,entry_stack_address=body,
            mask=0x200,acquire_environment=acquire,invoke_jni=invoke_jni,wake_condition=wake_condition)
        word=switch.switch.switch_word;chosen=0x2A0028 if switch.matched else 0x28040C
        if switch.matched:
            result=alternative.initialize_startup_caller(p,image_base=base,entry_stack_address=body,
                thread_pointer=thread_pointer,allocate=allocate,free=free,create_thread=create_thread,
                register_destructor=register_exit,thread_id=thread_id,signal_condition=signal_condition,
                max_steps=max_steps,max_depth=max_depth,reserved_regions=regions)
        else:
            result=startup.initialize_startup_caller(p,image_base=base,entry_stack_address=body,
                return_address=base+0x27BCC0,thread_pointer=thread_pointer,vm_module=vm_module,
                allocate=allocate,create_thread=create_thread,register_destructor=register_exit,
                thread_id=thread_id,signal_condition=signal_condition,saved_frame_pointer=body+0xE0,
                saved_x19=java_vm_address,saved_x28=delta,max_steps=max_steps)
        _write_span(p,body+0x10,bytes(64))
        number=parse_decimal(p,selector(0))
        if type(number) is not int or not -(1<<63)<=number<(1<<63) or number>>2!=0x522:fail('cleanup decimal dispatch is unsupported')
        # +27bed8 -> +27bf1c -> +204098 submits the JNI finalizer callable
        # to the second queue. +294340 is the adapter's incidental X1,
        # rather than its actual callback. Recover the incoming frame and
        # inline vtable from the original constructor instructions.
        singleton(body-0x30)
        source=body-0x80
        w(source,base+0x34F010);w(source+0x20,source)
        executor=startup.submit_default_callable(p,source_address=source,scratch_address=body-0x200,
            image_base=base,allocate=allocate,create_thread=create_thread,
            register_destructor=register_exit,thread_id=thread_id,
            signal_condition=signal_condition,queue_index=1)
        startup.destroy_callable(p,object_address=source,image_base=base,free=free)
        finalizer_queue=u(executor+8);finalizer_callable=u(finalizer_queue+0x18)
        if u(u(base+0x375010),4)!=instruction:fail('JNI entry changed during startup')
        w(body,instruction,4);version=0x10006
    if _read_span(p,thread_pointer+0x28,8)!=canary:fail('TLS stack canary changed')
    status,seconds,nanos=read_clock(p,1)
    if status or type(seconds) is not int or not -(1<<63)<=seconds<(1<<63) or type(nanos) is not int or not 0<=nanos<1000000000:
        fail('monotonic clock result is unsupported')
    time=(seconds*1000000000+nanos)&MASK64
    signed=time-(1<<64) if time>>63 else time
    micros=(abs(signed)//1000)*(-1 if signed<0 else 1)
    elapsed=(micros-u(base+0x3D17C8))&MASK64;w(base+0x3D17C8,elapsed)
    for page in p:
        start=page<<12
        for a,b in regions:
            low,high=max(start,a),min(start+4096,b)
            if low<high and _read_span(p,low,high-low)!=_read_span(pages,low,high-low):fail('changed reserved storage')
    returned=JniOnLoadResult(version,env,word,chosen,result,finalizer_queue,finalizer_callable,elapsed)
    p.commit();return returned
