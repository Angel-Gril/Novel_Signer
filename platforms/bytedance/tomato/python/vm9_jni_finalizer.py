"""JNI finalizer queue body, delayed submission and joinable guest exit.

The supported serial path observes two absent files, rejected sigaction,
uncontended probe mutex and explicit successful temporary mapping services.
Copied code is recovered as bounded self-modifying counter semantics; its
actual bytes stay in the caller's ELF. External provider effects must be
staged by the caller. No host executable pages or threads are created.
"""
from dataclasses import dataclass
import hashlib
from vm9_allocator import _PageTransaction,_read_span,_write_span,RefillUnsupported,GuestOS
import vm9_registry as registry
import vm9_objects as objects
import vm9_startup as startup
import vm9_jni_environment as environment
import vm9_thread_exit as thread_exit
import vm9_timed_tasks as timed

MASK64=(1<<64)-1

@dataclass(frozen=True)
class FinalizerResult:
    probe_result: int
    image_vm_steps: int
    copy_bound: int
    submission: timed.TimedTaskSubmission

@dataclass(frozen=True)
class FinalizerWorkerResult:
    return_code: int
    finalizer: FinalizerResult
    exit_result: thread_exit.GuestThreadExitResult

def _system(p,provider,number,values):
    result=provider(p,number,values)
    if type(result) is not int or not -(1<<63)<=result<=MASK64:
        raise RefillUnsupported('finalizer raw system result is outside the guest ABI')
    return result if result<1<<63 else result-(1<<64)

def _u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def _w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))

def _run_image_vm(p,base,sp,payload,vm_module,max_steps):
    C=sp-0x380;E=sp-0x30;backing=E-0x118;pc=base+0x203DA0
    delta=(((((~pc|0xA060400A021040)&0xA061440A061440)+(pc&0x10400040400))|0x1010104)^0xFF5F9EBBF5F8D8E4)&MASK64
    entry,a,b=[(_u(p,base+0x37D410+i*8)+delta)&MASK64 for i in range(3)]
    callback=base+0x2043D4;ret=base+0x203EA8
    if (entry,a,b)!=(base+0x89D20,base+0x34F150,base+0x34F160):raise RefillUnsupported('unknown image VM tables')
    for adr,val in ((C,payload),(C+0x10,callback),(C+0x18,E),(C+0x20,ret),(backing,0),
        (backing+4*8,C),(backing+5*8,a),(backing+6*8,b),(backing+7*8,callback),
        (backing+29*8,(E-0x130)&~15),(backing+31*8,ret),(E-0x120,entry)):
        _w(p,adr,val)
    class Memory(vm_module.Mem):
        def __init__(self,pages):self.pages=pages
        def _pg(self,address):
            if address>>12 not in self.pages:raise RefillUnsupported('unmapped finalizer VM page')
            return self.pages[address>>12]
    old=vm_module.B
    try:
        vm_module.B=base;vm=vm_module.VM(Memory(p),entry-base,0,0,0,callback,ret,maxsteps=max_steps)
        vm.R=[_u(p,backing+i*8) for i in range(32)];vm.register_backing_base=backing
        vm._vm_tmp32=_u(p,backing+0x100);vm._vm_tmp33=_u(p,backing+0x108)
        def native(current,function,arg):
            if function!=base+0x204504 or _u(p,arg)!=base+0x2946B0:
                raise RefillUnsupported('unknown finalizer image callback')
            if not _u(p,base+0x3E1D58,1)&1:raise RefillUnsupported('uncached finalizer page size')
            _w(p,arg+8,_u(p,base+0x3E1D50,4),4)
        vm.native_hook=native
        exited=False
        try:vm.run()
        except vm_module.VMExit:exited=True
        except RuntimeError as error:
            if vm.steps>max_steps:raise RefillUnsupported('finalizer image VM budget exhausted') from error
            raise
        if not exited or vm.pc!=base+0x89E70:raise RefillUnsupported('finalizer image VM did not reach its recovered exit')
        result=_u(p,C+8)
        if result!=base:raise RefillUnsupported('finalizer image VM returned another mapping')
        return result,vm.steps
    finally:vm_module.B=old


def _cached_page_size(p,base,thread_id):
    guard=base+0x3E1D58
    if not _u(p,guard,1)&1:
        if startup.acquire_serial_guard(p,guard_address=guard,image_base=base,thread_id=thread_id):
            # Matching libc getpagesize +264FC is mov w0,#4096; ret.
            _w(p,base+0x3E1D50,4096,4)
            startup.release_serial_guard(p,guard_address=guard,image_base=base)
    value=_u(p,base+0x3E1D50,4)
    if value!=4096:raise RefillUnsupported('probe page size is unsupported')
    return value


def _run_copied_probe(p,base,sp,thread,system,thread_id=None):
    _cached_page_size(p,base,thread_id)
    page_size=_u(p,base+0x3E1D50,4)
    if page_size!=4096 or not _u(p,base+0x3E1D58,1)&1:raise RefillUnsupported('probe page size is unsupported')
    address=_system(p,system,222,(0,page_size,7,33,0xFFFFFFFF,0))
    if type(address) is not int or address<0x10000 or address&4095 or address>=1<<56:
        raise RefillUnsupported('probe mmap failed')
    if address>>12 in p:raise RefillUnsupported('probe mmap overlaps surviving guest storage')
    source=base+0x1DB664;length=0x270;code=bytearray(page_size)
    if _system(p,system,167,(0x53564D41,0,address,page_size,base+0x3D5C44))!=0:
        raise RefillUnsupported('failed probe prctl is unrecovered')
    code[:length]=_read_span(p,source,length)
    if hashlib.sha256(code[:length]).hexdigest()!='cc17175247fa72fd98fca5e0094e19056660d94563fc9e7c7df4de8e8a5301f4':
        raise RefillUnsupported('copied probe body differs from recovered code')
    def instruction(offset):return int.from_bytes(code[offset:offset+4],'little')
    # The copied function changes its counter instruction while executing.
    # Recover its actual counter loop; the page is transient and never host executable.
    for offset,expected in ((0x188,0x910004A5),(0x194,0x91000484),(0x1A4,0xB9000046),
            (0x1A8,0xF100289F),(0x1AC,0x5400008A),(0x1B0,0xF10028BF),
            (0x24C,0xAA0403E0)):
        if instruction(offset)!=expected:raise RefillUnsupported('unrecovered copied probe instruction '+hex(offset))
    sleep=sp-0xE8
    _w(p,sleep,0);_w(p,sleep+8,5000000)
    if _system(p,system,101,(sleep,0))!=0:
        raise RefillUnsupported('failed probe nanosleep is unrecovered')
    first=instruction(0x188);counter=instruction(0x194);x4=x5=0
    x5+=1
    for _ in range(10):
        if counter==0x91000484:x4+=1
        elif counter==0x910004A5:x5+=1
        else:raise RefillUnsupported('unrecovered self-modified counter')
        previous=counter;counter=first;code[0x194:0x198]=counter.to_bytes(4,'little')
        if x4>=10 or x5>=10:break
    else:raise RefillUnsupported('copied probe loop did not terminate')
    code[0x194:0x198]=previous.to_bytes(4,'little')
    if _system(p,system,215,(address,page_size,page_size,base+0x3D5C44,0,0))!=0:
        raise RefillUnsupported('failed probe munmap is unrecovered')
    return x4


def _run_finalizer(pages, *, image_base, entry_stack_address, thread_pointer,
        thread_id, allocate,free,read_clock,get_tls,initialize_registry,broadcast,
        register_destructor,invoke_javavm,invoke_jni,system,clock,signal_condition,
        vm_module,max_steps=1000000):
    p=_PageTransaction(pages);base=image_base;S=entry_stack_address
    if not all(callable(f) for f in (allocate,free,read_clock,get_tls,initialize_registry,broadcast,
            register_destructor,invoke_javavm,invoke_jni,system,clock,signal_condition)):
        raise RefillUnsupported('finalizer requires explicit providers')
    if type(S) is not int or S&15 or type(thread_pointer) is not int or thread_pointer&7:
        raise RefillUnsupported('invalid finalizer stack/thread ABI')
    if type(max_steps) is not int or not 1<=max_steps<=1000000:raise ValueError('invalid finalizer VM budget')
    _read_span(p,S-0x8000,0x8000)
    def decode(source,dest,mask,flag):
        if not _u(p,base+flag,4):
            objects.decode_masked_bytes(p,source_address=base+source,destination_address=base+dest,
                mask_address=base+mask,max_bytes=64);_w(p,base+flag,1,4)
    def singleton(sp):
        r=registry.get_singleton136_reference(p,image_base=base,entry_stack_address=sp,thread_id=thread_id,
            allocate=allocate,free=free,read_clock=read_clock,get_tls=get_tls,initialize_registry=initialize_registry,broadcast=broadcast)
        return _u(p,r.wrapper_address)
    payload=singleton(S-0x10)
    decode(0x894B4,0x3D9E38,0x89568,0x3D9E48)
    decode(0x894D0,0x3D9E50,0x89550,0x3D9E68)
    if _u(p,payload+0xC,4)==0xFF:
        for path in (0x3D9E38,0x3D9E50):
            if _system(p,system,56,(0xFFFFFF9C,base+path,0,0))!=-2:
                raise RefillUnsupported('finalizer file-present branch is unrecovered')
            _w(p,thread_pointer+0x10,2,4)
    payload=singleton(S-0x10);signal_sp=S-0x90
    _write_span(p,signal_sp,bytes(32));_write_span(p,signal_sp+0x28,bytes(32))
    _w(p,signal_sp,0x10000000,4);_w(p,signal_sp+8,base+0x2042DC)
    if _system(p,system,134,(64,signal_sp-0x40,signal_sp-0x20,8))!=-22:
        raise RefillUnsupported('successful finalizer sigaction branch is unrecovered')
    _w(p,thread_pointer+0x10,22,4);_w(p,base+0x37D380,0xFFFFFFFF,4)
    mutex=_u(p,payload+0x58)+8
    objects.lock_uncontended_mutex(p,mutex_address=mutex)
    decode(0x83E30,0x3D5C44,0x83E38,0x3D5C4C)
    probe=_run_copied_probe(p,base,S,thread_pointer,system,thread_id)
    if probe!=10:_w(p,payload+0x30,1,4)
    objects.unlock_uncontended_mutex(p,mutex_address=mutex)
    decode(0x89F20,0x3DA014,0x8A03C,0x3DA018)
    decode(0x89F24,0x3DA01C,0x8A038,0x3DA020)
    if not _u(p,base+0x3DA010,1):
        pair=S-0x70
        acquired=environment.acquire_thread_environment(p,image_base=base,entry_stack_address=pair,
            output_pair_address=pair,get_tls=get_tls,register_destructor=register_destructor,invoke_javavm=invoke_javavm)
        env=acquired.environment;cls=_u(p,base+0x3DEEB8)
        if not env:raise RefillUnsupported('finalizer requires a Java environment')
        environment._invoke_jni(p,env,0x388,(cls,base+0x3DA014,base+0x3DA01C),invoke_jni)
        if environment._invoke_jni(p,env,0x720,(),invoke_jni)&255:
            environment._invoke_jni(p,env,0x88,(),invoke_jni);_w(p,base+0x3DA010,0,1)
        else:_w(p,base+0x3DA010,1,1)
    payload=singleton(S-0x10);image,steps=_run_image_vm(p,base,S-0x30,payload,vm_module,max_steps)
    ph=image+_u(p,image+0x20);count=_u(p,image+0x38,2)
    if not 1<=count<=64:raise RefillUnsupported('unbounded finalizer ELF headers')
    minimum=MASK64-1;maximum=0
    for i in range(count):
        record=ph+i*56
        if _u(p,record,4)==1:
            begin=_u(p,record+0x10);end=begin+_u(p,record+0x28)
            if end>MASK64:raise RefillUnsupported('overflowed finalizer ELF segment')
            minimum=min(minimum,begin);maximum=max(maximum,end)
    bound=(_u(p,payload+0x10)-(minimum&-4096)+((maximum+4095)&-4096))&MASK64
    _w(p,payload+0x18,bound)
    if _u(p,payload+0x10)>4096 and _u(p,payload+0x10)<bound:
        _w(p,payload+0x20,_u(p,base+0x37D454,4),4)
        copied_word=_u(p,base+0x37D450,4)
        _w(p,payload+0x28,0 if copied_word>0xDEADBEE0 else copied_word)
    source=S-0x60;_w(p,source,base+0x34F058);_w(p,source+0x20,source)
    submission=timed.submit_timed_callable(p,source_address=source,scratch_address=S-0x500,
        image_base=base,queue_index=1,delay_ms=60000,allocate=allocate,free=free,clock=clock,signal_condition=signal_condition)
    startup.destroy_callable(p,object_address=source,image_base=base,free=free)
    p.commit();return FinalizerResult(probe,steps,bound,submission)


def run_finalizer_worker(pages, *, thread_start_address,argument_address,image_base,libc_base,entry_stack_address,
        thread_pointer,thread_id,allocate,free,create_key,set_specific,get_tls,
        read_clock,clock,futex,broadcast,initialize_registry,register_destructor,
        invoke_javavm,invoke_jni,system,signal_condition,get_libc_tls,os_call,vm_module,
        max_iterations=64,max_steps=1000000):
    """Run the startup-generated finalizer queue and its complete guest exit.

    Queue support/TLS and the original finalizer task compose existing owners.
    The image VM resumes after each recovered page-size callback and must reach
    its actual exit. Unknown code, contended state and unsupported OS outcomes
    reject with guest-page rollback, including failures after task submission.
    Providers own reversible external effects; guest rollback cannot undo them.
    """
    for value,alignment in ((image_base,4096),(libc_base,4096),(argument_address,8),
            (entry_stack_address,16),(thread_pointer,8)):
        if type(value) is not int or not 0<value<1<<56 or value%alignment:
            raise RefillUnsupported('invalid finalizer worker address')
    if type(thread_id) is not int or not 0<thread_id<1<<32:
        raise RefillUnsupported('finalizer worker requires a nonzero uint32 thread id')
    if type(thread_start_address) is not int or thread_start_address!=image_base+0x3260A4:
        raise RefillUnsupported('unknown finalizer worker entry')
    if not all(callable(f) for f in (allocate,free,create_key,set_specific,get_tls,read_clock,
            clock,futex,broadcast,initialize_registry,register_destructor,invoke_javavm,
            invoke_jni,system,signal_condition,get_libc_tls,os_call)):
        raise RefillUnsupported('finalizer worker requires explicit providers')
    if vm_module is None or not all(hasattr(vm_module,n) for n in ('VM','Mem','VMExit','B')):
        raise RefillUnsupported('finalizer worker requires its VM owner')
    if type(max_iterations) is not int or not 1<=max_iterations<=4096:
        raise ValueError('invalid finalizer worker iteration budget')
    if type(max_steps) is not int or not 1<=max_steps<=1000000:
        raise ValueError('invalid finalizer image VM budget')
    p=_PageTransaction(pages);base=image_base;S=entry_stack_address;results=[]
    thread=_u(p,thread_pointer+8)
    if not thread or _u(p,thread+0x50,4) or _u(p,thread+0x78) or _u(p,thread+0x58):
        raise RefillUnsupported('finalizer worker requires fresh joinable storage')
    def invoke(staged,function,argument):
        if function!=base+0x204348 or argument!=S-0xC0:raise RefillUnsupported('unknown finalizer queued task')
        results.append(_run_finalizer(staged,image_base=base,entry_stack_address=S-0xD0,
            thread_pointer=thread_pointer,thread_id=thread_id,allocate=allocate,free=free,
            read_clock=read_clock,get_tls=get_tls,initialize_registry=initialize_registry,
            broadcast=broadcast,register_destructor=register_destructor,invoke_javavm=invoke_javavm,
            invoke_jni=invoke_jni,system=system,clock=clock,signal_condition=signal_condition,vm_module=vm_module,max_steps=max_steps))
    returned=startup.run_startup_worker(p,argument_address=argument_address,worker_kind='queue',
        image_base=base,thread_pointer=thread_pointer,thread_id=thread_id,create_key=create_key,
        set_specific=set_specific,get_tls=get_tls,clock=clock,futex=futex,free=free,invoke=invoke,task_address=S-0xC0,max_iterations=max_iterations)
    if returned!=0 or len(results)!=1:raise RefillUnsupported('finalizer worker did not complete one task')
    def destructor(staged,function,argument):
        if function!=base+0x26EF2C:raise RefillUnsupported('unknown finalizer TLS destructor')
        environment.destroy_thread_environment(staged,image_base=base,object_address=argument,invoke_javavm=invoke_javavm)
    exited=thread_exit.run_pthread_exit(GuestOS(p),image_base=base,libc_base=libc_base,
        thread_pointer=thread_pointer,return_value=0,get_libc_tls=get_libc_tls,free=free,
        os_call=os_call,set_specific=set_specific,get_image_tls=get_tls,broadcast=broadcast,invoke=destructor)
    if exited.detached or exited.unmapped_regions:
        raise RefillUnsupported('finalizer exit changed joinable ownership')
    p.commit();return FinalizerWorkerResult(returned,results[0],exited)
