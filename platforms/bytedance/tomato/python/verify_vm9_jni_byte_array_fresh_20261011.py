"""Original Java byte array helper versus Python from independent ELF inputs.

JNI, calloc, malloc and free are explicit synthetic services. The original
reference constructor and matching-libc diagnostic locks execute naturally.
Only counts and comparison outcomes are exported; binary inputs stay local.
"""
from pathlib import Path
import argparse, hashlib, json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_strings import Effects
from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
import vm9_jni_environment as environment
import vm9_diagnostics as diagnostics
import vm9_libc_stdio as mutex
from vm9_allocator import _read_span, _write_span, RefillUnsupported

G=oracle.GUEST;OUT=G+0x1000;ENV=G+0x2000;ARRAY=G+0x2100
TABLE=G+0x2200;OTHER_TABLE=G+0x2900;TP=G+0x3000;THREAD=G+0x3100
LENGTH=G+0xF600;REGION=G+0xF610;OTHER_REGION=G+0xF620;SP=G+0xEF00
def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))

def fresh(library,base,*,warm=False,referenced=0):
    p=oracle.image_pages(library,base);p.update(oracle.fresh_pages())
    w(p,ENV,TABLE);w(p,TABLE+0x558,LENGTH);w(p,TABLE+0x640,REGION)
    w(p,OTHER_TABLE+0x640,OTHER_REGION)
    w(p,TP+8,THREAD);w(p,THREAD+0x10,137,4)
    if warm:
        global_lock,table,entry=G+0x3500,G+0x800,G+0x3600
        w(p,base+diagnostics.GUARD,0x101);w(p,base+diagnostics.GLOBAL_LOCK,global_lock)
        w(p,global_lock,base+0x34C738);_write_span(p,global_lock+8,bytes(40))
        w(p,base+diagnostics.TABLE,table);_write_span(p,table,bytes(0x800))
        w(p,table+((referenced>>4)&255)*8,entry);w(p,entry,base+0x34C738)
        mutex.initialize_recursive_mutex(p,mutex_address=entry+8)
    return p

class Services:
    def __init__(self,length,payload,*,failures=(),reload_table=False,region_result=0):
        self.length=length;self.payload=payload;self.effects=Effects(blocks={},failures=failures)
        self.events=[];self.reload_table=reload_table;self.region_result=region_result
    def jni(self,fn,args,read,write):
        if fn==LENGTH:
            assert args==(ENV,ARRAY);self.events.append(['GetArrayLength',self.length&0xFFFFFFFF])
            if self.reload_table:write(ENV,OTHER_TABLE.to_bytes(8,'little'))
            return self.length&0xFFFFFFFF
        assert fn==(OTHER_REGION if self.reload_table else REGION)
        assert args[:4]==(ENV,ARRAY,0,self.length) and len(args)==5
        assert read(args[4],self.length)==bytes(self.length),'calloc provider did not zero buffer'
        write(args[4],self.payload);self.events.append(['GetByteArrayRegion',self.length,args[4]])
        return self.region_result
    def model_jni(self,p,fn,args):return self.jni(fn,args,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
    def allocation(self,kind,size,read,write):
        pointer=self.effects.operation(kind,size,0,read,write)
        if kind=='calloc' and pointer:write(pointer,bytes(size))
        self.events.append([kind,size,pointer]);return pointer
    def malloc(self,p,n):return self.allocation('malloc',n,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
    def calloc(self,p,count,size):
        assert count==1 and size==self.length
        return self.allocation('calloc',size,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
    def free(self,p,pointer):
        self.effects.free(p,pointer);self.events.append(['free',pointer])
    def diagnostic(self,kind,*args):self.events.append([kind,*args])
    def imports(self,base):
        def reg(c,i):return c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i)))
        def jni(fn,count):
            return lambda c:self.jni(fn,tuple(reg(c,i) for i in range(count)),
                lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
        def calloc(c):
            assert (reg(c,0),reg(c,1))==(1,self.length)
            return self.allocation('calloc',self.length,lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
        def free(c):
            pointer=reg(c,0);self.effects.native(c,'free',pointer=pointer)
            self.events.append(['free',pointer]);return 0
        return {LENGTH-base:jni(LENGTH,2),REGION-base:jni(REGION,5),OTHER_REGION-base:jni(OTHER_REGION,5),
                0x3482B0:calloc,0x347FA0:free}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    operation=environment.construct_java_byte_array_reference
    cases=[];guards=[]
    profiles=[('NULL_environment',0,ARRAY,7,b'fixture',(),False,0),
        ('NULL_array',ENV,0,7,b'fixture',(),False,0),
        ('zero_length',ENV,ARRAY,0,b'',(),False,0),
        ('negative_length',ENV,ARRAY,-1,b'',(),False,0),
        ('signed_minimum_length',ENV,ARRAY,0x80000000,b'',(),False,0),
        ('one_byte',ENV,ARRAY,1,b'\xff',(),False,0),
        ('embedded_NUL',ENV,ARRAY,13,b'fixture\0bytes',(),False,0),
        ('binary_alphabet',ENV,ARRAY,256,bytes(range(256)),(),False,0),
        ('cross_page_binary',ENV,ARRAY,4097,(bytes(range(256))*17)[:4097],(),False,0),
        ('calloc_NULL',ENV,ARRAY,13,b'fixture\0bytes',(0,),False,0),
        ('string_buffer_NULL',ENV,ARRAY,13,b'fixture\0bytes',(2,),False,0),
        ('reload_environment_table',ENV,ARRAY,13,b'fixture\0bytes',(),True,0),
        ('void_region_result_ignored',ENV,ARRAY,13,b'fixture\0bytes',(),False,0xFFFFFFFF)]
    for base in (0x122C0000,0x775C205000):
        for warm in (False,True):
            for label,env,array,length,payload,failures,reload_table,region_result in profiles:
                effective=length&0xFFFFFFFF
                referenced=G+0x4000+((max(effective,16)+15)&~15) if env and array and 0<effective<0x80000000 and 0 not in failures else 0
                p=fresh(args.library,base,warm=warm,referenced=referenced)
                expected=Services(length,payload,failures=failures,reload_table=reload_table,region_result=region_result)
                actual=Services(length,payload,failures=failures,reload_table=reload_table,region_result=region_result)
                seen={};observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
                observed[SP-0x50,24]=None
                def watch(cpu,address):
                    off=address-base
                    if off in (0x2700A8,0x2481FC,0x1625A4,0x26C858,0x26C9D0):seen[off]=seen.get(off,0)+1
                    if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
                    if off==0x348310:expected.diagnostic('gettid',137)
                def malloc(cpu,n):return expected.allocation('malloc',n,lambda a,n:bytes(cpu.mem_read(a,n)),lambda a,b:cpu.mem_write(a,b))
                _,memory,_,_=oracle.native(args.library,base,0x2700A8,[env,array],p,libc=args.libc,
                    real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
                    extra_registers={arm.UC_ARM64_REG_X8:OUT,arm.UC_ARM64_REG_TPIDR_EL0:TP},thread_id=137,
                    host_imports=expected.imports(base),malloc_handler=malloc,instruction_limit=100000,
                    instruction_observer=watch,observed_memory=observed)
                result=operation(p,image_base=base,entry_stack_address=SP,output_reference_address=OUT,
                    environment_pointer=env,array_reference=array,thread_pointer=TP,thread_id=137,
                    invoke_jni=actual.model_jni,calloc=actual.calloc,allocate=actual.malloc,free=actual.free,
                    diagnostic_observer=actual.diagnostic)
                own=_read_span(p,G,0xA000)
                if own!=memory:
                    offset=next(i for i,(x,y) in enumerate(zip(own,memory)) if x!=y)
                    raise AssertionError((label,warm,hex(base),'guest',hex(offset)))
                for (address,n),value in observed.items():
                    assert _read_span(p,address,n)==value,(label,warm,hex(base),hex(address-base))
                assert actual.events==expected.events,(label,warm,'service order',actual.events,expected.events)
                assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
                assert u(p,OUT)==result.string_address and u(p,OUT+8)==result.counter_address and u(p,result.counter_address,4)==1
                if referenced:
                    string=u(p,OUT);data=u(p,string+16);size=u(p,string+12,4)
                    if 2 in failures:assert data==size==u(p,string+8,4)==0
                    else:assert size==length and _read_span(p,data,size+1)==payload+b'\0'
                else:assert u(p,OUT)==0
                assert seen.get(0x1625A4)==seen.get(0x2700A8)==1
                cases.append(dict(case=label,image_base=hex(base),warm_diagnostic_locks=warm,
                    original_helper_and_reference_constructor_returned=True,
                    all_guest_payload_and_image_pages_match=True,diagnostic_scope_bytes_match=True,
                    all_ordered_JNI_allocation_free_lock_services_match=True,
                    JNI_calls=sum(e[0].startswith('Get') for e in actual.events),
                    malloc_calls=sum(e[0]=='malloc' for e in actual.events),
                    calloc_calls=sum(e[0]=='calloc' for e in actual.events),
                    free_calls=sum(e[0]=='free' for e in actual.events),reference_count_one=True,
                    binary_payload_preserved=bool(referenced and 2 not in failures),native_snapshot_input=False))
                print('PASS',hex(base),'warm' if warm else 'cold',label,flush=True)
    base=0x122C0000
    def reject(label,*,change=None,provider=None,**options):
        p=fresh(args.library,base)
        if change:change(p)
        before={k:bytes(v) for k,v in p.items()};services=Services(13,b'fixture\0bytes')
        call=dict(image_base=base,entry_stack_address=SP,output_reference_address=OUT,environment_pointer=ENV,
            array_reference=ARRAY,thread_pointer=TP,thread_id=137,invoke_jni=services.model_jni,
            calloc=services.calloc,allocate=services.malloc,free=services.free,diagnostic_observer=services.diagnostic)
        call.update(options)
        if provider:call.update(provider(services))
        try:operation(p,**call)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError,StopIteration):pass
        else:raise AssertionError(label+' was accepted')
        assert before=={k:bytes(v) for k,v in p.items()},label
        guards.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    for label,kw in [('unaligned_stack',dict(entry_stack_address=SP-1)),('NULL_output',dict(output_reference_address=0)),
        ('negative_environment',dict(environment_pointer=-1)),('oversized_array_pointer',dict(array_reference=1<<64)),
        ('oversized_payload',dict(max_payload_bytes=12)),('invalid_bound',dict(max_payload_bytes=-1)),
        ('missing_JNI',dict(invoke_jni=None)),('missing_calloc',dict(calloc=None)),('missing_free',dict(free=None)),
        ('missing_allocator',dict(allocate=None))]:reject(label,**kw)
    reject('missing_length_method',change=lambda p:w(p,TABLE+0x558,0))
    reject('missing_region_method_after_calloc',change=lambda p:w(p,TABLE+0x640,0))
    reject('invalid_calloc_result',calloc=lambda *a:-1)
    reject('unmapped_calloc_buffer',calloc=lambda *a:0x66000000)
    reject('string_object_new_NULL',provider=lambda s:(s.effects.failures.add(1) or {}))
    reject('counter_new_NULL_after_free',provider=lambda s:(s.effects.failures.add(6) or {}))
    reject('diagnostic_guard_wait',change=lambda p:w(p,base+diagnostics.GUARD+1,2,1))
    reject('provider_failure_after_region',free=lambda *a:(_ for _ in ()).throw(RuntimeError('synthetic service failure')))
    reject('provider_exhaustion',invoke_jni=lambda *a:next(iter(())))
    result=dict(component='Java byte array reference helper +0x2700a8',library_sha256=oracle.LIBRARY_SHA256,
        matching_libc_sha256=LIBC_SHA256,native_Python_controls=len(cases),rollback_guards=len(guards),cases=cases,
        negative_cases=guards,native_input_snapshot_used=False,private_names_or_payloads_published=False,
        real_diagnostic_reference_constructor_verified=True,live_Android_JVM_verified=False,
        complete_live_lookup_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS Java byte array',len(cases),'controls',len(guards),'rollback guards',flush=True)
if __name__=='__main__':main()
