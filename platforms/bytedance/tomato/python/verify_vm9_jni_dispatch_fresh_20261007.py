"""Original JNI dispatcher/variadic GP frame versus Python from fresh inputs.

Explicit environment acquisition/JNI services bound component tests. Separate
compositions execute actual TLS acquisition and its recovered Python owner.
The legacy dispatcher stub is disabled; Android JVM/whole bootstrap are open.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from unicorn import arm64_const as arm
import vm9_jni_environment as environment
from vm9_allocator import RefillUnsupported,_read_span,_write_span
from verify_vm9_signer_objects import GUEST,STOP,LIBRARY_SHA256,fresh_pages,image_pages,native
import verify_vm9_jni_environment_fresh_20261007 as acquisition
from verify_vm9_strings import Effects

MASK64=(1<<64)-1
ENV,TABLE,CLASS,METHOD,OBJECT,EXCEPTION=(GUEST+x for x in (0x3000,0xA000,0x3330,0x3340,0x3500,0x3510))
SP=GUEST+0xEF00
SLOTS={0x398:('CallStaticObjectMethodV',4),0x720:('ExceptionCheck',1),
    0x78:('ExceptionOccurred',1),0x88:('ExceptionClear',1),0xB8:('DeleteLocalRef',2)}
DEFAULT_WORDS=(0x1000000E,0,0,GUEST+0x3600,GUEST+0x3700)


def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))

def fill(p,base,profile):
    w(p,ENV,TABLE)
    for i,slot in enumerate(SLOTS):
        for extra in (0,0x100):w(p,TABLE+(0x800 if extra else 0)+slot,GUEST+0xF500+i*0x10+extra)
    w(p,base+0x3DEEB8,0 if profile.get('missing_class') else CLASS)
    w(p,base+0x3DEEC0,0 if profile.get('missing_method') else METHOD)
    if profile.get('relocated'):
        delta=(1<<64)-0x3E4C88
        w(p,base+0x3825B8,GUEST+0x3400-delta);w(p,GUEST+0x3400,CLASS)
        w(p,base+0x3825B0,GUEST+0x3408-delta);w(p,GUEST+0x3408,METHOD)
    return p


class Providers:
    def __init__(self,profile,words=DEFAULT_WORDS):
        self.profile=profile;self.words=words;self.checks=list(profile.get('checks',(0,0)));self.events=[]
    def call(self,target,args,read,write):
        slots={GUEST+0xF500+i*0x10+extra:slot for i,slot in enumerate(SLOTS) for extra in (0,0x100)}
        slot=slots[target];label,arity=SLOTS[slot]
        assert len(args)==arity and args[0]==ENV
        event=[label,target,list(args)]
        if label=='CallStaticObjectMethodV':
            assert args[1:3]==(CLASS,METHOD)
            raw=read(args[3],32)
            stack,gtop,vtop=(int.from_bytes(raw[i:i+8],'little') for i in (0,8,16))
            goff,voff=(int.from_bytes(raw[i:i+4],'little',signed=True) for i in (24,28))
            assert (stack,gtop,vtop,goff,voff)==(SP-0x70,SP-0xE0,SP-0x110,-40,-128)
            gp=[int.from_bytes(read(gtop+goff+i*8,8),'little') for i in range(5)]
            assert gp==[self.words[0]&0xFFFFFFFF,self.words[1]&0xFFFFFFFF,*self.words[2:]]
            event.append(dict(va_list_hex=raw.hex(),integer_words=gp))
            if self.profile.get('switch_table'):write(ENV,(TABLE+0x800).to_bytes(8,'little'))
            result=self.profile.get('object_result',OBJECT)
        elif label=='ExceptionCheck':
            assert self.checks,'extra exception check';result=self.checks.pop(0)
        elif label=='ExceptionOccurred':result=self.profile.get('exception_reference',EXCEPTION)
        elif label=='ExceptionClear':result=0
        elif label=='DeleteLocalRef':
            assert args[1]==self.profile.get('exception_reference',EXCEPTION);result=0
        else:raise AssertionError(label)
        self.events.append(event+[result&MASK64]);return result&MASK64
    def model(self,p,target,args):return self.call(target,args,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
    def imports(self):
        handlers={}
        for i,slot in enumerate(SLOTS):
            arity=SLOTS[slot][1]
            for extra in (0,0x100):
                target=GUEST+0xF500+i*0x10+extra
                def invoke(cpu,target=target,arity=arity):
                    args=tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(arity))
                    return self.call(target,args,lambda a,n:bytes(cpu.mem_read(a,n)),lambda a,b:cpu.mem_write(a,b))
                handlers[target]=invoke
        return handlers
    def acquire(self,p,*,entry_stack_address,output_pair_address):
        assert entry_stack_address==SP-0x70 and output_pair_address==SP-0x68
        env=0 if self.profile.get('null_environment') else ENV
        self.events.append(['acquire',entry_stack_address,output_pair_address,env])
        w(p,output_pair_address,env);w(p,output_pair_address+8,GUEST+0x3800)
    def native_acquire(self,cpu):
        pair=cpu.reg_read(arm.UC_ARM64_REG_X0);sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        assert sp==SP-0x70 and pair==SP-0x68
        env=0 if self.profile.get('null_environment') else ENV
        self.events.append(['acquire',sp,pair,env])
        cpu.mem_write(pair,env.to_bytes(8,'little')+(GUEST+0x3800).to_bytes(8,'little'));return 0


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==acquisition.LIBC_SHA256
    cases=[];exceptions=[];compositions=[];negatives=[]
    def compare(label,base,profile,words=DEFAULT_WORDS,helper=None,real_tls=False):
        if real_tls:
            p,blocks=acquisition.fixture(a.library,base,tls_cold=profile.get('tls_cold',False));fill(p,base,profile)
            ep,ap=(acquisition.Providers(base,Effects(blocks=blocks),((0,ENV),)*(2 if profile.get('tls_cold') else 1)) for _ in range(2))
        else:p=fresh_pages();p.update(image_pages(a.library,base));fill(p,base,profile)
        expected,actual=Providers(profile,words),Providers(profile,words)
        entry=helper or 0x26E70C;args=[0 if profile.get('null_environment') else ENV] if helper else list(words)
        imports={target-base:fn for target,fn in expected.imports().items()}
        if real_tls:imports.update(ep.imports())
        else:imports[0x26EDC4]=expected.native_acquire
        if helper:
            expected.checks=list(profile.get('checks',(0,)))
            actual.checks=list(profile.get('checks',(0,)))
        observed={(k<<12,4096):None for k in p if base<=k<<12<base+0x400000}
        if not helper:
            for address,size in ((SP-0x108,40),(SP-0xE0,32),(SP-0xB8,32)):observed[address,size]=None
        seen=[]
        def observe(cpu,address):
            off=address-base
            if off in (entry,0x26EDC4,0x26E944,0x27184C,0x26F258):seen.append(hex(off))
        result,memory,alloc,ledger=native(a.library,base,entry,args,p,host_imports=imports,
            libc=a.libc if real_tls else None,real_singletons=real_tls,real_mutexes=real_tls,
            thread_id=137 if real_tls else None,real_jni_acquisition=True,real_jni_dispatch=True,
            instruction_observer=observe,observed_memory=observed,instruction_limit=200000,
            malloc_handler=(lambda cpu,n:ep.effects.native(cpu,'malloc',n)) if real_tls else None)
        if helper==0x27184C:
            value=environment.check_and_clear_java_exception(p,environment_pointer=args[0],invoke_jni=actual.model)
            assert result==int(value)
        elif helper==0x26F258:
            environment.clear_java_exception(p,environment_pointer=args[0],invoke_jni=actual.model)
        else:
            acquire=actual.acquire
            if real_tls:
                def acquire(p,*,entry_stack_address,output_pair_address):
                    return environment.acquire_thread_environment(p,image_base=base,entry_stack_address=entry_stack_address,
                        output_pair_address=output_pair_address,get_tls=ap.tls,register_destructor=ap.register,invoke_javavm=ap.model_vm)
            modeled=environment.invoke_java_dispatch(p,image_base=base,entry_stack_address=SP,
                argument_words=words,acquire_environment=acquire,invoke_jni=actual.model)
            assert result==modeled.returned_reference
        assert memory==_read_span(p,GUEST,0xA000),(label,'guest payload')
        assert expected.events==actual.events,(label,'JNI event order')
        for (address,n),data in observed.items():
            if SP-0x108<=address<=SP-0xB8 and not any(e[0]=='CallStaticObjectMethodV' for e in expected.events):continue
            assert data==_read_span(p,address,n),(label,hex(address))
        if real_tls:
            assert ep.events==ap.events and ep.effects.calls==ap.effects.calls
            assert not ep.responses and not ap.responses
        else:assert not alloc and not ledger
        case=dict(label=label,image_base=hex(base),native_entries=seen,profile=profile,
            original_dispatch_body_executed=not bool(helper),legacy_dispatch_stub_disabled=True,
            explicit_acquisition_service_used=not real_tls and not bool(helper),actual_TLS_body_executed=real_tls,
            JNI_service_order=[e[0] for e in expected.events],integer_variadic_window_compared=any(e[0]=='CallStaticObjectMethodV' for e in expected.events),
            guest_payload_match=True,all_main_image_pages_match=True,returned_reference_match=not bool(helper),
            actual_android_jvm_executed=False,full_JNI_OnLoad_recovered=False)
        (exceptions if helper else compositions if real_tls else cases).append(case)
    profiles=[('ordinary',{}),('missing_class',dict(missing_class=True)),('missing_method',dict(missing_method=True)),
        ('null_environment',dict(null_environment=True)),('null_object',dict(object_result=0)),
        ('exception',dict(checks=(1,0))),('exception_null_ref',dict(checks=(1,0),exception_reference=0)),
        ('second_exception',dict(checks=(0,1))),('low_byte_zero',dict(checks=(0x100,0))),
        ('both_checks_throw',dict(checks=(0x101,0xFF))),('live_table_switch',dict(switch_table=True)),
        ('relocated_cache',dict(relocated=True))]
    for base in (0x122C0000,0x775C205000):
        for label,profile in profiles:compare(label,base,profile)
        for label,words in [('integer_upper_bits',(0x9988776655443322,MASK64,0xFEDCBA9876543210,1,MASK64)),
                ('all_zero',(0,0,0,0,0)),('integer_sign_bits',(0x80000000,0xFFFFFFFF,MASK64,0,1))]:
            compare(label,base,{},words)
        for helper in (0x27184C,0x26F258):
            for label,profile in [('no_exception',dict(checks=(0,))),('exception',dict(checks=(1,))),
                    ('low_byte_zero',dict(checks=(0x100,))),('null_environment',dict(null_environment=True)),
                    ('null_exception',dict(checks=(0xFF,),exception_reference=0))]:compare(label,base,profile,helper=helper)
        for label,profile in [('warm_tls',{}),('fresh_thread_tls',dict(tls_cold=True))]:compare(label,base,profile,real_tls=True)
    def reject(label,change,**kwargs):
        p=fresh_pages();p.update(image_pages(a.library,0x122C0000));fill(p,0x122C0000,{})
        change(p);before={k:bytes(v) for k,v in p.items()};provider=Providers({})
        options=dict(image_base=0x122C0000,entry_stack_address=SP,argument_words=DEFAULT_WORDS,
            acquire_environment=provider.acquire,invoke_jni=provider.model);options.update(kwargs)
        try:environment.invoke_java_dispatch(p,**options)
        except (ValueError,RefillUnsupported):pass
        else:raise AssertionError('negative control accepted: '+label)
        assert before=={k:bytes(v) for k,v in p.items()};negatives.append(dict(label=label,pages_unchanged=True))
    reject('unaligned_stack',lambda p:None,entry_stack_address=SP-1)
    reject('wrong_argument_count',lambda p:None,argument_words=(1,2))
    reject('negative_raw_word',lambda p:None,argument_words=(-1,*DEFAULT_WORDS[1:]))
    reject('word_overflow',lambda p:None,argument_words=(1<<64,*DEFAULT_WORDS[1:]))
    reject('missing_acquisition',lambda p:None,acquire_environment=None)
    reject('missing_JNI_provider',lambda p:None,invoke_jni=None)
    reject('null_JNI_function',lambda p:w(p,TABLE+0x398,0))
    reject('missing_stack_page',lambda p:p.pop((SP-0x108)>>12))
    reject('bad_JNI_result',lambda p:None,invoke_jni=lambda *a:1<<64)
    reject('late_exception_refusal',lambda p:None,invoke_jni=lambda p,f,args:OBJECT if f==GUEST+0xF500 else (_ for _ in ()).throw(RefillUnsupported('exception service missing')))
    e=dict(schema='vm9-jni-dispatch-fresh-differential-v1',evidence_date='2026-10-07',sample_sha256=LIBRARY_SHA256,
        matching_libc_sha256=acquisition.LIBC_SHA256,dispatcher_controls=len(cases),exception_controls=len(exceptions),
        composition_controls=len(compositions),negative_controls=len(negatives),dispatcher_cases=cases,exception_cases=exceptions,
        composition_cases=compositions,negative_checks=negatives,legacy_dispatch_stub_disabled=True,native_input_snapshot_used=False,
        integer_variadic_frames_compared=True,full_SIMD_variadic_and_physical_stack_ABI_compared=False,
        explicit_JNI_services_used=True,actual_android_jvm_executed=False,full_JNI_OnLoad_recovered=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8')
    print('JNI dispatch:',len(cases),'dispatcher;',len(exceptions),'exception;',len(compositions),'TLS composition;',len(negatives),'negative passed')

if __name__=='__main__':main()
