"""Original Long conversion versus Python with explicit JNI/cache mutex inputs.

JNI services are controlled inputs. Matching-libc uncontended mutex bodies run
in the oracle. Cache mutex construction and whole JNI_OnLoad remain separate.
The ()J signature consumes no arguments: compare two va_list structures and
its redundant object spill, excluding four unused GP words/SIMD/canary/FP/LR.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from unicorn import arm64_const as arm
import vm9_jni_environment as environment
import vm9_objects as objects
from vm9_allocator import RefillUnsupported,_read_span,_write_span
from verify_vm9_signer_objects import GUEST,LIBRARY_SHA256,fresh_pages,image_pages,native
from verify_vm9_jni_initialization_fresh_20261007 import LIBC_SHA256,cstring

MASK64=(1<<64)-1
ENV,TABLE,MUTEX,CLASS,GLOBAL,METHOD,OBJECT=(GUEST+x for x in (0x1000,0x2000,0x3000,0x4000,0x4100,0x4200,0x4300))
SP=GUEST+0xEF00
DECODES=((0x3DEF7C,0xA5828,0x3DEF6C,0xA5A1C),(0x3DEFB4,0xA5854,0x3DEFA8,0xA59E8),(0x3DEFBC,0xA5860,0x3DEFB8,0xA59E4))
SLOTS={0x30:('FindClass',2),0x740:('GetObjectRefType',2),0xA8:('NewGlobalRef',2),
    0xB8:('DeleteLocalRef',2),0x108:('GetMethodID',4),0x1A8:('CallLongMethodV',4)}


def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))


def fixture(lib,base,profile):
    p=fresh_pages();p.update(image_pages(lib,base));w(p,ENV,TABLE)
    for i,slot in enumerate(SLOTS):
        for extra in (0,0x100):w(p,TABLE+(0x800 if extra else 0)+slot,GUEST+0xF600+i*0x10+extra)
    objects.construct_normal_mutex_object(p,object_address=MUTEX,image_base=base)
    if profile.get('shared_mutex'):w(p,MUTEX+8,0x2000,2)
    w(p,base+0x3DF0A8,MUTEX)
    w(p,base+0x3DF0C0,GLOBAL if profile.get('warm_class') else 0)
    w(p,base+0x3DF0C8,METHOD if profile.get('warm_method') else 0)
    for i,(flag,source,dest,mask) in enumerate(DECODES):
        if i in profile.get('warm_decode',()):
            objects.decode_masked_bytes(p,source_address=base+source,destination_address=base+dest,mask_address=base+mask)
            w(p,base+flag,0x80000000,4)
    return p


class Providers:
    def __init__(self,base,profile):self.base=base;self.profile=profile;self.events=[]
    def call(self,target,args,read,write):
        slot={GUEST+0xF600+i*0x10+extra:slot for i,slot in enumerate(SLOTS) for extra in (0,0x100)}[target]
        label,arity=SLOTS[slot];assert len(args)==arity and args[0]==ENV
        event=[label,target,list(args)]
        if label=='FindClass':
            assert cstring(read,args[1])==b'java/lang/Long'
            if self.profile.get('switch_table'):write(ENV,(TABLE+0x800).to_bytes(8,'little'))
            result=self.profile.get('class_result',CLASS)
        elif label=='GetObjectRefType':
            assert args[1]==self.profile.get('class_result',CLASS);result=self.profile.get('reference_type',1)
        elif label=='NewGlobalRef':result=self.profile.get('global_result',GLOBAL)
        elif label=='DeleteLocalRef':
            assert args[1]==self.profile.get('class_result',CLASS);result=0
        elif label=='GetMethodID':
            assert args[1]==(CLASS if self.profile.get('reference_type')==2 else self.profile.get('global_result',GLOBAL))
            assert cstring(read,args[2])==b'longValue' and cstring(read,args[3])==b'()J'
            result=self.profile.get('method_result',METHOD)
        elif label=='CallLongMethodV':
            assert args[1:3]==(0 if self.profile.get('null_object') else OBJECT,METHOD)
            raw=read(args[3],32);fields=[int.from_bytes(raw[i:i+8],'little') for i in (0,8,16)]
            fields += [int.from_bytes(raw[i:i+4],'little',signed=True) for i in (24,28)]
            assert args[3]==SP-0xE0 and fields==[SP-0x70,SP-0xE0,SP-0x110,-40,-128]
            assert int.from_bytes(read(fields[1]+fields[3],8),'little')==args[1]
            event.append(dict(va_list_fields=fields,signature_consumes_zero_arguments=True))
            result=self.profile.get('long_result',0xF123456789ABCDEF)
        else:raise AssertionError(label)
        self.events.append(event+[result&MASK64]);return result&MASK64
    def model(self,p,target,args):return self.call(target,args,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
    def imports(self):
        result={}
        for i,slot in enumerate(SLOTS):
            for extra in (0,0x100):
                target=GUEST+0xF600+i*0x10+extra;arity=SLOTS[slot][1]
                def invoke(cpu,target=target,arity=arity):
                    args=tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(arity))
                    return self.call(target,args,lambda a,n:bytes(cpu.mem_read(a,n)),lambda a,b:cpu.mem_write(a,b))
                result[target-self.base]=invoke
        return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    cases=[];negatives=[]
    def compare(label,base,profile):
        p=fixture(a.library,base,profile);expected,actual=Providers(base,profile),Providers(base,profile)
        observed={(k<<12,4096):None for k in p if base<=k<<12<base+0x400000}
        for address,size in ((SP-0x108,8),(SP-0xE0,32),(SP-0xB8,32),(SP-0x70,20)):observed[address,size]=None
        entries=[]
        def observe(cpu,address):
            off=address-base
            if off in (0x270854,0x167E54,0x26F154,0x15F778,0x224FF8):entries.append(hex(off))
            if profile.get('cache_published_at_lock') and off==0x270960:
                cpu.mem_write(base+0x3DF0C0,GLOBAL.to_bytes(8,'little')+METHOD.to_bytes(8,'little'))
        result,memory,alloc,ledger=native(a.library,base,0x270854,
            [0 if profile.get('null_environment') else ENV,0 if profile.get('null_object') else OBJECT],p,
            libc=a.libc,real_mutexes=True,real_singletons=True,thread_id=137,host_imports=expected.imports(),
            instruction_observer=observe,observed_memory=observed,instruction_limit=100000)
        def lock(p,*,mutex_address):
            status=objects.lock_uncontended_mutex(p,mutex_address=mutex_address)
            if profile.get('cache_published_at_lock'):
                w(p,base+0x3DF0C0,GLOBAL);w(p,base+0x3DF0C8,METHOD)
            return status
        modeled=environment.convert_java_long(p,image_base=base,entry_stack_address=SP,
            environment_pointer=0 if profile.get('null_environment') else ENV,
            object_reference=0 if profile.get('null_object') else OBJECT,
            invoke_jni=actual.model,lock_mutex=lock)
        assert result==modeled.returned_word and memory==_read_span(p,GUEST,0xA000)
        assert expected.events==actual.events and not alloc
        attempted=any(e[0]=='CallLongMethodV' for e in expected.events)
        cold_locked='0x15f778' in entries
        for (address,n),data in observed.items():
            if SP-0x108<=address<=SP-0xB8 and not attempted:continue
            if address==SP-0x70 and not cold_locked:continue
            assert data==_read_span(p,address,n),(label,hex(address))
        assert [e[0] for e in ledger]==(['pthread_mutex_lock','pthread_mutex_unlock'] if cold_locked else [])
        cases.append(dict(label=label,image_base=hex(base),profile=profile,native_entries=entries,
            guest_payload_match=True,all_main_image_pages_match=True,returned_word_match=True,
            returned_word_hex=hex(result),decoded_lengths=list(modeled.decoded_lengths),
            JNI_service_order=[e[0] for e in expected.events],uncontended_lock_scope_compared=cold_locked,
            no_argument_variadic_window_compared=attempted,unused_four_GP_words_compared=False,
            explicit_cache_mutex_input_used=True,cache_mutex_constructor_compared=False,
            actual_android_jvm_executed=False,full_JNI_OnLoad_recovered=False))
    profiles=[('cold',{}),('warm',dict(warm_class=True,warm_method=True)),
        ('class_only',dict(warm_class=True)),('method_only',dict(warm_method=True)),
        ('null_environment',dict(null_environment=True)),('null_object',dict(null_object=True)),
        ('missing_class',dict(class_result=0,global_result=0)),('missing_global',dict(global_result=0)),
        ('missing_method',dict(method_result=0)),('already_global',dict(reference_type=2)),
        ('live_table_switch',dict(switch_table=True)),('shared_normal_mutex',dict(shared_mutex=True)),
        ('warm_decodes',dict(warm_decode=(0,1,2))),('mixed_decodes',dict(warm_decode=(0,2))),
        ('lock_recheck_published',dict(cache_published_at_lock=True)),('zero_long',dict(long_result=0)),
        ('all_bits_long',dict(long_result=MASK64))]
    for base in (0x122C0000,0x775C205000):
        for label,profile in profiles:compare(label,base,profile)
    def reject(label,change,*,late_refusal=False,**kwargs):
        base=0x122C0000;p=fixture(a.library,base,{})
        change(p);before={k:bytes(v) for k,v in p.items()};provider=Providers(base,{})
        options=dict(image_base=base,entry_stack_address=SP,environment_pointer=ENV,object_reference=OBJECT,invoke_jni=provider.model)
        options.update(kwargs)
        if late_refusal:
            def fail_late(p,target,args):
                if target==GUEST+0xF650:raise RefillUnsupported('explicit Long service refuses')
                return provider.model(p,target,args)
            options['invoke_jni']=fail_late
        try:environment.convert_java_long(p,**options)
        except (ValueError,RefillUnsupported):pass
        else:raise AssertionError('accepted negative '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        if late_refusal:assert provider.events
        negatives.append(dict(label=label,pages_unchanged=True,external_JNI_effects_retained=bool(provider.events)))
    reject('unaligned_stack',lambda p:None,entry_stack_address=SP-1)
    reject('negative_object',lambda p:None,object_reference=-1)
    reject('environment_overflow',lambda p:None,environment_pointer=1<<64)
    reject('missing_cache_mutex',lambda p:w(p,0x122C0000+0x3DF0A8,0))
    reject('contended_mutex',lambda p:w(p,MUTEX+8,1,2))
    reject('missing_JNI_provider',lambda p:None,invoke_jni=None)
    reject('null_JNI_function',lambda p:w(p,TABLE+0x30,0))
    reject('missing_stack_page',lambda p:p.pop((SP-0x70)>>12))
    reject('JNI_result_overflow',lambda p:None,invoke_jni=lambda *args:1<<64)
    reject('unsupported_lock_status',lambda p:None,lock_mutex=lambda *args,**kwargs:22)
    reject('late_Long_service_refusal',lambda p:None,late_refusal=True)
    e=dict(schema='vm9-jni-long-fresh-differential-v1',evidence_date='2026-10-07',sample_sha256=LIBRARY_SHA256,
        matching_libc_sha256=LIBC_SHA256,conversion_controls=len(cases),negative_controls=len(negatives),
        conversion_cases=cases,negative_checks=negatives,native_input_snapshot_used=False,
        explicit_cache_mutex_and_JNI_services_used=True,cache_mutex_constructor_recovered=False,
        full_JNI_OnLoad_recovered=False,actual_android_jvm_executed=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8')
    print('JNI Long conversion:',len(cases),'native/Python;',len(negatives),'negative passed')

if __name__=='__main__':main()
