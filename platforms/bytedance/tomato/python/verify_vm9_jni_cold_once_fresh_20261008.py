"""Fresh ctor -> JNI initialization -> actual cold getter versus Python.

Two explicit driver continuations compose native component bodies. Separate
ctor -> original JNI_OnLoad observations use one explicit driver continuation.
Warm reference/TLS globals/OS keys and allocator/JNI/JavaVM services remain
inputs; full Python bootstrap, all ELF constructors and fresh signer are open.
"""
from __future__ import annotations
import argparse,collections,hashlib,json
from pathlib import Path
from unicorn import arm64_const as arm
from elftools.elf.elffile import ELFFile
from verify_vm9_root_configuration import LIBC_BASE
import vm9_jni_environment as environment
import verify_vm9_jni_environment_fresh_20261007 as acquisition
import verify_vm9_jni_initialization_fresh_20261007 as initialization
from verify_vm9_signer_objects import GUEST,STOP,LIBRARY_SHA256,native
from verify_vm9_strings import Effects
from vm9_allocator import RefillUnsupported,_read_span,_write_span

MASK64=(1<<64)-1
ENV=initialization.ENV
TABLE,NAME,OBJECT=(GUEST+x for x in (0xA000,0x1400,0x5700))
LONG_CLASS,LONG_GLOBAL,LONG_METHOD,EXCEPTION=(0x60606,0x70707,0x80808,0x90909)
INNER_ENV=GUEST+0x1800
SP=GUEST+0xEF00
INIT_RETURN=GUEST+0xF800
EXTRA={0x398:('CallStaticObjectMethodV',4),0x720:('ExceptionCheck',1),0x108:('GetMethodID',4),
    0x1A8:('CallLongMethodV',4),0x78:('ExceptionOccurred',1),0x88:('ExceptionClear',1)}


def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))


def fixture(lib,base,profile,*,bootstrap=False):
    p,blocks=acquisition.fixture(lib,base,tls_cold=not profile.get('warm_tls'),vm_present=not bootstrap)
    w(p,ENV,TABLE);w(p,INNER_ENV,TABLE);_write_span(p,NAME,b'fixture/Startup\0')
    for i,slot in enumerate(initialization.SLOTS):w(p,TABLE+slot,GUEST+0xF210+i*0x10)
    for i,slot in enumerate(EXTRA):w(p,TABLE+slot,GUEST+0xF400+i*0x10)
    w(p,base+0x3D1578,0 if bootstrap else 0x9911)
    if bootstrap:
        wrapper,payload,counter=(GUEST+x for x in (0x5000,0x5100,0x5200))
        _write_span(p,payload,bytes(136));w(p,wrapper,payload);w(p,wrapper+8,counter);w(p,counter,1)
        w(p,base+0x3D1678,wrapper);w(p,base+0x3D1680,1)
        reg,regpayload,timer=(GUEST+x for x in (0x5300,0x5400,0x5600))
        _write_span(p,regpayload,bytes(320));w(p,reg,regpayload);w(p,reg+8,GUEST+0x53E0)
        w(p,regpayload+0x130,timer);w(p,timer,3);w(p,timer+8,5)
        w(p,base+0x3D1550,reg);w(p,base+0x3D1558,1)
        with lib.open('rb') as stream:
            elf=ELFFile(stream);binding=None
            for section in elf.iter_sections():
                if section['sh_type']=='SHT_RELA':
                    symbols=elf.get_section(section['sh_link'])
                    for reloc in section.iter_relocations():
                        if reloc['r_offset']==0x375010:
                            symbol=symbols.get_symbol(reloc['r_info_sym'])
                            assert symbol.name=='JNI_OnLoad' and symbol['st_shndx']!='SHN_UNDEF' and reloc['r_info_type']==1025
                            binding=symbol['st_value']+reloc['r_addend']
        assert binding==0x27B41C
        w(p,base+0x375010,base+binding)
    return p,blocks


class JNI(initialization.Providers):
    def __init__(self,base,profile):
        super().__init__(base,profile);self.checks=list(profile.get('checks',(0,0)))
        self.dispatch_sp=None;self.long_sp=None
    def call(self,target,args,read,write):
        if target==GUEST+0xF210 and initialization.cstring(read,args[1])==b'java/lang/Long':
            self.events.append(['FindClassLong',target,list(args),LONG_CLASS]);return LONG_CLASS
        if target==GUEST+0xF270 and args[1]==LONG_CLASS:
            self.events.append(['NewGlobalRefLong',target,list(args),LONG_GLOBAL]);return LONG_GLOBAL
        if target not in {GUEST+0xF400+i*0x10 for i in range(len(EXTRA))}:
            return super().call(target,args,read,write)
        slot=list(EXTRA)[(target-(GUEST+0xF400))//0x10];label,arity=EXTRA[slot]
        expected_env=INNER_ENV if self.profile.get('split_environments') and label in ('CallStaticObjectMethodV','ExceptionCheck','ExceptionOccurred','ExceptionClear') else ENV
        assert len(args)==arity and args[0]==expected_env
        event=[label,target,list(args)]
        if label=='CallStaticObjectMethodV':
            assert args[1:3]==(initialization.GLOBAL,initialization.METHOD)
            s=self.dispatch_sp;raw=read(args[3],32)
            fields=[int.from_bytes(raw[i:i+8],'little') for i in (0,8,16)]
            fields += [int.from_bytes(raw[i:i+4],'little',signed=True) for i in (24,28)]
            assert args[3]==s-0xE0 and fields==[s-0x70,s-0xE0,s-0x110,-40,-128]
            assert read(s-0xB8,32)==raw
            words=[int.from_bytes(read(fields[1]+fields[3]+i*8,8),'little') for i in range(5)]
            assert words==[0x1000000E,0,0,0,0]
            event.append(dict(va_list_fields=fields,integer_words=words))
            result=0 if self.profile.get('null_object') else OBJECT
        elif label=='ExceptionCheck':
            assert self.checks;result=self.checks.pop(0)
        elif label=='ExceptionOccurred':result=EXCEPTION
        elif label=='ExceptionClear':result=0
        elif label=='GetMethodID':
            assert args[1]==LONG_GLOBAL
            assert initialization.cstring(read,args[2])==b'longValue'
            assert initialization.cstring(read,args[3])==b'()J'
            result=0 if self.profile.get('missing_method') else LONG_METHOD
        elif label=='CallLongMethodV':
            assert args[1:3]==(OBJECT,LONG_METHOD);s=self.long_sp;raw=read(args[3],32)
            fields=[int.from_bytes(raw[i:i+8],'little') for i in (0,8,16)]
            fields += [int.from_bytes(raw[i:i+4],'little',signed=True) for i in (24,28)]
            assert args[3]==s-0xE0 and fields==[s-0x70,s-0xE0,s-0x110,-40,-128]
            assert read(s-0xB8,32)==raw
            assert int.from_bytes(read(fields[1]+fields[3],8),'little')==OBJECT
            event.append(dict(va_list_fields=fields));result=self.profile.get('long_word',0)
        else:raise AssertionError(label)
        self.events.append(event+[result&MASK64]);return result&MASK64
    def imports(self):
        result={}
        slots=dict(initialization.SLOTS);slots.update(EXTRA)
        for i,slot in enumerate(slots):
            target=(GUEST+0xF210+list(initialization.SLOTS).index(slot)*0x10) if slot in initialization.SLOTS else (GUEST+0xF400+list(EXTRA).index(slot)*0x10)
            arity=slots[slot][1]
            def invoke(cpu,target=target,arity=arity):
                args=tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(arity))
                return self.call(target,args,lambda a,n:bytes(cpu.mem_read(a,n)),lambda a,b:cpu.mem_write(a,b))
            result[target-self.base]=invoke
        return result


def run_native(a,base,profile,*,bootstrap=False):
    p,blocks=fixture(a.library,base,profile,bootstrap=bootstrap);effects=Effects(blocks=blocks)
    response_count=4 if bootstrap else (2 if profile.get('warm_tls') else 3)
    responses=[(0,ENV)]*response_count
    if profile.get('split_environments'):responses[-1]=(0,INNER_ENV)
    vm=acquisition.Providers(base,effects,responses);jni=JNI(base,profile)
    imports=vm.imports();imports.update(jni.imports());exit_events=[];drivers=[];entries=[];decimals=[]
    original_exit=imports[0x347EA0];trace=collections.deque(maxlen=24)
    wake_events=[]
    with a.libc.open('rb') as stream:
        elf=ELFFile(stream)
        broadcast_address=next(LIBC_BASE+symbol['st_value'] for section in elf.iter_sections()
            if section['sh_type']=='SHT_DYNSYM' for symbol in section.iter_symbols() if symbol.name=='pthread_cond_broadcast')
    def broadcast(cpu):
        assert cpu.reg_read(arm.UC_ARM64_REG_X0)==base+0x3E2EE0
        cpu.reg_write(arm.UC_ARM64_REG_PC,broadcast_address);return None
    def syscall(cpu,number):
        assert number==98
        args=[cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)]
        assert args==[base+0x3E2EE0,129,0x7FFFFFFF]
        wake_events.append([number,*args,0]);return 0
    if bootstrap:imports[0x3485A0]=broadcast
    def constructor_exit(cpu):
        args=[cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)]
        if args==[base+0x165388,base+0x3DF118,base+0x34C700]:
            assert not exit_events;exit_events.append([*args,0])
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==SP
            target=0x27B41C if bootstrap else 0x26E19C
            cpu.reg_write(arm.UC_ARM64_REG_X0,acquisition.VM if bootstrap else ENV)
            cpu.reg_write(arm.UC_ARM64_REG_X1,0 if bootstrap else NAME)
            cpu.reg_write(arm.UC_ARM64_REG_X30,STOP if bootstrap else INIT_RETURN)
            cpu.reg_write(arm.UC_ARM64_REG_PC,base+target);drivers.append(['ctor_exit_to',hex(target)]);return None
        return original_exit(cpu)
    def initialization_return(cpu):
        assert not bootstrap and cpu.reg_read(arm.UC_ARM64_REG_SP)==SP
        cpu.reg_write(arm.UC_ARM64_REG_X30,STOP);cpu.reg_write(arm.UC_ARM64_REG_PC,base+0x165658)
        drivers.append(['initializer_return_to','0x165658']);return None
    def decimal(cpu):
        assert cpu.reg_read(arm.UC_ARM64_REG_X1)==0 and cpu.reg_read(arm.UC_ARM64_REG_X2)==10
        value=int(initialization.cstring(lambda a,n:bytes(cpu.mem_read(a,n)),cpu.reg_read(arm.UC_ARM64_REG_X0)).decode(),10)
        decimals.append(value);return value
    def clock(cpu):
        cpu.mem_write(cpu.reg_read(arm.UC_ARM64_REG_X1),(1791023800).to_bytes(8,'little')+(500000000).to_bytes(8,'little'));return 0
    imports.update({0x347EA0:constructor_exit,INIT_RETURN-base:initialization_return,0x3484B0:decimal,0x348450:clock})
    def observe(cpu,address):
        off=address-base;trace.append(hex(off))
        if off==0x26E70C:jni.dispatch_sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        if off==0x270854:jni.long_sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        if off in (0x271940,0x27B41C,0x27BE88,0x26E19C,0x32A0A0,0x165648,0x165658,0x26E70C,0x270854,0x224FF8,0x1656D0):entries.append(hex(off))
    observed={(k<<12,4096):None for k in p if base<=k<<12<base+0x400000}
    observed[TABLE,4096]=None
    if not bootstrap:
        s=SP-0x50
        observed[SP-0x48,16]=None
    stop=(0x2A0028 if profile.get('long_word',0)&0x200 else 0x28040C) if bootstrap else None
    try:
        result,memory,alloc,ledger=native(a.library,base,0x271940,[],p,libc=a.libc,
            real_singletons=True,real_mutexes=True,thread_id=137,real_jni_acquisition=True,real_jni_dispatch=True,
            malloc_handler=lambda cpu,n:effects.native(cpu,'malloc',n),host_imports=imports,
            instruction_observer=observe,observed_memory=observed,stop_offset=stop,instruction_limit=300000,
            syscall_handler=syscall if bootstrap else None)
    except Exception:
        print('last PCs',list(trace));print('VM events',vm.events);print('JNI events',jni.events);raise
    assert not vm.responses and not jni.checks and not alloc
    if bootstrap:assert len(wake_events)==1
    jni.wake_events=wake_events
    return p,blocks,effects,vm,jni,exit_events,drivers,entries,decimals,observed,memory,stop


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--probes-only',action='store_true');a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==initialization.LIBC_SHA256
    cases=[];probes=[];negatives=[]
    if not a.probes_only:
        for base in (0x122C0000,0x775C205000):
            for label,profile in [('cold_zero',{}),('cold_flag',dict(long_word=0x200)),('null_object',dict(null_object=True)),
                    ('missing_method',dict(missing_method=True)),('dispatch_exception',dict(checks=(1,0))),
                    ('warm_tls_high_word',dict(warm_tls=True,long_word=0xF123456789ABCDEF)),
                    ('distinct_outer_dispatch_env',dict(split_environments=True,long_word=0x55))]:
                p,blocks,ep,ev,ej,ee,drivers,entries,decimals,observed,memory,stop=run_native(a,base,profile)
                ap=Effects(blocks=blocks);responses=[(0,ENV)]*(2 if profile.get('warm_tls') else 3)
                if profile.get('split_environments'):responses[-1]=(0,INNER_ENV)
                av=acquisition.Providers(base,ap,responses)
                aj=JNI(base,profile);aj.dispatch_sp=aj.long_sp=SP-0x50;ae=[]
                def register(p,fn,obj,dso):ae.append([fn,obj,dso,0]);return 0
                environment.initialize_java_cache_mutexes(p,image_base=base,allocate=ap.malloc,register_exit=register)
                environment.initialize_java_dispatch(p,image_base=base,entry_stack_address=SP,environment_pointer=ENV,
                    class_name_address=NAME,invoke_jni=aj.model)
                def acquire(p,*,entry_stack_address,output_pair_address):
                    return environment.acquire_thread_environment(p,image_base=base,entry_stack_address=entry_stack_address,
                        output_pair_address=output_pair_address,get_tls=av.tls,register_destructor=av.register,invoke_javavm=av.model_vm)
                modeled=environment.initialize_cold_java_switch(p,image_base=base,entry_stack_address=SP,
                    acquire_environment=acquire,invoke_jni=aj.model)
                assert memory==_read_span(p,GUEST,0xA000) and ej.events==aj.events and ev.events==av.events
                assert ep.calls==ap.calls and ee==ae and not av.responses and not aj.checks
                for (address,n),data in observed.items():assert data==_read_span(p,address,n),(label,hex(address))
                assert modeled.object_deleted==(not profile.get('null_object') and not profile.get('checks'))
                cases.append(dict(label=label,image_base=hex(base),profile=profile,native_entries=entries,
                    explicit_driver_continuations=drivers,guest_payload_match=True,all_main_image_pages_match=True,
                    JNI_table_page_compared=True,caller_output_pair_and_live_consumed_variadic_windows_compared=True,
                    allocator_VM_JNI_exit_effect_groups_match=True,unused_four_GP_words_and_full_physical_ABI_compared=False,
                    switch_word_hex=hex(u(p,base+0x3D1578)),object_deleted=modeled.object_deleted,
                    native_input_snapshot_used=False,whole_JNI_OnLoad_compared=False))
        def reject(label,**kwargs):
            base=0x122C0000;p,blocks=fixture(a.library,base,{})
            effects=Effects(blocks=blocks);jni=JNI(base,{});jni.dispatch_sp=jni.long_sp=SP-0x50
            environment.initialize_java_cache_mutexes(p,image_base=base,allocate=effects.malloc,register_exit=lambda *args:0)
            environment.initialize_java_dispatch(p,image_base=base,entry_stack_address=SP,environment_pointer=ENV,
                class_name_address=NAME,invoke_jni=jni.model)
            def acquire(p,*,entry_stack_address,output_pair_address):w(p,output_pair_address,ENV);w(p,output_pair_address+8,0)
            def late(p,target,args):
                if target==GUEST+0xF240 and args[1]==OBJECT:raise RefillUnsupported('object deletion refused')
                return jni.model(p,target,args)
            options=dict(image_base=base,entry_stack_address=SP,acquire_environment=acquire,invoke_jni=jni.model)
            options.update(kwargs)
            if label=='late_object_delete':options['invoke_jni']=late
            before={k:bytes(v) for k,v in p.items()};event_count=len(jni.events)
            try:environment.initialize_cold_java_switch(p,**options)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('accepted negative '+label)
            assert before=={k:bytes(v) for k,v in p.items()}
            if label=='late_object_delete':assert len(jni.events)>event_count
            negatives.append(dict(label=label,pages_unchanged=True,external_JNI_events_retained=len(jni.events)>event_count))
        reject('unaligned_stack',entry_stack_address=SP-1)
        reject('missing_acquisition',acquire_environment=None)
        reject('missing_JNI',invoke_jni=None)
        reject('late_object_delete')
    for base in (0x122C0000,0x775C205000):
        for word in (0,0x200):
            profile=dict(long_word=word)
            p,blocks,ep,ev,ej,ee,drivers,entries,decimals,observed,memory,stop=run_native(a,base,profile,bootstrap=True)
            def got(off,n=8):return int.from_bytes(observed[base+(off&~0xFFF),4096][off&0xFFF:(off&0xFFF)+n],'little')
            assert got(0x3D1570)==MASK64 and got(0x3D1578)==word
            assert got(0x3E2EE0,4)==4
            assert got(0x3DF0A8)==GUEST+0x4000 and got(0x3DF0C0)==LONG_GLOBAL and got(0x3DF0C8)==LONG_METHOD
            assert [e[0] for e in ev.events].count('GetEnv')==4 and decimals==[5256,5256]
            assert [c[1] for c in ep.calls]==[48,128,16,39,16,24,23]
            assert ej.events[-1][0]=='DeleteLocalRef' and ej.events[-1][2]==[ENV,OBJECT]
            probes.append(dict(image_base=hex(base),long_word_hex=hex(word),stopped_before_offset=hex(stop),
                cold_once_state_hex=hex(got(0x3D1570)),cold_once_completed=True,native_entries=entries,
                explicit_driver_continuations=drivers,original_JNI_OnLoad_invocation_executed=True,
                JNI_service_order=[e[0] for e in ej.events],GetEnv_calls=4,allocator_effects=ep.calls,
                matching_libc_condition_broadcast_executed=True,no_waiter_futex_services=ej.wake_events,
                once_condition_u32_after_broadcast=got(0x3E2EE0,4),
                cache_mutex_constructed_in_same_native_run=True,returned_object_deleted=True,
                defined_JNI_OnLoad_got_bound_from_ELF=True,actual_startup_VM_body_executed=False,
                warm_reference_and_TLS_global_OS_key_inputs_used=True,native_input_snapshot_used=False,
                Python_full_bootstrap_compared=False,full_JNI_OnLoad_return_verified=False))
            print('cold once completed:',hex(base),hex(word),'startup',hex(stop),flush=True)
    e=dict(schema='vm9-jni-cold-once-fresh-composition-v1',evidence_date='2026-10-08',evidence_timezone='Asia/Shanghai',sample_sha256=LIBRARY_SHA256,
        matching_libc_sha256=initialization.LIBC_SHA256,caller_composition_controls=len(cases),negative_controls=len(negatives),
        original_bootstrap_prefix_probes=len(probes),Python_full_bootstrap_comparison_controls=0,
        composition_cases=cases,negative_checks=negatives,bootstrap_prefix_cases=probes,
        explicit_driver_continuations_used=True,explicit_allocator_VM_JNI_OS_exit_services_used=True,
        native_input_snapshot_used=False,legacy_acquisition_and_dispatch_stubs_disabled=True,
        all_ELF_constructors_recovered=False,full_cold_TLS_subsystem_boot_verified=False,
        full_JNI_OnLoad_recovered=False,actual_android_jvm_executed=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8')
    print('Cold getter:',len(cases),'compositions;',len(negatives),'negative;',len(probes),'prefix probes passed')

if __name__=='__main__':main()
