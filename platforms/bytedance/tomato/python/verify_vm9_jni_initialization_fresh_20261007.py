"""Fresh +0x26e19c JNI dispatch initialization and +0x26f154 retention.

ELF instructions execute with explicit JNI service inputs, never Android JVM.
Publication compositions use an explicit continuation; original JNI_OnLoad
probes stop before the next actual startup dispatch.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn import arm64_const as arm
import vm9_jni_environment as environment
import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, STOP, LIBRARY_SHA256, fresh_pages, image_pages, native

LIBC_SHA256='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
MASK64=(1<<64)-1
ENV,TABLE,NAME,BLOCK,VM=(GUEST+x for x in (0x1000,0x2000,0x1400,0x1600,0x1800))
STACK=GUEST+0xEF00
METHOD_TABLE=STACK-0xA0
CLASS,SUPER,GRAND,METHOD,GLOBAL=(0x10101,0x20202,0x30303,0x40404,0x50505)
SLOTS={0x30:('FindClass',2),0x50:('GetSuperclass',2),0x6B8:('RegisterNatives',4),
    0xB8:('DeleteLocalRef',2),0x388:('GetStaticMethodID',4),
    0x740:('GetObjectRefType',2),0xA8:('NewGlobalRef',2)}


def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
def cstring(read,a):
    data=bytearray()
    while len(data)<256:
        b=read(a+len(data),1)
        if b==b'\0':return bytes(data)
        data+=b
    raise AssertionError('unterminated JNI fixture string')


def fixture(library,base,profile):
    p=fresh_pages();p.update(image_pages(library,base));w(p,ENV,TABLE)
    _write_span(p,NAME,b'fixture/Startup\0')
    for i,slot in enumerate(SLOTS):
        for t in (TABLE,TABLE+0x800):w(p,t+slot,GUEST+0xF210+i*0x10+(0x100 if t!=TABLE else 0))
    # Existing outputs distinguish preserve-on-early-return from forced clearing.
    w(p,base+0x3DEEC0,0x717171);w(p,base+0x3DEEB8,0x727272)
    warm=profile.get('warm',())
    for index,(flag,source,destination,mask) in enumerate(((0x3DEE6C,0xA5694,0x3DEE68,0xA572C),
            (0x3DEEAC,0xA56A0,0x3DEE70,0xA56F0),(0x3DEEB4,0xA56DC,0x3DEEB0,0xA56E0))):
        if index in warm:
            objects.decode_masked_bytes(p,source_address=base+source,destination_address=base+destination,mask_address=base+mask)
            w(p,base+flag,0x80000000,4)
    if profile.get('relocated'):
        delta=MASK64+1-0x3E4C88
        # Explicit replacement of encoded guest destinations, flags and outputs.
        for off,target in ((0x382550,GUEST+0x4000),(0x382558,GUEST+0x4100),(0x382560,GUEST+0x4200),
                (0x382568,GUEST+0x4300),(0x382580,GUEST+0x4304),(0x382598,GUEST+0x4308),
                (0x3825B0,GUEST+0x4400),(0x3825B8,GUEST+0x4408)):
            w(p,base+off,target-delta)
        for off in (0x4300,0x4304,0x4308):w(p,GUEST+off,0,4)
        for off in (0x4000,0x4100,0x4200):_write_span(p,GUEST+off,bytes(0x80))
    return p


class Providers:
    def __init__(self,base,profile):self.base=base;self.profile=profile;self.events=[];self.super_count=0
    def call(self,target,args,read,write):
        candidates={GUEST+0xF210+i*0x10+extra:slot for i,slot in enumerate(SLOTS) for extra in (0,0x100)}
        assert target in candidates,'unprovided JNI target'
        slot=candidates[target];name,arity=SLOTS[slot]
        assert len(args)==arity and args[0]==ENV
        event=[name,target,list(args)]
        if name=='FindClass':
            event.append(cstring(read,args[1]).hex())
            if self.profile.get('switch_table'):write(ENV,(TABLE+0x800).to_bytes(8,'little'))
            result=self.profile.get('class_result',CLASS)
        elif name=='GetSuperclass':
            self.super_count+=1
            assert args[1]==(CLASS if self.super_count==1 else SUPER)
            result=self.profile.get('super_result',SUPER) if self.super_count==1 else self.profile.get('grand_result',GRAND)
        elif name=='RegisterNatives':
            assert args[1]==GRAND and args[3]==1
            raw=read(args[2],24);words=[int.from_bytes(raw[i:i+8],'little') for i in (0,8,16)]
            assert words[2]==self.base+0x26E684
            event.append([cstring(read,words[0]).hex(),cstring(read,words[1]).hex(),words[2]])
            result=self.profile.get('register_result',0)
        elif name=='GetStaticMethodID':
            assert args[1]==CLASS
            event.append([cstring(read,args[2]).hex(),cstring(read,args[3]).hex()])
            result=self.profile.get('method_result',METHOD)
        elif name=='GetObjectRefType':result=self.profile.get('reference_type',1)
        elif name=='NewGlobalRef':result=self.profile.get('global_result',GLOBAL)
        elif name=='DeleteLocalRef':result=0
        else:raise AssertionError(name)
        event.append(result&MASK64);self.events.append(event);return result&MASK64
    def model(self,p,target,args):return self.call(target,args,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
    def imports(self):
        result={}
        for i,slot in enumerate(SLOTS):
            arity=SLOTS[slot][1]
            for extra in (0,0x100):
                target=GUEST+0xF210+i*0x10+extra
                def invoke(cpu,target=target,arity=arity):
                    args=tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(arity))
                    return self.call(target,args,lambda a,n:bytes(cpu.mem_read(a,n)),lambda a,b:cpu.mem_write(a,b))
                result[target-self.base]=invoke
        return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    initializations=[];retentions=[];compositions=[];probes=[];negatives=[]
    def observed(p,extra=()):
        return {(address,n):None for address,n in [*((k<<12,4096) for k in p if not GUEST<=k<<12<GUEST+0x10000),*extra]}
    def compare(label,base,profile,*,retain=False,compose=False):
        p=fixture(a.library,base,profile)
        expected,actual=Providers(base,profile),Providers(base,profile)
        imports=expected.imports();seen=[];frames=[]
        obs=observed(p,((METHOD_TABLE,24),) if not retain else ())
        name=0 if profile.get('null_name') else NAME
        env=0 if profile.get('null_env') else ENV
        ref=profile.get('reference',CLASS)
        entry=0x26F154 if retain else 0x26E19C
        args=[env,ref] if retain else [env,name]
        extra={}
        if compose:
            entry=0x271998;args=[base+0x27BE88,BLOCK];w(p,BLOCK,VM)
            continuation=GUEST+0xF400;fp=GUEST+0xCC00
            extra={arm.UC_ARM64_REG_X29:fp,arm.UC_ARM64_REG_X30:continuation}
            def enter(cpu):
                assert int.from_bytes(cpu.mem_read(base+0x3DEED8,8),'little')==VM
                cpu.reg_write(arm.UC_ARM64_REG_X0,env);cpu.reg_write(arm.UC_ARM64_REG_X1,name)
                cpu.reg_write(arm.UC_ARM64_REG_X30,STOP);cpu.reg_write(arm.UC_ARM64_REG_PC,base+0x26E19C)
                return None
            imports[continuation-base]=enter
        def observe(cpu,address):
            off=address-base
            if off in (entry,0x27BE88,0x26E19C,0x26F154):seen.append(hex(off))
            if address==STOP:frames.append(cpu.reg_read(arm.UC_ARM64_REG_SP))
        returned,memory,alloc,ledger=native(a.library,base,entry,args,p,host_imports=imports,
            extra_registers=extra,real_jni_acquisition=True,observed_memory=obs,instruction_observer=observe,
            instruction_limit=30000)
        assert not alloc and not ledger
        if compose:
            environment.publish_java_vm_callback(p,image_base=base,entry_stack_address=STACK,
                argument_block_address=BLOCK,saved_frame_pointer=fp,return_address=continuation)
        if retain:
            value=environment.retain_global_jni_reference(p,environment_pointer=env,reference=ref,invoke_jni=actual.model)
            assert returned==value
        else:
            result=environment.initialize_java_dispatch(p,image_base=base,entry_stack_address=STACK,
                environment_pointer=env,class_name_address=name,invoke_jni=actual.model)
            assert result.methods_address==METHOD_TABLE
        assert memory==_read_span(p,GUEST,0xA000),label
        assert actual.events==expected.events,label
        for (address,n),data in obs.items():
            # The method table is meaningful only if RegisterNatives was called.
            if address==METHOD_TABLE and not any(e[0]=='RegisterNatives' for e in expected.events):continue
            assert data==_read_span(p,address,n),(label,hex(address))
        case=dict(label=label,image_base=hex(base),profile=profile,native_entries=seen,
            JNI_service_order=[e[0] for e in expected.events],guest_payload_match=True,all_main_image_pages_match=True,
            JNI_service_inputs_and_outputs_match=True,native_input_snapshot_used=False,
            method_table_compared=any(e[0]=='RegisterNatives' for e in expected.events),actual_android_jvm_executed=False)
        if compose:case['explicit_host_continuation_used']=True;compositions.append(case)
        elif retain:case['returned_reference_match']=True;retentions.append(case)
        else:initializations.append(case)
    profiles=[('cold_local',{}),('all_warm_global',dict(warm=(0,1,2),reference_type=2)),
        ('null_name',dict(null_name=True)),('null_name_and_env',dict(null_name=True,null_env=True)),
        ('class_not_found',dict(class_result=0)),('super_not_found',dict(super_result=0)),
        ('grand_not_found',dict(grand_result=0)),('register_error',dict(register_result=-1)),
        ('method_missing',dict(method_result=0)),('global_creation_null',dict(global_result=0)),
        ('weak_reference',dict(reference_type=3)),('invalid_reference_type',dict(reference_type=-1)),
        ('first_warm',dict(warm=(0,))),('signature_warm',dict(warm=(1,))),('third_warm',dict(warm=(2,))),
        ('table_switch',dict(switch_table=True)),('relocated_outputs',dict(relocated=True))]
    for base in (0x122C0000,0x775C205000):
        for label,profile in profiles:compare(label,base,profile)
        for label,profile in [('null_env',dict(null_env=True)),('null_ref',dict(reference=0)),
                ('local',{}),('global',dict(reference_type=2)),('weak',dict(reference_type=3)),
                ('invalid',dict(reference_type=0)),('negative_type',dict(reference_type=-1)),
                ('upper_bits_ignored',dict(reference_type=0x100000002)),('null_global',dict(global_result=0))]:
            compare(label,base,profile,retain=True)
        for label,profile in [('published_local',{}),('published_missing_grand',dict(grand_result=0))]:
            compare(label,base,profile,compose=True)
    def reject(label,change,call=None):
        p=fixture(a.library,0x122C0000,{});provider=Providers(0x122C0000,{})
        change(p);before={k:bytes(v) for k,v in p.items()}
        try:
            if call:call(p,provider)
            else:environment.initialize_java_dispatch(p,image_base=0x122C0000,entry_stack_address=STACK,
                environment_pointer=ENV,class_name_address=NAME,invoke_jni=provider.model)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('negative control accepted: '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        negatives.append(dict(label=label,pages_unchanged=True))
    reject('null_env_with_name',lambda p:None,lambda p,s:environment.initialize_java_dispatch(p,
        image_base=0x122C0000,entry_stack_address=STACK,environment_pointer=0,class_name_address=NAME,invoke_jni=s.model))
    reject('unaligned_stack',lambda p:None,lambda p,s:environment.initialize_java_dispatch(p,
        image_base=0x122C0000,entry_stack_address=STACK-1,environment_pointer=ENV,class_name_address=NAME,invoke_jni=s.model))
    reject('missing_environment_page',lambda p:p.pop(ENV>>12))
    reject('null_function',lambda p:w(p,TABLE+0x30,0))
    reject('missing_provider',lambda p:None,lambda p,s:environment.initialize_java_dispatch(p,
        image_base=0x122C0000,entry_stack_address=STACK,environment_pointer=ENV,class_name_address=NAME,invoke_jni=None))
    reject('bad_provider_result',lambda p:None,lambda p,s:environment.initialize_java_dispatch(p,
        image_base=0x122C0000,entry_stack_address=STACK,environment_pointer=ENV,class_name_address=NAME,invoke_jni=lambda *args:1<<64))
    reject('negative_reference',lambda p:None,lambda p,s:environment.retain_global_jni_reference(p,
        environment_pointer=ENV,reference=-1,invoke_jni=s.model))
    reject('missing_method_stack_page',lambda p:p.pop(METHOD_TABLE>>12))
    # Retain one provider across the partial call sequence; its external events
    # are deliberately outside the page rollback guarantee.
    late_provider=Providers(0x122C0000,{})
    def late(p,target,args):
        if target==GUEST+0xF260:raise RefillUnsupported('bounded refusal after method ID publication')
        return late_provider.model(p,target,args)
    reject('late_JNI_refusal',lambda p:None,lambda p,s:environment.initialize_java_dispatch(p,
        image_base=0x122C0000,entry_stack_address=STACK,environment_pointer=ENV,class_name_address=NAME,invoke_jni=late))
    assert [e[0] for e in late_provider.events][-1]=='GetStaticMethodID'
    # Original JNI_OnLoad observations are counted separately from comparisons.
    # Resolve its defined GLOB_DAT binding from the private ELF, not a body stub.
    from elftools.elf.elffile import ELFFile
    with a.library.open('rb') as stream:
        elf=ELFFile(stream);binding=None
        for section in elf.iter_sections():
            if section['sh_type']=='SHT_RELA':
                symbols=elf.get_section(section['sh_link'])
                for relocation in section.iter_relocations():
                    if relocation['r_offset']==0x375010:
                        symbol=symbols.get_symbol(relocation['r_info_sym'])
                        assert relocation['r_info_type']==1025 and symbol.name=='JNI_OnLoad'
                        assert symbol['st_shndx']!='SHN_UNDEF'
                        binding=symbol['st_value']+relocation['r_addend']
    assert binding==0x27B41C
    for base in (0x122C0000,0x775C205000):
        for switch,stop,warm_switch in ((0,0x28040C,True),(0x200,0x2A0028,True),(0,0x26EDC4,False)):
            p=fixture(a.library,base,{})
            wrapper,payload,counter=(GUEST+x for x in (0x5000,0x5100,0x5200))
            _write_span(p,payload,bytes(136));w(p,wrapper,payload);w(p,wrapper+8,counter);w(p,counter,1)
            w(p,base+0x3D1678,wrapper);w(p,base+0x3D1680,1)
            reg,regpayload,timer=(GUEST+x for x in (0x5300,0x5400,0x5600))
            _write_span(p,regpayload,bytes(320));w(p,reg,regpayload);w(p,reg+8,GUEST+0x53E0)
            w(p,regpayload+0x130,timer);w(p,timer,3);w(p,timer+8,5)
            w(p,base+0x3D1550,reg);w(p,base+0x3D1558,1)
            w(p,base+0x3D1578,switch);w(p,base+0x375010,base+binding)
            if warm_switch:w(p,base+0x3D1570,MASK64)
            vm_table,getenv=GUEST+0x1900,GUEST+0xF410
            w(p,VM,vm_table);w(p,vm_table+0x30,getenv)
            provider=Providers(base,{});imports=provider.imports();entries=[];getenv_calls=[];decimals=[]
            def get(cpu):
                args=tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3))
                assert args[0]==VM and args[2]==0x10006
                cpu.mem_write(args[1],ENV.to_bytes(8,'little'));getenv_calls.append(list(args));return 0
            def decimal(cpu):
                assert cpu.reg_read(arm.UC_ARM64_REG_X1)==0 and cpu.reg_read(arm.UC_ARM64_REG_X2)==10
                raw=cstring(lambda a,n:bytes(cpu.mem_read(a,n)),cpu.reg_read(arm.UC_ARM64_REG_X0))
                value=int(raw.decode('ascii'),10);decimals.append(value);return value
            def clock(cpu):
                cpu.mem_write(cpu.reg_read(arm.UC_ARM64_REG_X1),
                    (1791023800).to_bytes(8,'little')+(500000000).to_bytes(8,'little'));return 0
            imports.update({getenv-base:get,0x3484B0:decimal,0x348450:clock})
            cold_entries=[]
            def observe(cpu,address):
                off=address-base
                if off in (0x32A0A0,0x165644,0x165648,0x165658):cold_entries.append(hex(off))
                if off in (0x27B41C,0x27B750,0x27B7A8,0x27BE88,0x26E19C,0x26F154,0x1658DC):entries.append(hex(off))
            obs={(base+0x3DEED8,8):None,(base+0x3DEEB8,16):None}
            if not warm_switch:obs[base+0x3D1570,8]=None;obs[base+0x3E2EB8,8]=None
            _,_,alloc,ledger=native(a.library,base,0x27B41C,[VM,0],p,host_imports=imports,
                libc=a.libc if not warm_switch else None,real_singletons=not warm_switch,
                real_mutexes=not warm_switch,thread_id=137 if not warm_switch else None,
                real_jni_acquisition=True,instruction_observer=observe,observed_memory=obs,
                stop_offset=stop,instruction_limit=200000)
            expected_ledger=[] if warm_switch else [['pthread_mutex_lock',base+0x3E2EB8],
                ['pthread_mutex_unlock',base+0x3E2EB8]]
            assert not alloc and ledger==expected_ledger and len(getenv_calls)==1 and decimals==[5256,5256]
            if not warm_switch:
                assert cold_entries==['0x32a0a0','0x165644','0x165648','0x165658']
                assert obs[base+0x3D1570,8]==(1).to_bytes(8,'little')
                assert obs[base+0x3E2EB8,8]==bytes(8)
            assert int.from_bytes(obs[base+0x3DEED8,8],'little')==VM
            assert obs[base+0x3DEEB8,16]==GLOBAL.to_bytes(8,'little')+METHOD.to_bytes(8,'little')
            assert entries[-3:]==['0x26e19c','0x26f154','0x1658dc']
            assert [e[0] for e in provider.events]==['FindClass','GetSuperclass','GetSuperclass','RegisterNatives',
                'DeleteLocalRef','GetStaticMethodID','GetObjectRefType','NewGlobalRef','DeleteLocalRef']
            probes.append(dict(image_base=hex(base),switch_value=switch,stopped_before_offset=hex(stop),
                native_entry_order=entries,JNI_service_order=[e[0] for e in provider.events],
                native_actual_class_name_hex=provider.events[0][3],original_vm_publication_executed=True,
                original_JNI_initialization_returned=True,switch_getter_entered=True,
                original_switch_predicate_returned=warm_switch,explicit_warm_switch_once_control_used=warm_switch,
                cold_switch_once_prefix_executed=not warm_switch,cold_once_initializer_entries=cold_entries,
                matching_libc_mutex_bodies_executed=not warm_switch,cold_once_control_at_boundary=1 if not warm_switch else None,
                cold_once_initializer_completed=False,original_TLS_acquisition_body_entered=False,
                actual_ELF_decimal_selectors=decimals,explicit_warm_references_and_JNI_clock_services_used=True,
                full_Python_bootstrap_compared=False,full_JNI_OnLoad_return_verified=False,
                actual_android_jvm_executed=False))
    evidence=dict(schema='vm9-jni-initialization-fresh-differential-v1',evidence_date='2026-10-07',sample_sha256=LIBRARY_SHA256,matching_libc_sha256=LIBC_SHA256,
        initialization_controls=len(initializations),retention_controls=len(retentions),composition_controls=len(compositions),
        negative_controls=len(negatives),initialization_cases=initializations,retention_cases=retentions,
        composition_cases=compositions,negative_checks=negatives,original_bootstrap_probes=len(probes),
        bootstrap_probe_cases=probes,native_input_snapshot_used=False,
        original_initialization_body_executed=True,original_reference_retention_body_executed=True,
        explicit_JNI_services_used=True,all_main_image_pages_compared=True,full_physical_stack_and_ABI_compared=False,
        full_JNI_OnLoad_recovered=False,actual_android_jvm_executed=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('JNI initialization:',len(initializations),'init;',len(retentions),'retention;',len(compositions),'composition;',len(negatives),'negative;',len(probes),'bootstrap probes passed')


if __name__=='__main__':main()
