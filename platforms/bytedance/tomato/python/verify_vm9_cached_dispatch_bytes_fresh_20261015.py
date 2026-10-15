"""Original +1cf688 cache producer with explicit environment and JNI services."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_java_object_bytes_fresh_20261015 as child
import vm9_jni_environment as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
oracle=child.oracle;binary=child.binary
G=child.G;SP=child.SP;TP=child.TP;OUT=child.OUT;ENV=child.ENV
DISPATCH=G+0xF900;DISPATCH_CLASS=G+0x1D00;DISPATCH_METHOD=G+0x1E00
OTHER_ENV=G+0x1F80
BASES=child.BASES
PROFILES=('normal','cold_diagnostics','NULL_environment','NULL_dispatch_result','NULL_utf',
    'NULL_array','method_exception','zero_length','embedded_NUL','calloc_NULL','reload_table','second_acquisition_NULL',
    'replace_first_environment_after_dispatch')


def fixture(library,image,label):
    p,kw=child.fixture(library,image,label)
    binary.w(p,child.TABLE+0x398,DISPATCH);binary.w(p,binary.OTHER_TABLE+0x398,DISPATCH)
    binary.w(p,image+0x3DEEB8,DISPATCH_CLASS);binary.w(p,image+0x3DEEC0,DISPATCH_METHOD)
    if label=='replace_first_environment_after_dispatch':binary.w(p,OTHER_ENV,child.TABLE)
    return p,dict(image_base=image,entry_stack_address=SP,output_reference_address=OUT,
        thread_pointer=TP,thread_id=137)


class Services(child.Services):
    def __init__(self,image,label):
        super().__init__(image,label);self.acquisitions=0;self.dispatch_checks=0
    def jni(self,fn,args,read,write):
        if fn==DISPATCH:
            assert args[:3]==(ENV,DISPATCH_CLASS,DISPATCH_METHOD) and len(args)==4
            raw=read(args[3],32);gtop=int.from_bytes(raw[8:16],'little')
            goff=int.from_bytes(raw[24:28],'little',signed=True)
            words=[int.from_bytes(read(gtop+goff+i*8,8),'little') for i in range(5)]
            assert words==[0x01000011,0,0,0,0]
            self.events.append(['dispatch',*words])
            if self.label=='replace_first_environment_after_dispatch':write(SP-0x58,OTHER_ENV.to_bytes(8,'little'))
            return 0 if self.label=='NULL_dispatch_result' else child.OBJECT
        if self.label=='replace_first_environment_after_dispatch':
            assert args[0] in (ENV,OTHER_ENV)
            self.events.append(['environment',args[0]]);args=(ENV,*args[1:])
        if fn in (G+0xF720,G+0xF820) and self.dispatch_checks<2:
            self.dispatch_checks+=1;self.events.append(['JNI',0x720,*args]);return 0
        return super().jni(fn,args,read,write)
    def acquire(self,p,*,entry_stack_address,output_pair_address):
        self.acquisitions+=1
        expected=(SP-0x70,SP-0x58) if self.acquisitions==1 else (SP-0xE0,SP-0xD8)
        assert (entry_stack_address,output_pair_address)==expected and self.acquisitions<=2
        env=0 if self.label=='NULL_environment' or self.label=='second_acquisition_NULL' and self.acquisitions==2 else ENV
        self.events.append(['acquire',entry_stack_address,output_pair_address,env])
        _write_span(p,output_pair_address,env.to_bytes(8,'little')+(G+0x1F00).to_bytes(8,'little'))
    def imports(self,image):
        result=super().imports(image)
        def acquire(cpu):
            self.acquisitions+=1
            stack=cpu.reg_read(arm.UC_ARM64_REG_SP);pair=cpu.reg_read(arm.UC_ARM64_REG_X0)
            expected=(SP-0x70,SP-0x58) if self.acquisitions==1 else (SP-0xE0,SP-0xD8)
            assert (stack,pair)==expected and self.acquisitions<=2
            env=0 if self.label=='NULL_environment' or self.label=='second_acquisition_NULL' and self.acquisitions==2 else ENV
            self.events.append(['acquire',stack,pair,env])
            cpu.mem_write(pair,env.to_bytes(8,'little')+(G+0x1F00).to_bytes(8,'little'));return 0
        def dispatch(cpu):
            args=tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(4))
            return self.jni(DISPATCH,args,lambda a,n:bytes(cpu.mem_read(a,n)),lambda a,b:cpu.mem_write(a,b))
        result.update({0x26EDC4:acquire,DISPATCH-image:dispatch});return result


def original(library,libc,image,label,p):
    expected=Services(image,label);seen=set();steps=[0]
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    scope=SP-0xB0
    watch.update({(SP-0x58,16):None,(SP-0x68,16):None,(scope,12):None,(scope+16,8):None})
    def observe(cpu,address):
        steps[0]+=1;off=address-image
        if off in (0x1CF688,0x26EDC4,0x26E70C,0x26FE2C,0x2481AC,0x15E1A8):seen.add(off)
        if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        elif off==0x348310:expected.diagnostic('gettid',137)
    def malloc(cpu,n):return expected.allocation('malloc',n,lambda a,n:bytes(cpu.mem_read(a,n)),lambda a,b:cpu.mem_write(a,b))
    _,memory,_,_=oracle.native(library,image,0x1CF688,[],p,
        libc=libc,real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        real_jni_acquisition=True,real_jni_dispatch=True,
        extra_registers={arm.UC_ARM64_REG_X8:OUT,arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP},
        thread_id=137,host_imports=expected.imports(image),malloc_handler=malloc,
        instruction_limit=200000,instruction_observer=observe,observed_memory=watch)
    assert {0x1CF688,0x26EDC4,0x26E70C,0x26FE2C,0x15E1A8}.issubset(seen)
    assert expected.acquisitions==2
    return memory,watch,expected,steps[0]


def red(library,libc):
    assert not hasattr(model,'construct_cached_dispatch_byte_reference')
    rows=[]
    for image in BASES:
        p,kw=fixture(library,image,'normal');memory,watch,events,steps=original(library,libc,image,'normal',p)
        string=int.from_bytes(memory[OUT-G:OUT-G+8],'little')
        assert string and memory[string-G+12:string-G+16]==(7).to_bytes(4,'little')
        rows.append(dict(image_base=hex(image),previous_producer_composition_missing=True,
            original_producer_dispatch_and_conversion_returned=True,two_explicit_acquisitions_observed=True,
            exact_dispatch_words_and_binary_output_observed=True,native_instructions=steps,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,kw=fixture(library,image,label);memory,watch,expected,steps=original(library,libc,image,label,p)
    actual=Services(image,label)
    model.construct_cached_dispatch_byte_reference(p,**kw,acquire_environment=actual.acquire,
        invoke_jni=actual.model_jni,allocate=actual.malloc,calloc=actual.calloc,free=actual.free,
        diagnostic_observer=actual.diagnostic)
    assert _read_span(p,G,0xA000)==memory,(label,'guest')
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a),_read_span(p,a,n).hex(),raw.hex())
    assert actual.events==expected.events,(label,'ordered effects',actual.events,expected.events)
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert actual.acquisitions==2
    if label=='replace_first_environment_after_dispatch':
        environments=[e for e in actual.events if e[0]=='environment']
        assert ['environment',OTHER_ENV] in environments and environments[-1]==['environment',ENV]
    print('PASS cached dispatch bytes',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        original_producer_dispatch_and_conversion_returned=True,all_declared_guest_image_and_live_fields_equal=True,
        exact_dispatch_words_and_two_acquisitions_equal=True,ordered_JNI_allocation_free_and_diagnostic_effects_equal=True,
        first_pair_reload_and_retained_cleanup_environment_verified=label=='replace_first_environment_after_dispatch',
        acquisition_and_JNI_services_explicit=True,native_snapshot_input=False,physical_padding_and_register_spills_compared=False)


def guards(library):
    rows=[]
    for label in ('unaligned_stack','unmapped_stack','NULL_output','missing_output','missing_acquisition',
            'missing_JNI','missing_allocator','missing_calloc','missing_free','payload_bound',
            'invalid_bound','diagnostic_guard_wait','provider_failure_after_acquisition'):
        image=BASES[0];p,kw=fixture(library,image,'cold_diagnostics');service=Services(image,'normal')
        kw.update(acquire_environment=service.acquire,invoke_jni=service.model_jni,allocate=service.malloc,
            calloc=service.calloc,free=service.free,diagnostic_observer=service.diagnostic)
        if label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='unmapped_stack':
            kw['entry_stack_address']=0x66001000
            kw['acquire_environment']=lambda p,**options:_write_span(p,options['output_pair_address'],bytes(16))
        elif label=='NULL_output':kw['output_reference_address']=0
        elif label=='missing_output':kw['output_reference_address']=0x66000000
        elif label=='missing_acquisition':kw['acquire_environment']=None
        elif label=='missing_JNI':kw['invoke_jni']=None
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='missing_calloc':kw['calloc']=None
        elif label=='missing_free':kw['free']=None
        elif label=='payload_bound':kw['max_payload_bytes']=6
        elif label=='invalid_bound':kw['max_payload_bytes']=-1
        elif label=='diagnostic_guard_wait':binary.w(p,image+binary.diagnostics.GUARD+1,2,1)
        elif label=='provider_failure_after_acquisition':
            def fail(p,**options):
                service.acquire(p,**options);raise RuntimeError('synthetic acquisition failure')
            kw['acquire_environment']=fail
        before={k:bytes(v) for k,v in p.items()}
        try:model.construct_cached_dispatch_byte_reference(p,**kw)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','producer','guards','all'),default='all')
    parser.add_argument('--case',choices=PROFILES)
    a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==binary.LIBC_SHA256
    e=dict(schema='vm9-cached-dispatch-bytes-fresh-v1',sample_sha256=oracle.LIBRARY_SHA256,
        evidence_date='2026-10-15',cases=[],negative_cases=[],accepted_native_controls_not_repeated=True,
        native_snapshot_input=False,private_names_or_payloads_published=False,
        complete_physical_ABI_verified=False,whole_request_native_differential_verified=False,
        complete_second_vm_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.group=='red':e['red_cases']=red(a.library,a.libc)
    if a.group in ('producer','all'):e['cases']=[compare(a.library,a.libc,b,n) for b in BASES for n in ((a.case,) if a.case else PROFILES)]
    if a.group in ('guards','all'):e['negative_cases']=guards(a.library)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS cached dispatch bytes',a.group,e['native_Python_controls'])
if __name__=='__main__':main()
