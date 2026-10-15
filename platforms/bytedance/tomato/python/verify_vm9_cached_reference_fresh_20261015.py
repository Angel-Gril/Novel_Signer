"""Original +1cf55c inline cache versus Python, with explicit external services."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_cached_dispatch_bytes_fresh_20261015 as producer
import vm9_jni_environment as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span

oracle=producer.oracle;binary=producer.binary
G=producer.G;SP=producer.SP;TP=producer.TP;OUT=producer.OUT;BASES=producer.BASES
producer.SP=SP-0x60
STRING=G+0x3800;COUNT=G+0x3820;PAYLOAD=G+0x3840
PROFILES=('cold','cold_diagnostics','cold_atexit_failure','cold_empty','cold_empty_refresh',
    'warm_nonempty','warm_NULL','warm_zero_length','warm_NULL_data','warm_sentinel',
    'refresh_ninth','skip_tenth','refresh_nineteenth','signed_negative','signed_overflow',
    'unsigned_wrap','guard_nonzero_even','guard_pending_complete','guard_other_flag',
    'output_alias_cache','warm_sentinel_exact','warm_sentinel_nonempty')


def fixture(library,image,label):
    p,kw=producer.fixture(library,image,'cold_diagnostics' if label=='cold_diagnostics' else 'normal')
    kw.update(entry_stack_address=SP)
    binary.w(p,image+0x3D5100,0 if label.startswith('cold') or label=='guard_other_flag' else 0x101)
    binary.w(p,image+0x3D5108,0)
    _write_span(p,image+0x3D5120,bytes(16))
    if label.startswith('warm') or label in ('refresh_ninth','skip_tenth','refresh_nineteenth',
            'signed_negative','signed_overflow','unsigned_wrap','guard_nonzero_even',
            'guard_pending_complete','output_alias_cache'):
        value=b'cache'
        if label=='warm_sentinel_nonempty':_write_span(p,image+0x6FE64,b'fixture-marker\0')
        if label in ('warm_sentinel','warm_sentinel_exact','warm_sentinel_nonempty'):
            value=bytes(model.objects._cstring(p,image+0x6FE64,0x1000))
            if label!='warm_sentinel':value=value[:-1]
        _write_span(p,STRING,(image+0x34F5F8).to_bytes(8,'little')+
            (len(value)+1).to_bytes(4,'little')+len(value).to_bytes(4,'little')+PAYLOAD.to_bytes(8,'little'))
        _write_span(p,PAYLOAD,value+b'\0');binary.w(p,COUNT,1,4)
        binary.w(p,image+0x3D5120,STRING);binary.w(p,image+0x3D5128,COUNT)
        if label in ('warm_NULL','refresh_ninth','skip_tenth','refresh_nineteenth','signed_negative',
                'signed_overflow','unsigned_wrap'):binary.w(p,image+0x3D5120,0)
        if label=='warm_zero_length':binary.w(p,STRING+12,0,4)
        if label=='warm_NULL_data':binary.w(p,STRING+16,0)
    counts={'cold_empty_refresh':8,'refresh_ninth':8,'skip_tenth':9,'refresh_nineteenth':18,
        'signed_negative':(1<<64)-12,'signed_overflow':(1<<63)-1,'unsigned_wrap':(1<<64)-1}
    binary.w(p,image+0x3D5108,counts.get(label,0))
    if label=='guard_nonzero_even':binary.w(p,image+0x3D5100,2,1)
    if label=='guard_pending_complete':binary.w(p,image+0x3D5100,0x100,2)
    if label=='guard_other_flag':binary.w(p,image+0x3D5100,0x400,2)
    if label=='output_alias_cache':kw['output_reference_address']=image+0x3D5120
    return p,kw


class Services(producer.Services):
    def __init__(self,image,label):
        super().__init__(image,'NULL_environment' if label in ('cold_empty','cold_empty_refresh') else 'normal')
        self.profile=label
        self.effects.blocks.update({STRING:24,COUNT:4,PAYLOAD:32})
    def acquired(self,stack,pair,write):
        index=self.acquisitions%2;self.acquisitions+=1
        expected=(SP-0xD0,SP-0xB8) if index==0 else (SP-0x140,SP-0x138)
        assert (stack,pair)==expected
        if index==0:self.dispatch_checks=0;self.checks=0
        env=0 if self.profile in ('cold_empty','cold_empty_refresh') else producer.ENV
        self.events.append(['acquire',stack,pair,env])
        write(pair,env.to_bytes(8,'little')+(G+0x1F00).to_bytes(8,'little'))
    def acquire(self,p,*,entry_stack_address,output_pair_address):
        self.acquired(entry_stack_address,output_pair_address,lambda a,b:_write_span(p,a,b))
    def register(self,p,destructor,obj,dso):
        return self.registered(destructor,obj,dso)
    def registered(self,destructor,obj,dso):
        assert (destructor,obj,dso)==(self.image+0x15E1A8,self.image+0x3D5120,self.image+0x34C700)
        status=-1 if self.profile=='cold_atexit_failure' else 0
        self.events.append(['atexit',destructor,obj,dso,status]);return status
    def imports(self,image):
        result=super().imports(image)
        def acquire(cpu):
            self.acquired(cpu.reg_read(arm.UC_ARM64_REG_SP),cpu.reg_read(arm.UC_ARM64_REG_X0),cpu.mem_write)
            return 0
        def register(cpu):
            return self.registered(*(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)))&0xFFFFFFFF
        result.update({0x26EDC4:acquire,0x347EA0:register});return result


def original(library,libc,image,label,p,kw):
    expected=Services(image,label);seen=set();steps=[0]
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch.update({(SP-0x48,16):None,(SP-0x58,16):None,(SP-0xB0,12):None,(SP-0xA0,8):None})
    def observe(cpu,address):
        steps[0]+=1;off=address-image
        if off in (0x1CF55C,0x1CF688,0x32D3A0,0x32D4F8,0x343D60,0x15F554,0x162620):seen.add(off)
        if off in (0x347F00,0x347F10):
            expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        elif off==0x348310:expected.diagnostic('gettid',137)
    _,memory,_,_=oracle.native(library,image,0x1CF55C,[],p,
        libc=libc,real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        real_jni_acquisition=True,real_jni_dispatch=True,
        extra_registers={arm.UC_ARM64_REG_X8:kw['output_reference_address'],arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP},
        thread_id=137,host_imports=expected.imports(image),
        malloc_handler=lambda c,n:expected.allocation('malloc',n,lambda a,n:bytes(c.mem_read(a,n)),c.mem_write),
        instruction_limit=200000,instruction_observer=observe,observed_memory=watch)
    assert {0x1CF55C,0x15F554}.issubset(seen)
    return memory,watch,expected,steps[0],seen


def red(library,libc):
    assert not hasattr(model,'copy_cached_dispatch_byte_reference')
    rows=[]
    for image in BASES:
        p,kw=fixture(library,image,'cold')
        memory,watch,expected,steps,seen=original(library,libc,image,'cold',p,kw)
        assert {0x1CF688,0x32D3A0,0x32D4F8}.issubset(seen)
        assert int.from_bytes(memory[OUT-G:OUT-G+8],'little')
        rows.append(dict(image_base=hex(image),previous_cache_owner_missing=True,
            original_cache_initialization_and_output_returned=True,native_instructions=steps,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,kw=fixture(library,image,label)
    memory,watch,expected,steps,seen=original(library,libc,image,label,p,kw)
    actual=Services(image,label)
    model.copy_cached_dispatch_byte_reference(p,**kw,acquire_environment=actual.acquire,
        invoke_jni=actual.model_jni,register_exit=actual.register,allocate=actual.malloc,calloc=actual.calloc,
        free=actual.free,diagnostic_observer=actual.diagnostic)
    got=_read_span(p,G,0xA000)
    if got!=memory:
        i=next(i for i,(a,b) in enumerate(zip(got,memory)) if a!=b)
        raise AssertionError((label,'guest',hex(G+i),got[i:i+32].hex(),memory[i:i+32].hex()))
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a),_read_span(p,a,n).hex(),raw.hex())
    assert actual.events==expected.events,(label,'ordered effects',actual.events,expected.events)
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert actual.acquisitions==expected.acquisitions
    print('PASS cached reference',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        original_cache_getter_returned=True,declared_guest_image_temporary_and_diagnostic_fields_equal=True,
        ordered_JNI_acquisition_atexit_allocation_free_lock_effects_equal=True,
        producer_calls=actual.acquisitions//2,atomic_increment_executed=0x343D60 in seen,
        assignment_executed=0x162620 in seen,native_snapshot_input=False,
        physical_padding_and_register_spills_compared=False)


def guards(library):
    rows=[]
    for label in ('unaligned_stack','unmapped_stack','NULL_output','missing_output','guard_wait',
            'missing_thread_id','missing_exit','bad_exit_status','exit_failure_after_effect',
            'missing_acquisition','missing_JNI','missing_allocator','missing_calloc','missing_free',
            'invalid_bound','payload_bound','busy_guard_mutex','guard_broadcast'):
        image=BASES[0];p,kw=fixture(library,image,'cold');service=Services(image,'cold')
        kw.update(acquire_environment=service.acquire,invoke_jni=service.model_jni,register_exit=service.register,
            allocate=service.malloc,calloc=service.calloc,free=service.free,diagnostic_observer=service.diagnostic)
        if label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='unmapped_stack':
            kw['entry_stack_address']=0x66001000
            kw['acquire_environment']=lambda p,**options:_write_span(p,options['output_pair_address'],bytes(16))
        elif label=='NULL_output':kw['output_reference_address']=0
        elif label=='missing_output':kw['output_reference_address']=0x66000000
        elif label=='guard_wait':binary.w(p,image+0x3D5101,2,1)
        elif label=='missing_thread_id':kw['thread_id']=None
        elif label=='missing_exit':kw['register_exit']=None
        elif label=='bad_exit_status':kw['register_exit']=lambda *a:1<<40
        elif label=='exit_failure_after_effect':
            def fail(*a):service.register(*a);raise RuntimeError('synthetic exit failure')
            kw['register_exit']=fail
        elif label=='missing_acquisition':kw['acquire_environment']=None
        elif label=='missing_JNI':kw['invoke_jni']=None
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='missing_calloc':kw['calloc']=None
        elif label=='missing_free':kw['free']=None
        elif label=='invalid_bound':kw['max_payload_bytes']=-1
        elif label=='payload_bound':kw['max_payload_bytes']=6
        elif label=='busy_guard_mutex':binary.w(p,image+0x3E2F40,1,4)
        elif label=='guard_broadcast':
            def mutate(p,*a):binary.w(p,image+0x3D5101,6,1);return 0
            kw['register_exit']=mutate
        before={k:bytes(v) for k,v in p.items()}
        try:model.copy_cached_dispatch_byte_reference(p,**kw)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--mode',choices=('red','native','guards'),default='native')
    parser.add_argument('--case',action='append',choices=PROFILES)
    a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==binary.LIBC_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,complete_physical_ABI_verified=False,allocator_provider_mapping_rollback_verified=False,
        complete_second_vm_verified=False,actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,a.libc)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:e['cases']=[compare(a.library,a.libc,image,label) for image in BASES for label in (a.case or PROFILES)]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
